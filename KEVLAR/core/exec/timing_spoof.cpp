#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include "core/exec/timing_spoof.h"
#include "core/exec/cpu_profile.h"
#include <Logger/Logger.h>
#include "core/memory/unicorn_memory.h"
#include <intrin.h>
#include <cmath>

thread_local uint64_t TlsLastRdtscValue = 0;
thread_local int64_t TlsLastRdtscQpc = 0;
thread_local bool TlsCpuidBetweenRdtsc = false;
thread_local int TlsShortIntervalCount = 0;

uint64_t TimingSeed = 0x4B45464F2021ULL; // "KEFO !"

uint64_t TscFastRand() {
    static thread_local uint64_t State = TimingSeed;
    State ^= State << 13;
    State ^= State >> 7;
    State ^= State << 17;
    return State;
}

int64_t TscGaussianJitter(double Stddev) {
    static thread_local bool HasSpare = false;
    static thread_local double Spare = 0.0;
    if (HasSpare) {
        HasSpare = false;
        return (int64_t)(Spare * Stddev);
    }
    HasSpare = true;
    double U, V, S;
    do {
        U = (double)(TscFastRand() & 0xFFFFFFFF) / 4294967295.0 * 2.0 - 1.0;
        V = (double)(TscFastRand() & 0xFFFFFFFF) / 4294967295.0 * 2.0 - 1.0;
        S = U * U + V * V;
    } while (S >= 1.0 || S == 0.0);
    double Mul = sqrt(-2.0 * log(S) / S);
    Spare = V * Mul;
    return (int64_t)(U * Mul * Stddev);
}

DWORD WINAPI KusdUpdaterThread(LPVOID Param) {
    auto Block = (volatile uint8_t*)Param;
    auto RealKusd = (volatile uint8_t*)0x7FFE0000;
    while (KusdThreadRunning) {
        LARGE_INTEGER CurrentQpc;
        QueryPerformanceCounter(&CurrentQpc);
        int64_t RealElapsed = CurrentQpc.QuadPart - UnicornEmu::EmulationStartQpc;
        int64_t EmulatedElapsed = RealElapsed - UnicornEmu::HookTimeAccumulated;
        if (EmulatedElapsed < 0) EmulatedElapsed = 0;

        int64_t ElapsedIn100Ns = 0;
        if (UnicornEmu::QpcFrequency > 0)
            ElapsedIn100Ns = (EmulatedElapsed * 10000000LL) / UnicornEmu::QpcFrequency;

        int64_t VirtualSystemTime = UnicornEmu::EmulationStartSystemTime + ElapsedIn100Ns;

        int64_t VirtualInterruptTime = ElapsedIn100Ns;

        uint32_t VirtualTickCount = (uint32_t)(ElapsedIn100Ns / 156250);

        auto It = (volatile int64_t*)(Block + 0x08);
        *It = VirtualInterruptTime;
        *(volatile int32_t*)(Block + 0x10) = (int32_t)(VirtualInterruptTime >> 32);

        *(volatile int64_t*)(Block + 0x14) = VirtualSystemTime;
        *(volatile int32_t*)(Block + 0x1C) = (int32_t)(VirtualSystemTime >> 32);

        memcpy((void*)(Block + 0x20), (void*)(RealKusd + 0x20), 8);

        auto Tc = (volatile uint32_t*)(Block + 0x320);
        Tc[0] = VirtualTickCount;
        Tc[1] = 0;
        Tc[2] = VirtualTickCount;

        Sleep(1);
    }
    return 0;
}

void UnicornEmu::InitTimingSpoofing() {
    LARGE_INTEGER Freq, StartQpc;
    QueryPerformanceFrequency(&Freq);
    QueryPerformanceCounter(&StartQpc);

    QpcFrequency = Freq.QuadPart;
    EmulationStartQpc = StartQpc.QuadPart;

    EmulationStartSystemTime = CpuProfile::kEmulatedSystemTimeBase;

    // Aligned with CpuProfile leaf 0x15 (38.4MHz * 168 / 2 = 3.2256 GHz) so a
    // driver that derives frequency from CPUID sees the same rate RDTSC uses.
    TscPerQpcTick = (double)CpuProfile::kProfileTscHz / (double)QpcFrequency;

    HookTimeAccumulated = 0;
    VirtualTsc = CpuProfile::kInitialVirtualTsc;

    Logger::Log("{GRN}Timing spoofing initialized: QpcFreq=%lld TscPerQpc=%.2f{RESET}\n",
        QpcFrequency, TscPerQpcTick);
}

int64_t GetEmulatedQpcElapsed() {
    LARGE_INTEGER CurrentQpc;
    QueryPerformanceCounter(&CurrentQpc);
    int64_t RealElapsed = CurrentQpc.QuadPart - UnicornEmu::EmulationStartQpc;
    int64_t EmulatedElapsed = RealElapsed - UnicornEmu::HookTimeAccumulated;
    if (EmulatedElapsed < 0) EmulatedElapsed = 0;
    return EmulatedElapsed;
}

// The KUSD time fields are KSYSTEM_TIME { LowPart, High1Time, High2Time }, not
// plain 64-bit values. Readers spin on
//     do { High1 = t->High1Time; Low = t->LowPart; High2 = t->High2Time; }
//     while (High1 != High2);
// so a 64-bit store - which writes LowPart and High1Time and leaves High2Time at
// whatever the host snapshot held - hangs every such reader forever. Write the
// three fields the way the kernel does: High2Time, then LowPart, then High1Time.
static void WriteKsystemTime(uint64_t UcAddr, int64_t Value) {
    void* Host = UnicornMem::UcToHost(UcAddr);
    if (!Host)
        return;

    auto Fields = (volatile uint32_t*)Host;
    uint32_t Low = (uint32_t)((uint64_t)Value & 0xFFFFFFFFULL);
    uint32_t High = (uint32_t)((uint64_t)Value >> 32);

    Fields[2] = High;
    Fields[0] = Low;
    Fields[1] = High;
}

void UnicornEmu::UpdateKusdTimeValues() {
    if (QpcFrequency == 0) return;

    int64_t EmulatedElapsed = GetEmulatedQpcElapsed();
    int64_t ElapsedIn100Ns = (EmulatedElapsed * 10000000LL) / QpcFrequency;

    WriteKsystemTime(KUSD_BASE_UC + 0x08, ElapsedIn100Ns);

    int64_t VirtualSystemTime = EmulationStartSystemTime + ElapsedIn100Ns;
    WriteKsystemTime(KUSD_BASE_UC + 0x14, VirtualSystemTime);

    int64_t VirtualTickCount = ElapsedIn100Ns / 156250;
    WriteKsystemTime(KUSD_BASE_UC + 0x320, VirtualTickCount);

    // TickCountLowDeprecated tracks the low half of the same count.
    void* TickLowHost = UnicornMem::UcToHost(KUSD_BASE_UC + 0x00);
    if (TickLowHost)
        *(volatile uint32_t*)TickLowHost = (uint32_t)VirtualTickCount;
}
