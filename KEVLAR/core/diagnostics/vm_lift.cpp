#include "core/diagnostics/vm_lift.h"
#include "core/exec/unicorn_engine.h"
#include "core/memory/unicorn_memory.h"
#include <Logger/Logger.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <algorithm>

namespace VmLift {

bool Enabled = false;
bool TracerEnabled = true;
std::string OutDir;

namespace {

uint64_t gDriverBase = 0;
uint64_t gDriverSize = 0;

// The interpreter context, latched after the same driver-resident RBP has been
// seen often enough that it cannot be a transient frame pointer in native code.
std::atomic<uint64_t> gCtxUc{ 0 };
uint64_t gCtxCandidate = 0;
uint32_t gCtxCandidateHits = 0;
constexpr uint32_t kCtxLatchThreshold = 256;

// One-entry translation cache. RBP is constant for the whole run on the primary
// engine, so this hits essentially always; spawned threads with their own
// context fall back to a map lookup and re-latch the cache.
uint64_t gCachedCtxUc = 0;
void* gCachedCtxHost = nullptr;

// ---------------------------------------------------------------------------
// Insert-only lock-free set, linear probing on 64-bit keys. Sized once and never
// grown: everything stored in one is bounded by the size of the *program* - how
// many distinct virtual instructions and edges exist - not by how long it runs,
// which is the whole point of recording edges instead of dispatches.
// Key 0 marks an empty slot, so keys are stored biased by one.
// ---------------------------------------------------------------------------
class AtomicSet {
public:
    void Init(size_t Slots) {
        mSlots = std::vector<std::atomic<uint64_t>>(Slots);
        mMask = Slots - 1;
        mCount.store(0, std::memory_order_relaxed);
        mFull.store(false, std::memory_order_relaxed);
    }

    bool Empty() const { return mSlots.empty(); }
    size_t Count() const { return mCount.load(std::memory_order_relaxed); }
    bool Overflowed() const { return mFull.load(std::memory_order_relaxed); }

    // True when this call is what inserted the key.
    bool Insert(uint64_t Key) {
        if (mSlots.empty())
            return false;
        uint64_t Stored = Key + 1;
        size_t I = (size_t)((Key * 0x9E3779B97F4A7C15ULL) >> 24) & mMask;
        for (size_t Probe = 0; Probe <= mMask; Probe++) {
            std::atomic<uint64_t>& Slot = mSlots[(I + Probe) & mMask];
            uint64_t Cur = Slot.load(std::memory_order_relaxed);
            if (Cur == Stored)
                return false;
            if (Cur == 0) {
                uint64_t Expect = 0;
                if (Slot.compare_exchange_strong(Expect, Stored, std::memory_order_relaxed)) {
                    mCount.fetch_add(1, std::memory_order_relaxed);
                    return true;
                }
                if (Expect == Stored)
                    return false;
            }
        }
        mFull.store(true, std::memory_order_relaxed);
        return false;
    }

    template <typename Fn>
    void ForEach(Fn F) const {
        for (const auto& Slot : mSlots) {
            uint64_t V = Slot.load(std::memory_order_relaxed);
            if (V)
                F(V - 1);
        }
    }

private:
    std::vector<std::atomic<uint64_t>> mSlots;
    size_t mMask = 0;
    std::atomic<size_t> mCount{ 0 };
    std::atomic<bool> mFull{ false };
};

// Virtual control-flow edges, key = (from VIP << 32) | to VIP. This is the
// complete virtual CFG: VIP only changes at instruction boundaries, so every
// transition observed here is an edge of the bytecode program regardless of
// which native block happened to be executing when it was seen.
AtomicSet gEdges;

// (native block << 32) | VIP. Identifies which handler decodes an instruction:
// the handler that updates VIP is the *previous* one, so its tail blocks pair
// with the new VIP too - the offline side keeps only pairs whose block is a
// known handler entry, which discards those tails.
AtomicSet gPairs;

constexpr size_t kEdgeSlots = 1u << 22;   // 4M slots, 32 MB
constexpr size_t kPairSlots = 1u << 22;

// Per-thread previous VIP. Each spawned guest thread runs its own engine and may
// carry its own interpreter context, so this cannot be global.
thread_local uint64_t tLastVip = 0;

// A short prefix of raw dispatch records, kept only to seed the offline decoder
// with known-good (block, VIP) pairs and to show the entry sequence in order.
// The edge set above is what carries coverage.
struct TraceRec { uint32_t BlockRva; uint32_t VipRva; };
constexpr size_t kTraceCap = 1u << 20;    // 1M records = 8 MB
std::vector<TraceRec> gTrace;
std::atomic<size_t> gTraceIdx{ 0 };

struct BlockStat { uint64_t Count; uint32_t FirstVipRva; };
std::unordered_map<uint32_t, BlockStat> gBlocks;
std::mutex gBlocksLock;

std::atomic<uint64_t> gBlockTotal{ 0 };
std::atomic<uint64_t> gDispatchTotal{ 0 };

// Block-start coverage over the whole image, independent of whether the
// interpreter context was live. One relaxed store per block, no read-modify-
// write: the question it answers is only "did a block ever start here", which
// is what separates code that runs from the ~90% of this image that never does.
std::vector<std::atomic<uint8_t>> gCov;

void* CtxHost(uint64_t CtxUc) {
    if (CtxUc == gCachedCtxUc && gCachedCtxHost)
        return gCachedCtxHost;
    void* Host = UnicornMem::UcToHost(CtxUc);
    if (Host) {
        gCachedCtxUc = CtxUc;
        gCachedCtxHost = Host;
    }
    return Host;
}

void OnBlock(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData) {
    (void)Size; (void)UserData;

    if (Addr - gDriverBase >= gDriverSize)
        return;

    gBlockTotal.fetch_add(1, std::memory_order_relaxed);

    if (!gCov.empty())
        gCov[(size_t)(Addr - gDriverBase)].store(1, std::memory_order_relaxed);

    uint64_t Rbp = 0;
    uc_reg_read(Uc, UC_X86_REG_RBP, &Rbp);

    uint64_t Ctx = gCtxUc.load(std::memory_order_relaxed);
    if (!Ctx) {
        // Latch phase: the context lives inside the driver image and never
        // moves, so the first RBP to survive kCtxLatchThreshold consecutive
        // blocks is it.
        if (Rbp - gDriverBase < gDriverSize) {
            if (Rbp == gCtxCandidate) {
                if (++gCtxCandidateHits >= kCtxLatchThreshold) {
                    gCtxUc.store(Rbp, std::memory_order_relaxed);
                    Logger::Log("{CYN}[DEVIRT] VM context latched at drv+0x%llx{RESET}\n",
                        Rbp - gDriverBase);
                    void* H = CtxHost(Rbp);
                    if (H) {
                        uint64_t Table = 0;
                        memcpy(&Table, (uint8_t*)H + kCtxHandlerTableOffset, 8);
                        Logger::Log("{CYN}[DEVIRT] handler table = 0x%llx (drv+0x%llx){RESET}\n",
                            Table, Table - gDriverBase);
                    }
                }
            } else {
                gCtxCandidate = Rbp;
                gCtxCandidateHits = 1;
            }
        }
        return;
    }

    // Only blocks reached with the interpreter context live are virtual
    // instruction handlers; native prologue code runs with an unrelated RBP.
    if (Rbp != Ctx)
        return;

    void* Host = CtxHost(Ctx);
    if (!Host)
        return;

    uint64_t Vip = 0;
    memcpy(&Vip, (uint8_t*)Host + kCtxVipOffset, 8);
    if (Vip - gDriverBase >= gDriverSize)
        return;

    uint32_t BlockRva = (uint32_t)(Addr - gDriverBase);
    uint32_t VipRva = (uint32_t)(Vip - gDriverBase);

    gDispatchTotal.fetch_add(1, std::memory_order_relaxed);

    gPairs.Insert(((uint64_t)BlockRva << 32) | VipRva);

    if (Vip != tLastVip) {
        if (tLastVip && tLastVip - gDriverBase < gDriverSize)
            gEdges.Insert(((uint64_t)(uint32_t)(tLastVip - gDriverBase) << 32) | VipRva);
        tLastVip = Vip;
    }

    size_t Idx = gTraceIdx.fetch_add(1, std::memory_order_relaxed);
    if (Idx < kTraceCap)
        gTrace[Idx] = { BlockRva, VipRva };

    {
        std::lock_guard<std::mutex> Lock(gBlocksLock);
        auto It = gBlocks.find(BlockRva);
        if (It == gBlocks.end())
            gBlocks.emplace(BlockRva, BlockStat{ 1, VipRva });
        else
            It->second.Count++;
    }
}

void (*const kOnBlock)(uc_engine*, uint64_t, uint32_t, void*) = OnBlock;

} // namespace

uint64_t GetContextUc() { return gCtxUc.load(std::memory_order_relaxed); }

void InstallTracer(uc_engine* Uc, uint64_t DriverBase, uint64_t DriverSize) {
    if (!Enabled)
        return;

    gDriverBase = DriverBase;
    gDriverSize = DriverSize;

    if (gTrace.empty())
        gTrace.resize(kTraceCap);

    if (gCov.empty())
        gCov = std::vector<std::atomic<uint8_t>>((size_t)DriverSize);

    if (gEdges.Empty())
        gEdges.Init(kEdgeSlots);
    if (gPairs.Empty())
        gPairs.Init(kPairSlots);

    if (OutDir.empty())
        OutDir = "devirt";
    std::error_code Ec;
    std::filesystem::create_directories(OutDir, Ec);

    uc_hook Hh;
    uc_err Err = uc_hook_add(Uc, &Hh, UC_HOOK_BLOCK, (void*)OnBlock, nullptr,
        DriverBase, DriverBase + DriverSize);
    if (Err != UC_ERR_OK)
        Logger::Log("{RED}[DEVIRT] block hook failed: %s{RESET}\n", uc_strerror(Err));
    else
        Logger::Log("{CYN}[DEVIRT] VM tracer installed over drv+0..0x%llx -> %s{RESET}\n",
            DriverSize, OutDir.c_str());
}

void InstallTracerOnEngine(uc_engine* Uc) {
    if (!Enabled || !TracerEnabled || !gDriverBase || !gDriverSize || !Uc)
        return;

    uc_hook Hh;
    uc_err Err = uc_hook_add(Uc, &Hh, UC_HOOK_BLOCK, (void*)kOnBlock, nullptr,
        gDriverBase, gDriverBase + gDriverSize);
    if (Err != UC_ERR_OK)
        Logger::Log("{RED}[DEVIRT] per-thread block hook failed: %s{RESET}\n", uc_strerror(Err));
}

void DumpImage(const char* Reason, uint64_t DriverBase, uint64_t DriverSize) {
    if (!Enabled)
        return;

    std::string Path = OutDir + "/image.bin";
    FILE* F = nullptr;
    if (fopen_s(&F, Path.c_str(), "wb") != 0 || !F) {
        Logger::Log("{RED}[DEVIRT] cannot open %s{RESET}\n", Path.c_str());
        return;
    }

    std::vector<uint8_t> Page(0x1000);
    uint64_t Missing = 0;
    for (uint64_t Off = 0; Off < DriverSize; Off += 0x1000) {
        uint64_t Chunk = (DriverSize - Off < 0x1000) ? (DriverSize - Off) : 0x1000;
        if (uc_mem_read(UnicornEmu::PrimaryEngine, DriverBase + Off, Page.data(), (size_t)Chunk) != UC_ERR_OK) {
            memset(Page.data(), 0, (size_t)Chunk);
            Missing++;
        }
        fwrite(Page.data(), 1, (size_t)Chunk, F);
    }
    fclose(F);

    uint64_t Ctx = gCtxUc.load(std::memory_order_relaxed);
    uint64_t Table = 0;
    if (Ctx) {
        void* H = UnicornMem::UcToHost(Ctx);
        if (H)
            memcpy(&Table, (uint8_t*)H + kCtxHandlerTableOffset, 8);
    }

    std::string MetaPath = OutDir + "/meta.txt";
    FILE* M = nullptr;
    if (fopen_s(&M, MetaPath.c_str(), "w") == 0 && M) {
        fprintf(M, "reason=%s\n", Reason);
        fprintf(M, "driver_base=0x%llx\n", (unsigned long long)DriverBase);
        fprintf(M, "driver_size=0x%llx\n", (unsigned long long)DriverSize);
        fprintf(M, "unmapped_pages=%llu\n", (unsigned long long)Missing);
        fprintf(M, "vm_ctx_rva=0x%llx\n", (unsigned long long)(Ctx ? Ctx - DriverBase : 0));
        fprintf(M, "handler_table_va=0x%llx\n", (unsigned long long)Table);
        fprintf(M, "handler_table_rva=0x%llx\n",
            (unsigned long long)((Table && Table - DriverBase < DriverSize) ? Table - DriverBase : 0));
        fprintf(M, "ctx_vip_offset=0x%llx\n", (unsigned long long)kCtxVipOffset);
        fprintf(M, "ctx_handler_table_offset=0x%llx\n", (unsigned long long)kCtxHandlerTableOffset);
        fclose(M);
    }

    Logger::Log("{GRN}[DEVIRT] image dumped (%s): 0x%llx bytes, %llu unmapped page(s) -> %s{RESET}\n",
        Reason, DriverSize, Missing, Path.c_str());
}

void DumpTrace(const char* Reason) {
    if (!Enabled)
        return;

    size_t Count = gTraceIdx.load(std::memory_order_relaxed);
    size_t Written = (Count < kTraceCap) ? Count : kTraceCap;

    std::string Path = OutDir + "/trace.bin";
    FILE* F = nullptr;
    if (fopen_s(&F, Path.c_str(), "wb") == 0 && F) {
        fwrite(gTrace.data(), sizeof(TraceRec), Written, F);
        fclose(F);
    }

    // The virtual CFG. One line per edge, both ends bytecode RVAs.
    std::string EPath = OutDir + "/edges.txt";
    if (fopen_s(&F, EPath.c_str(), "w") == 0 && F) {
        std::vector<uint64_t> E;
        E.reserve(gEdges.Count());
        gEdges.ForEach([&](uint64_t K) { E.push_back(K); });
        std::sort(E.begin(), E.end());
        fprintf(F, "# from_vip_rva to_vip_rva\n");
        for (uint64_t K : E)
            fprintf(F, "%08x %08x\n", (uint32_t)(K >> 32), (uint32_t)K);
        fclose(F);
    }

    // (native block, VIP) pairs - the seeds the offline decoder needs to know
    // which handler decodes which instruction.
    std::string PPath = OutDir + "/pairs.txt";
    if (fopen_s(&F, PPath.c_str(), "w") == 0 && F) {
        std::vector<uint64_t> P;
        P.reserve(gPairs.Count());
        gPairs.ForEach([&](uint64_t K) { P.push_back(K); });
        std::sort(P.begin(), P.end());
        fprintf(F, "# block_rva vip_rva\n");
        for (uint64_t K : P)
            fprintf(F, "%08x %08x\n", (uint32_t)(K >> 32), (uint32_t)K);
        fclose(F);
    }

    std::vector<std::pair<uint32_t, BlockStat>> Sorted;
    {
        std::lock_guard<std::mutex> Lock(gBlocksLock);
        Sorted.assign(gBlocks.begin(), gBlocks.end());
    }
    std::sort(Sorted.begin(), Sorted.end(),
        [](const auto& A, const auto& B) { return A.second.Count > B.second.Count; });

    std::string BPath = OutDir + "/blocks.txt";
    if (fopen_s(&F, BPath.c_str(), "w") == 0 && F) {
        fprintf(F, "# block_rva count first_vip_rva\n");
        for (auto& Entry : Sorted)
            fprintf(F, "%08x %llu %08x\n", Entry.first,
                (unsigned long long)Entry.second.Count, Entry.second.FirstVipRva);
        fclose(F);
    }

    size_t CovCount = 0;
    std::string CovPath = OutDir + "/coverage.txt";
    if (fopen_s(&F, CovPath.c_str(), "w") == 0 && F) {
        fprintf(F, "# rva of every basic block that executed\n");
        for (size_t I = 0; I < gCov.size(); I++) {
            if (gCov[I].load(std::memory_order_relaxed)) {
                fprintf(F, "%08zx\n", I);
                CovCount++;
            }
        }
        fclose(F);
    }

    Logger::Log("{GRN}[DEVIRT] trace dumped (%s): %llu blocks, %llu dispatches, "
        "%zu edges, %zu pairs, %zu covered blocks%s{RESET}\n",
        Reason, (unsigned long long)gBlockTotal.load(std::memory_order_relaxed),
        (unsigned long long)gDispatchTotal.load(std::memory_order_relaxed),
        gEdges.Count(), gPairs.Count(), CovCount,
        (gEdges.Overflowed() || gPairs.Overflowed()) ? " {RED}(TABLE FULL - counts truncated)" : "");
    (void)Written; (void)Count;
}

} // namespace VmLift
