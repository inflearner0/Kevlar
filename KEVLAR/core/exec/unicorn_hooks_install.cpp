#include "core/exec/unicorn_engine.h"
#include "core/exec/unicorn_engine_internal.h"
#include "core/exec/timing_spoof.h"
#include <Logger/Logger.h>
#include "core/memory/unicorn_memory.h"
#include "core/diagnostics/diag_center.h"
#include "host/providers/provider.h"
#include <PEMapper/pefile.h>
#include <cstdlib>
#include <atomic>
#include <algorithm>
#include <vector>
#include <unordered_map>

extern void OnRipRingTrace(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData);

void UnicornEmu::Hooks::OnNtoskrnlRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    NtoskrnlReadCount++;

    bool FoundMod = false;
    for (auto& Mod : UnicornEmu::MappedSysMods) {
        std::string NameLower = Mod.Name;
        for (auto& C : NameLower) C = tolower(C);
        if (NameLower.find("ntoskrnl") == std::string::npos)
            continue;

        FoundMod = true;
        uint64_t Rva = Addr - Mod.UcBase;

        if (Rva < 0x200000) {
            if (Rva < 0x1000) {
                NtoskrnlHdrReadCount++;
                uint64_t Rip = 0;
                uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
                uint64_t ReadVal = 0;
                if (Size <= 8) {
                    void* HostPtr = UnicornMem::UcToHost(Addr);
                    if (HostPtr)
                        memcpy(&ReadVal, HostPtr, Size);
                }
                if (HdrFirstLogged < 50) {
                    HdrFirstLogged++;
                    Logger::Log("{GRY}[HDR #%d] RVA=0x%llx size=%d val=0x%llx RIP=0x%llx{RESET}\n",
                        NtoskrnlHdrReadCount, Rva, Size, ReadVal, Rip);
                }
                HdrRingBuf[HdrRingIdx % 64] = { Rva, Size, ReadVal, Rip };
                HdrRingIdx++;
            }
            else if (Rva < 0xC9000) NtoskrnlRdataReadCount++;
            else if (Rva < 0x131000) NtoskrnlPdataReadCount++;
            else if (Rva < 0x134000) NtoskrnlIdataReadCount++;
            else if (Rva < 0x14D000) {
                NtoskrnlEdataReadCount++;
                uint64_t Rip = 0;
                uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
                uint64_t ReadVal = 0;
                if (Size <= 8) {
                    void* HostPtr = UnicornMem::UcToHost(Addr);
                    if (HostPtr)
                        memcpy(&ReadVal, HostPtr, Size);
                }
                if (EdataFirstLogged < 30) {
                    EdataFirstLogged++;
                    Logger::Log("{GRY}[EDATA #%d] RVA=0x%llx size=%d val=0x%llx RIP=0x%llx{RESET}\n",
                        NtoskrnlEdataReadCount, Rva, Size, ReadVal, Rip);
                }
                EdataRingBuf[EdataRingIdx % 32] = { Rva, Size, ReadVal, Rip };
                EdataRingIdx++;

                if (Size == 2 && Rva >= 0x13A074 && Rva < 0x13A074 + 3070*2) {
                    OrdinalReadCount++;
                    uint16_t Ord = (uint16_t)(ReadVal & 0xFFFF);
                    auto& Rec = OrdRingBuf[OrdRingIdx % 64];
                    Rec.NameRva = 0;
                    Rec.Ordinal = Ord;
                    Rec.FuncRva = 0;
                    Rec.Rip = Rip;
                    OrdRingIdx++;
                }
                if (Size == 4 && Rva >= 0x134028 && Rva < 0x134028 + 3093*4) {
                    FuncAddrReadCount++;
                    uint32_t FuncRva = (uint32_t)(ReadVal & 0xFFFFFFFF);
                    uint16_t LastOrdinal = 0;
                    bool HaveLastOrdinal = false;
                    if (OrdRingIdx > 0) {
                        auto& Prev = OrdRingBuf[(OrdRingIdx - 1) % 64];
                        LastOrdinal = Prev.Ordinal;
                        HaveLastOrdinal = true;
                        if (Prev.FuncRva == 0) {
                            Prev.FuncRva = FuncRva;
                        }
                    }

                    const char* ExportName = nullptr;
                    if (Mod.Pe) {
                        ExportName = Mod.Pe->GetExport(FuncRva);
                    }
                    static std::unordered_map<uint32_t, uint32_t> ExportResolveHits;
                    uint32_t& HitCount = ExportResolveHits[FuncRva];
                    HitCount++;
                    if (ExportName && (HitCount == 1 || (HitCount % 50000 == 0))) {
                        if (HaveLastOrdinal) {
                            Logger::Log("{CYN}[EXPORT RESOLVE] ordinal=%u funcRVA=0x%x name=%s RIP=0x%llx{RESET}\n",
                                (uint32_t)LastOrdinal, FuncRva, ExportName, Rip);
                        } else {
                            Logger::Log("{CYN}[EXPORT RESOLVE] funcRVA=0x%x name=%s RIP=0x%llx{RESET}\n",
                                FuncRva, ExportName, Rip);
                        }
                    }
                }
            } else NtoskrnlGfidsReadCount++;
        } else if (Rva < 0xc00000) {
            NtoskrnlCodeReadCount++;
            if (NtoskrnlCodeReadCount <= 20) {
                uint64_t Rip = 0;
                uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
                uint64_t ReadVal = 0;
                if (Size <= 8) {
                    void* HostPtr = UnicornMem::UcToHost(Addr);
                    if (HostPtr)
                        memcpy(&ReadVal, HostPtr, Size);
                }
                Logger::Log("{YEL}[NTOS CODE READ] RVA=0x%llx (size=%d, val=0x%llx) at RIP=0x%llx{RESET}\n",
                    Rva, Size, ReadVal, Rip);
            }
        } else {
            NtoskrnlDataReadCount++;
            uint64_t Rip = 0;
            uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
            uint64_t ReadVal = 0;
            if (Size <= 8) {
                void* HostPtr = UnicornMem::UcToHost(Addr);
                if (HostPtr)
                    memcpy(&ReadVal, HostPtr, Size);
            }

            bool IsPatchedExport = false;
            for (auto& [Name, Ptr] : Provider::data_providers) {
                uint64_t ExportUcAddr = (uint64_t)Ptr;
                if (Addr >= ExportUcAddr && Addr < ExportUcAddr + 16) {
                    size_t ExpSize = 8;
                    if (Provider::data_export_sizes.contains(Name))
                        ExpSize = Provider::data_export_sizes[Name];
                    Logger::Log("{YEL}[PATCHED EXPORT READ] %s RVA=0x%llx size=%d val=0x%llx (exportSize=%zu) at RIP=0x%llx{RESET}\n",
                        Name.c_str(), Rva, Size, ReadVal, ExpSize, Rip);
                    IsPatchedExport = true;
                    break;
                }
            }

            if (!IsPatchedExport && NtoskrnlDataReadCount <= 20) {
                Logger::Log("{GRY}[NTOS DATA READ] RVA=0x%llx (size=%d, val=0x%llx) at RIP=0x%llx{RESET}\n",
                    Rva, Size, ReadVal, Rip);
            }
        }

        if (NtoskrnlReadCount % 100000 == 0) {
            Logger::Log("{CYN}[NTOS READS] total=%d hdr=%d rdata=%d pdata=%d idata=%d edata=%d gfids=%d code=%d data=%d{RESET}\n",
                NtoskrnlReadCount, NtoskrnlHdrReadCount, NtoskrnlRdataReadCount, NtoskrnlPdataReadCount,
                NtoskrnlIdataReadCount, NtoskrnlEdataReadCount, NtoskrnlGfidsReadCount,
                NtoskrnlCodeReadCount, NtoskrnlDataReadCount);
        }

        if (DIAG_IS_ENABLED() && NtoskrnlReadCount <= 512) {
            uint64_t Rip = 0;
            uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
            uint64_t ReadVal = 0;
            if (Size <= 8) {
                void* HostPtr = UnicornMem::UcToHost(Addr);
                if (HostPtr) memcpy(&ReadVal, HostPtr, Size);
            }
            NtosReadEvent Ev = {};
            Ev.Base.Sequence = DIAG_SEQ;
            Ev.Base.Rip = Rip;
            Ev.Base.AccessType = ACCESS_READ;
            {
                uint64_t TmpBase = 0;
                uint32_t TmpRva = 0;
                DiagCenter::Instance().ResolveVaToModule(Rip, TmpBase, TmpRva, Ev.Section, sizeof(Ev.Section));
                Ev.Base.ModuleBase = TmpBase;
                Ev.Base.ModuleRva = TmpRva;
            }
            Ev.TargetVa = Addr;
            Ev.TargetRva = (uint32_t)Rva;
            Ev.Size = (uint32_t)Size;
            Ev.Value = ReadVal;
            DiagCenter::Instance().ResolveVaToPeSection(Addr, Ev.Section, sizeof(Ev.Section));
            DiagCenter::Instance().ResolveVaToSymbol(Addr, Ev.Symbol, sizeof(Ev.Symbol));
            DIAG_NTOS_READ(Ev);
        }
        return;
    }
    if (!FoundMod) {
        NtoskrnlNoModCount++;
        if (NtoskrnlNoModCount <= 5)
            Logger::Log("{RED}[NTOS READ] no module found for addr 0x%llx{RESET}\n", Addr);
    }
}

void UnicornEmu::Hooks::OnKusdRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    KusdReadCount++;
    uint64_t Offset = Addr - KUSD_BASE_UC;

    if (DIAG_IS_ENABLED() && KusdReadCount <= 256) {
        KusdReadEvent Ev = {};
        Ev.Base.Sequence = DIAG_SEQ;
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        Ev.Base.Rip = Rip;
        Ev.Base.AccessType = ACCESS_READ;
        {
            uint64_t TmpBase = 0;
            uint32_t TmpRva = 0;
            DiagCenter::Instance().ResolveVaToModule(Rip, TmpBase, TmpRva, Ev.FieldName, sizeof(Ev.FieldName));
            Ev.Base.ModuleBase = TmpBase;
            Ev.Base.ModuleRva = TmpRva;
        }
        Ev.Address = Addr;
        Ev.Offset = (uint32_t)Offset;
        Ev.Size = (uint32_t)Size;
        if (Size <= 8) {
            void* HostPtr = UnicornMem::UcToHost(Addr);
            if (HostPtr) memcpy(&Ev.Value, HostPtr, Size);
        }
        const char* FieldName = "???";
        if (Offset == 0x00) FieldName = "TickCount";
        else if (Offset == 0x14) FieldName = "SystemTime";
        else if (Offset == 0x320) FieldName = "TickCountQuad";
        strncpy(Ev.FieldName, FieldName, sizeof(Ev.FieldName) - 1);
        DIAG_KUSD_READ(Ev);
    }

    if (DiagnosticHooksEnabled) {
        uint64_t Rip = 0;
        uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
        if (Rip >= DRIVER_BASE_UC && Rip < DRIVER_BASE_UC + 0x10000000) {
            Logger::Log("  {GRY}KUSD read offset={WHT}0x%03llx {GRY}size=%d RIP=drv+0x%llx{RESET}\n", Offset, Size, Rip - DRIVER_BASE_UC);
        }
    }

    if (Offset >= 0x08 && Offset < 0x20) {
        int64_t EmulatedElapsed = GetEmulatedQpcElapsed();
        int64_t ElapsedIn100Ns = (EmulatedElapsed * 10000000LL) / UnicornEmu::QpcFrequency;

        if (Offset >= 0x14 && Offset < 0x1C) {
            int64_t VirtualSystemTime = UnicornEmu::EmulationStartSystemTime + ElapsedIn100Ns;
            void* SystemTimeHost = UnicornMem::UcToHost(KUSD_BASE_UC + 0x14);
            if (SystemTimeHost) {
                *(volatile int64_t*)SystemTimeHost = VirtualSystemTime;
            }
        } else {
            int64_t VirtualInterruptTime = ElapsedIn100Ns;
            void* InterruptTimeHost = UnicornMem::UcToHost(KUSD_BASE_UC + 0x08);
            if (InterruptTimeHost) {
                *(volatile int64_t*)InterruptTimeHost = VirtualInterruptTime;
            }
        }
        return;
    }

    if (Offset >= 0x320 && Offset < 0x32C) {
        int64_t EmulatedElapsed = GetEmulatedQpcElapsed();
        int64_t ElapsedIn100Ns = (EmulatedElapsed * 10000000LL) / UnicornEmu::QpcFrequency;
        uint32_t VirtualTickCount = (uint32_t)(ElapsedIn100Ns / 156250);

        void* TickHost = UnicornMem::UcToHost(KUSD_BASE_UC + 0x320);
        if (TickHost) {
            auto Tc = (volatile uint32_t*)TickHost;
            Tc[0] = VirtualTickCount;
            Tc[1] = 0;
            Tc[2] = VirtualTickCount;
        }
        return;
    }
}

void UnicornEmu::Hooks::OnSysModRead(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
    SysModReadCount++;

    uint64_t Rip = 0;
    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);

    bool IsDriverCaller = (Rip >= DRIVER_BASE_UC && Rip < DRIVER_BASE_UC + 0x10000000ULL);

    for (auto& Mod : UnicornEmu::MappedSysMods) {
        std::string NameLower = Mod.Name;
        for (auto& C : NameLower) C = tolower(C);
        if (NameLower.find("ntoskrnl") != std::string::npos)
            continue;

        if (Addr >= Mod.UcBase && Addr < Mod.UcBase + Mod.Size) {
            uint64_t Rva = Addr - Mod.UcBase;

            if (ModuleReadLoggingEnabled && IsDriverCaller) {
                static FILE* ModReadFile = nullptr;
                static std::mutex ModReadFileLock;
                static std::unordered_map<std::string, uint64_t> ModReadCounts;

                std::lock_guard<std::mutex> Guard(ModReadFileLock);
                if (!ModReadFile) {
                    ModReadFile = fopen("modreads.tsv", "w");
                    if (ModReadFile)
                        fprintf(ModReadFile, "module\trva\tsize\tcaller_rva\n");
                }

                ModReadCounts[Mod.Name]++;

                if (ModReadFile && ModReadCounts[Mod.Name] <= 10000) {
                    fprintf(ModReadFile, "%s\t0x%llx\t%d\t0x%llx\n",
                        Mod.Name.c_str(), Rva, Size, Rip - DRIVER_BASE_UC);
                    if (SysModReadCount % 1000 == 0)
                        fflush(ModReadFile);
                }
            }

            if (DiagnosticHooksEnabled && SysModReadCount <= 500) {
                Logger::Log("{MAG}[SYSMOD READ] %s RVA=0x%llx size=%d at RIP=0x%llx{RESET}\n",
                    Mod.Name.c_str(), Rva, Size, Rip);
            }
            return;
        }
    }
}

void UnicornEmu::InstallWatchpoints(uc_engine* Uc) {
    uc_hook Hh;

    if (DiagnosticHooksEnabled) {
        uc_err Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_READ, (void*)Hooks::OnDrvObjRead, nullptr,
            DRIVER_OBJ_BASE_UC, DRIVER_OBJ_BASE_UC + 0x10000 - 1);
        if (Err == UC_ERR_OK) {
            Logger::Log("{CYN}Watchpoint: DRIVER_OBJECT reads (0x%llx - 0x%llx){RESET}\n",
                DRIVER_OBJ_BASE_UC, DRIVER_OBJ_BASE_UC + 0x10000 - 1);
        }

        uint64_t PoolStart = POOL_BASE_UC;
        uint64_t PoolEnd = UnicornMem::NextPoolAddr;
        if (PoolEnd > PoolStart) {
            Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_READ, (void*)Hooks::OnModuleListRead, nullptr,
                PoolStart, PoolEnd - 1);
            if (Err == UC_ERR_OK) {
                Logger::Log("{CYN}Watchpoint: Pool/LDR reads (0x%llx - 0x%llx){RESET}\n", PoolStart, PoolEnd - 1);
            }
        }
    } else {
        Logger::Log("{YEL}FAST MODE: Skipping DRIVER_OBJECT and Pool/LDR read hooks{RESET}\n");
    }

    uc_err Err = uc_hook_add(Uc, &Hh, UC_HOOK_INSN, (void*)Hooks::OnRdtsc, nullptr, 1, 0, UC_X86_INS_RDTSC);
    if (Err == UC_ERR_OK) {
        Logger::Log("{GRN}RDTSC hook installed{RESET}\n");
    }

    uc_hook RdtscpHook;
    Err = uc_hook_add(Uc, &RdtscpHook, UC_HOOK_INSN, (void*)Hooks::OnRdtsc, nullptr, 1, 0, UC_X86_INS_RDTSCP);
    if (Err == UC_ERR_OK) {
        Logger::Log("{GRN}RDTSCP hook installed{RESET}\n");
    }

    uc_hook RdmsrHook;
    UnicornEmu::RdmsrInsnHookSupported = false;
    UnicornEmu::WrmsrInsnHookSupported = false;
    UnicornEmu::MsrCodeInterceptEnabled = false;
    Err = uc_hook_add(Uc, &RdmsrHook, UC_HOOK_INSN, (void*)Hooks::OnRdmsr, nullptr, 1, 0, UC_X86_INS_RDMSR);
    if (Err == UC_ERR_OK) {
        UnicornEmu::RdmsrInsnHookSupported = true;
        Logger::Log("{GRN}RDMSR hook installed{RESET}\n");
    } else {
        Logger::Log("{YEL}RDMSR insn hook not supported (err=%s){RESET}\n", uc_strerror(Err));
    }

    uc_hook WrmsrHook;
    Err = uc_hook_add(Uc, &WrmsrHook, UC_HOOK_INSN, (void*)Hooks::OnWrmsr, nullptr, 1, 0, UC_X86_INS_WRMSR);
    if (Err == UC_ERR_OK) {
        UnicornEmu::WrmsrInsnHookSupported = true;
        Logger::Log("{GRN}WRMSR hook installed{RESET}\n");
    } else {
        Logger::Log("{YEL}WRMSR insn hook not supported (err=%s){RESET}\n", uc_strerror(Err));
    }

    if (!UnicornEmu::RdmsrInsnHookSupported || !UnicornEmu::WrmsrInsnHookSupported) {
        UnicornEmu::MsrCodeInterceptEnabled = true;
        UnicornEmu::InstallMsrIntercept(Uc);
    }

    if (DiagnosticHooksEnabled) {
        InstallSseAlignCheck(Uc, DRIVER_BASE_UC, 0x10000000ULL);
    } else {
        Logger::Log("{YEL}FAST MODE: Skipping SSE alignment check hook{RESET}\n");
    }

    DrvObjReadCount = 0;
    ModListReadCount = 0;
    NtoskrnlReadCount = 0;
    KusdReadCount = 0;
    SysModReadCount = 0;

    for (auto& Mod : MappedSysMods) {
        std::string NameLower = Mod.Name;
        for (auto& C : NameLower) C = tolower(C);
        if (NameLower.find("ntoskrnl") != std::string::npos) {
            if (DiagnosticHooksEnabled || ModuleReadLoggingEnabled) {
                Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_READ, (void*)Hooks::OnNtoskrnlRead, nullptr,
                    Mod.UcBase, Mod.UcBase + Mod.Size - 1);
                if (Err == UC_ERR_OK) {
                    Logger::Log("{CYN}Watchpoint: ntoskrnl reads (0x%llx - 0x%llx){RESET}\n",
                        Mod.UcBase, Mod.UcBase + Mod.Size - 1);
                }
            } else {
                Logger::Log("{YEL}FAST MODE: Skipping ntoskrnl read hook (0x%llx - 0x%llx){RESET}\n",
                    Mod.UcBase, Mod.UcBase + Mod.Size - 1);
            }
        } else {
            if (DiagnosticHooksEnabled || ModuleReadLoggingEnabled) {
                Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_READ, (void*)Hooks::OnSysModRead, nullptr,
                    Mod.UcBase, Mod.UcBase + Mod.Size - 1);
                if (Err == UC_ERR_OK) {
                    Logger::Log("{CYN}Watchpoint: %s reads (0x%llx - 0x%llx){RESET}\n",
                        Mod.Name.c_str(), Mod.UcBase, Mod.UcBase + Mod.Size - 1);
                }
            }
        }
    }

    UpdateKusdTimeValues();
    bool KusdReadHookInstalled = false;
    if (DiagnosticHooksEnabled || ModuleReadLoggingEnabled) {
        uc_hook HhKusd;
        uc_err KusdHookErr = uc_hook_add(Uc, &HhKusd, UC_HOOK_MEM_READ, (void*)Hooks::OnKusdRead, nullptr,
            KUSD_BASE_UC, KUSD_BASE_UC + 0x1000 - 1);
        if (KusdHookErr == UC_ERR_OK) {
            KusdReadHookInstalled = true;
            Logger::Log("{CYN}Watchpoint: KUSER_SHARED_DATA reads (0x%llx - 0x%llx){RESET}\n",
                KUSD_BASE_UC, KUSD_BASE_UC + 0x1000 - 1);
        } else {
            Logger::Log("{YEL}KUSER_SHARED_DATA hook failed: %s{RESET}\n", uc_strerror(KusdHookErr));
        }
    }
    Logger::Log("{GRN}KUSD time values: periodic heartbeat updates%s{RESET}\n",
        KusdReadHookInstalled ? " + read hook" : " (no read hook)");

    // This watchpoint only records what the guest read; it never feeds the guest a
    // value. Keeping it always-on costs the whole run, because a single
    // UC_HOOK_MEM_READ makes Unicorn route every guest load through a helper, so
    // it belongs with the rest of the diagnostics.
    uc_hook HhHvPage;
    Err = (DiagnosticHooksEnabled || ModuleReadLoggingEnabled)
        ? uc_hook_add(Uc, &HhHvPage, UC_HOOK_MEM_READ, (void*)Hooks::OnHypervisorSharedPageRead, nullptr,
            HYPERVISOR_SHARED_PAGE_BASE_UC, HYPERVISOR_SHARED_PAGE_BASE_UC + 0x1000 - 1)
        : UC_ERR_OK;
    if (Err == UC_ERR_OK && (DiagnosticHooksEnabled || ModuleReadLoggingEnabled)) {
        Logger::Log("{CYN}Watchpoint: HypervisorSharedPage reads (0x%llx - 0x%llx){RESET}\n",
            HYPERVISOR_SHARED_PAGE_BASE_UC, HYPERVISOR_SHARED_PAGE_BASE_UC + 0x1000 - 1);
    } else {
        Logger::Log("{YEL}HypervisorSharedPage hook failed: %s{RESET}\n", uc_strerror(Err));
    }

    if (DiagnosticHooksEnabled) {
        auto OnDriverSelfRead = [](uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
            DrvSelfReadCount++;
            uint64_t Rva = Addr - DRIVER_BASE_UC;

            if (Rva < 0x1000) {
                DrvSelfHdrReadCount++;
                if (DrvSelfHdrReadCount <= 30) {
                    uint64_t Rip = 0;
                    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
                    uint64_t ReadVal = 0;
                    if (Size <= 8) {
                        void* HostPtr = UnicornMem::UcToHost(Addr);
                        if (HostPtr)
                            memcpy(&ReadVal, HostPtr, Size);
                    }
                    bool External = (Rip < DRIVER_BASE_UC || Rip >= DRIVER_BASE_UC + 0x10000000ULL);
                    if (!External) {
                        Logger::Log("{RED}[DRV SELF-READ HDR] RVA=0x%llx size=%d val=0x%llx drv+0x%llx{RESET}\n",
                            Rva, Size, ReadVal, Rip - DRIVER_BASE_UC);
                    }
                }
            }

            if (Rva >= 0x1FA000 && Rva < 0x1FB000) {
                DrvSelfIatReadCount++;
                static std::unordered_map<uint64_t, std::string> IatSlotNamesByRva;
                static std::once_flag IatSlotInitFlag;
                std::call_once(IatSlotInitFlag, []() {
                    uint8_t* DriverHostBase = (uint8_t*)UnicornMem::UcToHost(DRIVER_BASE_UC);
                    if (!DriverHostBase)
                        return;

                    auto Dos = (PIMAGE_DOS_HEADER)DriverHostBase;
                    if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
                        return;

                    auto Nt = (PIMAGE_NT_HEADERS)(DriverHostBase + Dos->e_lfanew);
                    auto& ImportDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                    if (!ImportDir.VirtualAddress || !ImportDir.Size)
                        return;

                    auto ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(DriverHostBase + ImportDir.VirtualAddress);
                    for (; ImportDesc->Name; ImportDesc++) {
                        const char* DllName = (const char*)(DriverHostBase + ImportDesc->Name);
                        PIMAGE_THUNK_DATA OrigThunk = nullptr;
                        if (ImportDesc->OriginalFirstThunk)
                            OrigThunk = (PIMAGE_THUNK_DATA)(DriverHostBase + ImportDesc->OriginalFirstThunk);
                        else
                            OrigThunk = (PIMAGE_THUNK_DATA)(DriverHostBase + ImportDesc->FirstThunk);

                        uint64_t IatThunkRva = ImportDesc->FirstThunk;
                        for (; OrigThunk && OrigThunk->u1.AddressOfData; OrigThunk++, IatThunkRva += sizeof(IMAGE_THUNK_DATA)) {
                            std::string SlotName;
                            if (IMAGE_SNAP_BY_ORDINAL(OrigThunk->u1.Ordinal)) {
                                char Buf[256] = {};
                                sprintf_s(Buf, sizeof(Buf), "%s!#%u", DllName, (unsigned)IMAGE_ORDINAL(OrigThunk->u1.Ordinal));
                                SlotName = Buf;
                            } else {
                                auto ImportByName = (PIMAGE_IMPORT_BY_NAME)(DriverHostBase + (OrigThunk->u1.AddressOfData & 0x7FFFFFFF));
                                if (ImportByName && ImportByName->Name) {
                                    SlotName = std::string(DllName) + "!" + (const char*)ImportByName->Name;
                                }
                            }
                            if (!SlotName.empty())
                                IatSlotNamesByRva[IatThunkRva] = SlotName;
                        }
                    }
                });

                uint64_t Rip = 0;
                uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
                uint64_t ReadVal = 0;
                if (Size <= 8) {
                    void* HostPtr = UnicornMem::UcToHost(Addr);
                    if (HostPtr)
                        memcpy(&ReadVal, HostPtr, Size);
                }

                const char* SlotName = "?";
                auto SlotIt = IatSlotNamesByRva.find(Rva);
                if (SlotIt != IatSlotNamesByRva.end()) {
                    SlotName = SlotIt->second.c_str();
                }

                std::string TargetName = "unknown";
                if (ReadVal != 0) {
                    auto SentinelIt = UnicornEmu::SentinelMap.find(ReadVal);
                    if (SentinelIt == UnicornEmu::SentinelMap.end()) {
                        SentinelIt = UnicornEmu::SentinelMap.find(ReadVal & ~0xFULL);
                    }
                    if (SentinelIt != UnicornEmu::SentinelMap.end()) {
                        TargetName = SentinelIt->second.Name;
                    } else {
                        std::lock_guard<std::mutex> Guard(UnicornEmu::SysModFuncCacheLock);
                        auto FuncIt = UnicornEmu::SysModFuncCache.find(ReadVal);
                        if (FuncIt != UnicornEmu::SysModFuncCache.end()) {
                            TargetName = FuncIt->second.ModName + "!" + FuncIt->second.FuncName;
                        }
                    }
                    if (TargetName == "unknown") {
                        if (ReadVal >= DRIVER_BASE_UC && ReadVal < DRIVER_BASE_UC + 0x10000000ULL) {
                            char Buf[64] = {};
                            sprintf_s(Buf, sizeof(Buf), "driver+0x%llx", ReadVal - DRIVER_BASE_UC);
                            TargetName = Buf;
                        } else {
                            for (auto& MapMod : UnicornEmu::MappedSysMods) {
                                if (ReadVal >= MapMod.UcBase && ReadVal < MapMod.UcBase + MapMod.Size) {
                                    char Buf[256] = {};
                                    sprintf_s(Buf, sizeof(Buf), "%s+0x%llx", MapMod.Name.c_str(), ReadVal - MapMod.UcBase);
                                    TargetName = Buf;
                                    break;
                                }
                            }
                        }
                    }
                }

                Logger::Log("{RED}[DRV IAT READ] RVA=0x%llx slot=%s size=%d val=0x%llx target=%s RIP=drv+0x%llx{RESET}\n",
                    Rva, SlotName, Size, ReadVal, TargetName.c_str(), Rip - DRIVER_BASE_UC);
            }

            if (DrvSelfReadCount % 100000 == 0) {
                Logger::Log("{CYN}[DRV SELF-READS] total=%d hdr=%d iat=%d{RESET}\n",
                    DrvSelfReadCount, DrvSelfHdrReadCount, DrvSelfIatReadCount);
            }
        };

        using DrvSelfReadFn = void(*)(uc_engine*, uc_mem_type, uint64_t, int, int64_t, void*);
        static DrvSelfReadFn DrvSelfReadPtr = OnDriverSelfRead;

        Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_READ, (void*)DrvSelfReadPtr, nullptr,
            DRIVER_BASE_UC, DRIVER_BASE_UC + 0x200000 - 1);
        if (Err == UC_ERR_OK) {
            Logger::Log("{CYN}Watchpoint: Driver self-reads (0x%llx - 0x%llx){RESET}\n",
                DRIVER_BASE_UC, DRIVER_BASE_UC + 0x200000 - 1);
        }

        RipRingIdx = 0;
        RipRingTotal = 0;
        using RipTraceFn = void(*)(uc_engine*, uint64_t, uint32_t, void*);
        static RipTraceFn RipTracePtr = OnRipRingTrace;
        Err = uc_hook_add(Uc, &Hh, UC_HOOK_CODE, (void*)RipTracePtr, nullptr,
            DRIVER_BASE_UC, DRIVER_BASE_UC + 0x3000000ULL - 1);
        if (Err == UC_ERR_OK) {
            Logger::Log("{CYN}RIP ring trace installed (last %d instructions){RESET}\n", RIP_RING_SIZE);
        }

        static auto OnStackErrorWrite = [](uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size, int64_t Value, void* UserData) {
            if (Size >= 4) {
                uint32_t Val32 = (uint32_t)(Value & 0xFFFFFFFF);
                uint64_t Val64 = (uint64_t)Value;
                if (Val32 == 0xC0000022 || Val64 == 0xC0000022) {
                    uint64_t Rip = 0;
                    uc_reg_read(Uc, UC_X86_REG_RIP, &Rip);
                    uint64_t DriverRva = (Rip >= DRIVER_BASE_UC) ? Rip - DRIVER_BASE_UC : Rip;
                    //Logger::Log("{RED}[STACK WRITE 0xC0000022] addr=0x%llx size=%d val=0x%llx RIP=drv+0x%llx insn#%llu{RESET}\n",
                    //    Addr, Size, Val64, DriverRva, RipRingTotal);
                }
            }
        };
        using StackWriteFn = void(*)(uc_engine*, uc_mem_type, uint64_t, int, int64_t, void*);
        static StackWriteFn StackWritePtr = OnStackErrorWrite;
        uint64_t StackBase = STACK_BASE_UC;
        uint64_t StackEnd = StackBase + STACK_SIZE_UC - 1;
        Err = uc_hook_add(Uc, &Hh, UC_HOOK_MEM_WRITE, (void*)StackWritePtr, nullptr, StackBase, StackEnd);
        if (Err == UC_ERR_OK) {
            //Logger::Log("{CYN}Watchpoint: Stack writes for 0xC0000022 (0x%llx - 0x%llx){RESET}\n", StackBase, StackEnd);
        }

    } else {
        RipRingIdx = 0;
        RipRingTotal = 0;
        const char* StatusTrace = std::getenv("KEVLAR_STATUS_TRACE");
        if (StatusTrace && StatusTrace[0] != '0') {
            using RipTraceFn = void(*)(uc_engine*, uint64_t, uint32_t, void*);
            static RipTraceFn RipTracePtr = OnRipRingTrace;
            Err = uc_hook_add(Uc, &Hh, UC_HOOK_CODE, (void*)RipTracePtr, nullptr,
                DRIVER_BASE_UC, DRIVER_BASE_UC + 0x3000000ULL - 1);
            if (Err == UC_ERR_OK) {
                Logger::Log("{CYN}FAST MODE: Lightweight DriverEntry status trace installed (last %d instructions){RESET}\n",
                    RIP_RING_SIZE);
            } else {
                Logger::Log("{RED}FAST MODE: Failed to install lightweight status trace: %s{RESET}\n", uc_strerror(Err));
            }
        }
        Logger::Log("{YEL}FAST MODE: Skipping driver self-read and sysmod read hooks{RESET}\n");
    }

    
}

// ---------------------------------------------------------------------------
// Hot-block profiler (--blockprof). A basic-block hook feeding a fixed-size
// table of atomics: cheap enough to leave on for a multi-minute run, readable
// from the heartbeat thread while the guest keeps running, and the per-interval
// delta answers what a 5s RIP sample cannot - whether the guest is cycling over
// a handful of blocks or making forward progress through new code.
// ---------------------------------------------------------------------------
namespace {
    constexpr size_t kBlockProfSlots = 1u << 17;
    constexpr int kBlockProfProbes = 8;

    struct BlockProfSlot {
        std::atomic<uint64_t> Addr;
        std::atomic<uint64_t> Count;
    };

    BlockProfSlot gBlockProf[kBlockProfSlots];
    std::atomic<uint64_t> gBlockProfTotal{ 0 };
    std::atomic<uint64_t> gBlockProfDropped{ 0 };
    uint64_t gBlockProfLastTotal = 0;
    std::unordered_map<uint64_t, uint64_t> gBlockProfLastCounts;
}

// Where the guest's loads land, by region. A loop that makes no API calls is
// polling memory; this says which memory.
namespace {
    enum ReadBucket {
        ReadBucketKusd = 0, ReadBucketHvsp, ReadBucketHyperspace, ReadBucketDriver,
        ReadBucketStack, ReadBucketPool, ReadBucketSysMod, ReadBucketKernelStruct,
        ReadBucketSentinel, ReadBucketOther, ReadBucketCount
    };

    const char* kReadBucketNames[ReadBucketCount] = {
        "KUSD", "HvSharedPage", "hyperspace", "driver image",
        "stack", "pool", "system modules", "KPCR/ETHREAD/EPROCESS",
        "sentinels", "other"
    };

    std::atomic<uint64_t> gReadBuckets[ReadBucketCount];
    std::atomic<uint64_t> gKusdOffsets[512];

    // Per-bucket address span for the current interval: a sweep (unpack, hash,
    // signature scan) walks its range, a spin keeps re-reading the same words.
    std::atomic<uint64_t> gReadMin[ReadBucketCount];
    std::atomic<uint64_t> gReadMax[ReadBucketCount];
}

static void TrackReadSpan(int Bucket, uint64_t Addr) {
    uint64_t Min = gReadMin[Bucket].load(std::memory_order_relaxed);
    while (Addr < Min) {
        if (gReadMin[Bucket].compare_exchange_weak(Min, Addr, std::memory_order_relaxed))
            break;
    }

    uint64_t Max = gReadMax[Bucket].load(std::memory_order_relaxed);
    while (Addr > Max) {
        if (gReadMax[Bucket].compare_exchange_weak(Max, Addr, std::memory_order_relaxed))
            break;
    }
}

static void OnReadProfile(uc_engine* Uc, uc_mem_type Type, uint64_t Addr, int Size,
                          int64_t Value, void* UserData) {
    int Bucket = ReadBucketOther;

    if (Addr >= KUSD_BASE_UC && Addr < KUSD_BASE_UC + 0x1000) {
        Bucket = ReadBucketKusd;
        gKusdOffsets[(Addr - KUSD_BASE_UC) >> 3].fetch_add(1, std::memory_order_relaxed);
    } else if (Addr >= HYPERVISOR_SHARED_PAGE_BASE_UC && Addr < HYPERVISOR_SHARED_PAGE_BASE_UC + 0x1000) {
        Bucket = ReadBucketHvsp;
    } else if (Addr >= HYPERSPACE_BASE_UC && Addr < HYPERSPACE_BASE_UC + HYPERSPACE_SIZE_UC) {
        Bucket = ReadBucketHyperspace;
    } else if (Addr >= DRIVER_BASE_UC && Addr < DRIVER_BASE_UC + 0x10000000ULL) {
        Bucket = ReadBucketDriver;
    } else if (Addr >= STACK_BASE_UC && Addr < STACK_BASE_UC + STACK_SIZE_UC) {
        Bucket = ReadBucketStack;
    } else if (Addr >= POOL_BASE_UC && Addr < POOL_BASE_UC + 0x100000000ULL) {
        Bucket = ReadBucketPool;
    } else if (Addr >= SYSMOD_BASE_UC && Addr < SYSMOD_BASE_UC + 0x100000000ULL) {
        Bucket = ReadBucketSysMod;
    } else if (Addr >= KPCR_BASE_UC && Addr < KPCR_BASE_UC + 0x1000000ULL) {
        Bucket = ReadBucketKernelStruct;
    } else if (Addr >= SENTINEL_BASE_UC && Addr < SENTINEL_BASE_UC + SENTINEL_RANGE_SIZE) {
        Bucket = ReadBucketSentinel;
    }

    gReadBuckets[Bucket].fetch_add(1, std::memory_order_relaxed);
    TrackReadSpan(Bucket, Addr);
}

static void OnBlockProfile(uc_engine* Uc, uint64_t Addr, uint32_t Size, void* UserData) {
    gBlockProfTotal.fetch_add(1, std::memory_order_relaxed);

    uint64_t Hash = (Addr * 0x9E3779B97F4A7C15ULL) >> 47;
    for (int Probe = 0; Probe < kBlockProfProbes; Probe++) {
        auto& Slot = gBlockProf[(Hash + Probe) & (kBlockProfSlots - 1)];
        uint64_t Existing = Slot.Addr.load(std::memory_order_relaxed);
        if (Existing == Addr) {
            Slot.Count.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        if (Existing == 0) {
            uint64_t Expected = 0;
            if (Slot.Addr.compare_exchange_strong(Expected, Addr, std::memory_order_relaxed) ||
                Slot.Addr.load(std::memory_order_relaxed) == Addr) {
                Slot.Count.fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
    }

    gBlockProfDropped.fetch_add(1, std::memory_order_relaxed);
}

void UnicornEmu::InstallBlockProfiler(uc_engine* Uc) {
    if (!BlockProfileEnabled)
        return;

    for (int I = 0; I < ReadBucketCount; I++) {
        gReadMin[I].store(~0ULL, std::memory_order_relaxed);
        gReadMax[I].store(0, std::memory_order_relaxed);
    }

    uc_hook Hh;
    uc_err Err = uc_hook_add(Uc, &Hh, UC_HOOK_BLOCK, (void*)OnBlockProfile, nullptr, 1, 0);
    if (Err != UC_ERR_OK)
        Logger::Log("{RED}Block profiler hook failed: %s{RESET}\n", uc_strerror(Err));

    uc_hook ReadHh;
    Err = uc_hook_add(Uc, &ReadHh, UC_HOOK_MEM_READ, (void*)OnReadProfile, nullptr, 1, 0);
    if (Err != UC_ERR_OK)
        Logger::Log("{RED}Read profiler hook failed: %s{RESET}\n", uc_strerror(Err));
}

void UnicornEmu::DumpBlockProfile(const char* Reason) {
    if (!BlockProfileEnabled)
        return;

    struct ProfEntry { uint64_t Addr; uint64_t Count; uint64_t Delta; };
    std::vector<ProfEntry> Entries;

    for (size_t I = 0; I < kBlockProfSlots; I++) {
        uint64_t Addr = gBlockProf[I].Addr.load(std::memory_order_relaxed);
        if (!Addr)
            continue;

        uint64_t Count = gBlockProf[I].Count.load(std::memory_order_relaxed);
        uint64_t Prev = 0;
        auto It = gBlockProfLastCounts.find(Addr);
        if (It != gBlockProfLastCounts.end())
            Prev = It->second;

        Entries.push_back({ Addr, Count, Count - Prev });
        gBlockProfLastCounts[Addr] = Count;
    }

    uint64_t Total = gBlockProfTotal.load(std::memory_order_relaxed);
    uint64_t TotalDelta = Total - gBlockProfLastTotal;
    gBlockProfLastTotal = Total;

    std::sort(Entries.begin(), Entries.end(),
        [](const ProfEntry& A, const ProfEntry& B) { return A.Delta > B.Delta; });

    Logger::Log("{CYN}[BLOCKPROF %s] %llu blocks total (+%llu), %zu distinct, %llu dropped{RESET}\n",
        Reason, Total, TotalDelta, Entries.size(), gBlockProfDropped.load(std::memory_order_relaxed));

    Logger::Log("{CYN}[BLOCKPROF] uc_emu_start re-entries: %llu, instructions emulated by host: %llu{RESET}\n",
        UnicornEmu::GetEmuStartCount(), UnicornEmu::GetInsnEmulatedCount());

    uint64_t ReadTotal = 0;
    for (int I = 0; I < ReadBucketCount; I++)
        ReadTotal += gReadBuckets[I].load(std::memory_order_relaxed);

    if (ReadTotal) {
        char ReadLine[512];
        int Used = 0;
        for (int I = 0; I < ReadBucketCount; I++) {
            uint64_t Count = gReadBuckets[I].load(std::memory_order_relaxed);
            if (!Count)
                continue;
            Used += snprintf(ReadLine + Used, sizeof(ReadLine) - Used, "%s=%.1f%% ",
                kReadBucketNames[I], 100.0 * (double)Count / (double)ReadTotal);
            if (Used >= (int)sizeof(ReadLine) - 32)
                break;
        }
        Logger::Log("{CYN}[READPROF] %llu reads: %s{RESET}\n", ReadTotal, ReadLine);

        for (int I = 0; I < ReadBucketCount; I++) {
            uint64_t Count = gReadBuckets[I].load(std::memory_order_relaxed);
            if (!Count)
                continue;

            uint64_t Min = gReadMin[I].load(std::memory_order_relaxed);
            uint64_t Max = gReadMax[I].load(std::memory_order_relaxed);
            if (Min > Max)
                continue;

            Logger::Log("{GRY}  %-22s span 0x%llx - 0x%llx (%llu KB)  reads=%llu{RESET}\n",
                kReadBucketNames[I], Min, Max, (Max - Min) / 1024, Count);

            // Reset the span each interval so the next dump shows fresh movement.
            gReadMin[I].store(~0ULL, std::memory_order_relaxed);
            gReadMax[I].store(0, std::memory_order_relaxed);
        }

        uint64_t KusdReads = gReadBuckets[ReadBucketKusd].load(std::memory_order_relaxed);
        if (KusdReads) {
            char KusdLine[512];
            int KusdUsed = 0;
            for (int I = 0; I < 512; I++) {
                uint64_t Count = gKusdOffsets[I].load(std::memory_order_relaxed);
                if (!Count)
                    continue;
                KusdUsed += snprintf(KusdLine + KusdUsed, sizeof(KusdLine) - KusdUsed,
                    "+0x%x:%llu ", (unsigned)(I * 8), Count);
                if (KusdUsed >= (int)sizeof(KusdLine) - 24)
                    break;
            }
            Logger::Log("{CYN}[READPROF] KUSD offsets: %s{RESET}\n", KusdLine);
        }
    }

    int Shown = 0;
    for (auto& E : Entries) {
        if (Shown >= 12 || E.Delta == 0)
            break;
        Shown++;

        double Share = TotalDelta ? (100.0 * (double)E.Delta / (double)TotalDelta) : 0.0;
        bool InDriver = (E.Addr >= DRIVER_BASE_UC && E.Addr < DRIVER_BASE_UC + 0x10000000ULL);
        if (InDriver) {
            Logger::Log("{GRY}  drv+0x%-9llx +%-12llu (%5.1f%%) total %llu{RESET}\n",
                E.Addr - DRIVER_BASE_UC, E.Delta, Share, E.Count);
        } else {
            Logger::Log("{GRY}  0x%-13llx +%-12llu (%5.1f%%) total %llu{RESET}\n",
                E.Addr, E.Delta, Share, E.Count);
        }
    }
}


// A UC_HOOK_CODE spanning the whole driver range fires for every instruction the
// guest executes and stops Unicorn chaining basic blocks, which on virtualised
// code costs far more than the handful of MSR accesses it exists to catch. The
// rdmsr/wrmsr encodings are two bytes, so find the pages that actually contain
// them and hook only those - on a 13MB virtualised driver that is ~7% of the
// executable pages.
//
// ponytail: the scan runs once, over the image as mapped. Code decrypted into
// pages that held no 0F 30 / 0F 32 at scan time is not intercepted; extend this
// with a write-triggered rescan when a driver is observed doing that.
static uc_hook gMsrWideHook = 0;
static uc_engine* gMsrWideEngine = nullptr;

void UnicornEmu::InstallMsrIntercept(uc_engine* Uc) {
    uint64_t ImageBase = 0;
    uint64_t ImageSize = 0;
    const uint8_t* ImageHost = nullptr;

    for (auto& Region : MappedRegions) {
        if (Region.Name == "DriverImage") {
            ImageBase = Region.UcBase;
            ImageSize = Region.Size;
            ImageHost = (const uint8_t*)Region.HostPtr;
            break;
        }
    }

    uc_hook Hh;

    if (!ImageHost || ImageSize < 2) {
        // Called before the driver is mapped (engine setup): cover everything and
        // let the post-load call narrow it down.
        uc_err WideErr = uc_hook_add(Uc, &Hh, UC_HOOK_CODE, (void*)Hooks::OnMsrFallback, nullptr,
            DRIVER_BASE_UC, DRIVER_BASE_UC + 0x10000000ULL - 1);
        if (WideErr == UC_ERR_OK) {
            gMsrWideHook = Hh;
            gMsrWideEngine = Uc;
        }
        Logger::Log("{GRN}MSR intercept: whole-image code hook (driver not mapped yet)%s{RESET}\n",
            WideErr == UC_ERR_OK ? "" : " FAILED");
        return;
    }

    // Drop the whole-image hook installed before the driver was mapped.
    if (gMsrWideHook && gMsrWideEngine == Uc) {
        uc_hook_del(Uc, gMsrWideHook);
        gMsrWideHook = 0;
        gMsrWideEngine = nullptr;
    }

    std::vector<std::pair<uint64_t, uint64_t>> Ranges;
    for (uint64_t Offset = 0; Offset + 1 < ImageSize; Offset++) {
        if (ImageHost[Offset] != 0x0F)
            continue;
        if (ImageHost[Offset + 1] != 0x30 && ImageHost[Offset + 1] != 0x32)
            continue;

        uint64_t PageStart = ImageBase + (Offset & ~0xFFFULL);
        uint64_t PageEnd = PageStart + 0x1000;

        // An encoding can carry prefixes, so include the tail of the page before it.
        if (PageStart > ImageBase)
            PageStart -= 0x10;

        if (!Ranges.empty() && Ranges.back().second >= PageStart)
            Ranges.back().second = PageEnd;
        else
            Ranges.push_back({ PageStart, PageEnd });
    }

    int Installed = 0;
    for (auto& Range : Ranges) {
        if (uc_hook_add(Uc, &Hh, UC_HOOK_CODE, (void*)Hooks::OnMsrFallback, nullptr,
                Range.first, Range.second - 1) == UC_ERR_OK)
            Installed++;
    }

    uint64_t Covered = 0;
    for (auto& Range : Ranges)
        Covered += Range.second - Range.first;

    Logger::Log("{GRN}MSR intercept: %d ranges covering %llu KB of %llu KB image (rdmsr=%d wrmsr=%d){RESET}\n",
        Installed, Covered / 1024, ImageSize / 1024,
        UnicornEmu::RdmsrInsnHookSupported ? 1 : 0,
        UnicornEmu::WrmsrInsnHookSupported ? 1 : 0);
}
