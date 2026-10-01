// VERSION.dll compatibility exports required by cod.exe and bootstrapper.exe.
// Resolve the genuine implementation from System32 so this DLL can be placed beside
// either executable under the name VERSION.dll without breaking version queries.

#include <windows.h>

namespace {

using GetFileVersionInfoSizeAFn = DWORD (WINAPI*)(LPCSTR, LPDWORD);
using GetFileVersionInfoSizeWFn = DWORD (WINAPI*)(LPCWSTR, LPDWORD);
using GetFileVersionInfoAFn = BOOL (WINAPI*)(LPCSTR, DWORD, DWORD, LPVOID);
using GetFileVersionInfoWFn = BOOL (WINAPI*)(LPCWSTR, DWORD, DWORD, LPVOID);
using GetFileVersionInfoSizeExAFn = DWORD (WINAPI*)(DWORD, LPCSTR, LPDWORD);
using GetFileVersionInfoSizeExWFn = DWORD (WINAPI*)(DWORD, LPCWSTR, LPDWORD);
using GetFileVersionInfoExAFn = BOOL (WINAPI*)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
using GetFileVersionInfoExWFn = BOOL (WINAPI*)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
using GetFileVersionInfoByHandleFn = BOOL (WINAPI*)(DWORD, HANDLE, LPVOID*, PDWORD);
using VerFindFileAFn = DWORD (WINAPI*)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
using VerFindFileWFn = DWORD (WINAPI*)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
using VerInstallFileAFn = DWORD (WINAPI*)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
using VerInstallFileWFn = DWORD (WINAPI*)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
using VerLanguageNameAFn = DWORD (WINAPI*)(DWORD, LPSTR, DWORD);
using VerLanguageNameWFn = DWORD (WINAPI*)(DWORD, LPWSTR, DWORD);
using VerQueryValueAFn = BOOL (WINAPI*)(LPCVOID, LPCSTR, LPVOID*, PUINT);
using VerQueryValueWFn = BOOL (WINAPI*)(LPCVOID, LPCWSTR, LPVOID*, PUINT);

struct VersionFunctions {
    HMODULE Module = nullptr;
    GetFileVersionInfoSizeAFn GetFileVersionInfoSizeA = nullptr;
    GetFileVersionInfoSizeWFn GetFileVersionInfoSizeW = nullptr;
    GetFileVersionInfoAFn GetFileVersionInfoA = nullptr;
    GetFileVersionInfoWFn GetFileVersionInfoW = nullptr;
    GetFileVersionInfoSizeExAFn GetFileVersionInfoSizeExA = nullptr;
    GetFileVersionInfoSizeExWFn GetFileVersionInfoSizeExW = nullptr;
    GetFileVersionInfoExAFn GetFileVersionInfoExA = nullptr;
    GetFileVersionInfoExWFn GetFileVersionInfoExW = nullptr;
    GetFileVersionInfoByHandleFn GetFileVersionInfoByHandle = nullptr;
    VerFindFileAFn VerFindFileA = nullptr;
    VerFindFileWFn VerFindFileW = nullptr;
    VerInstallFileAFn VerInstallFileA = nullptr;
    VerInstallFileWFn VerInstallFileW = nullptr;
    VerLanguageNameAFn VerLanguageNameA = nullptr;
    VerLanguageNameWFn VerLanguageNameW = nullptr;
    VerQueryValueAFn VerQueryValueA = nullptr;
    VerQueryValueWFn VerQueryValueW = nullptr;
};

VersionFunctions LoadVersionFunctions() {
    VersionFunctions Functions;

    wchar_t SystemDirectory[MAX_PATH];
    UINT Length = GetSystemDirectoryW(SystemDirectory, ARRAYSIZE(SystemDirectory));
    if (!Length || Length >= ARRAYSIZE(SystemDirectory) - 13)
        return Functions;

    const wchar_t Suffix[] = L"\\version.dll";
    CopyMemory(SystemDirectory + Length, Suffix, sizeof(Suffix));
    Functions.Module = LoadLibraryExW(
        SystemDirectory, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Functions.Module)
        return Functions;

#define RESOLVE_VERSION_FUNCTION(Name) \
    Functions.Name = reinterpret_cast<Name##Fn>(GetProcAddress(Functions.Module, #Name))
    RESOLVE_VERSION_FUNCTION(GetFileVersionInfoSizeA);
    RESOLVE_VERSION_FUNCTION(GetFileVersionInfoSizeW);
    RESOLVE_VERSION_FUNCTION(GetFileVersionInfoA);
    RESOLVE_VERSION_FUNCTION(GetFileVersionInfoW);
    RESOLVE_VERSION_FUNCTION(GetFileVersionInfoSizeExA);
    RESOLVE_VERSION_FUNCTION(GetFileVersionInfoSizeExW);
    RESOLVE_VERSION_FUNCTION(GetFileVersionInfoExA);
    RESOLVE_VERSION_FUNCTION(GetFileVersionInfoExW);
    RESOLVE_VERSION_FUNCTION(GetFileVersionInfoByHandle);
    RESOLVE_VERSION_FUNCTION(VerFindFileA);
    RESOLVE_VERSION_FUNCTION(VerFindFileW);
    RESOLVE_VERSION_FUNCTION(VerInstallFileA);
    RESOLVE_VERSION_FUNCTION(VerInstallFileW);
    RESOLVE_VERSION_FUNCTION(VerLanguageNameA);
    RESOLVE_VERSION_FUNCTION(VerLanguageNameW);
    RESOLVE_VERSION_FUNCTION(VerQueryValueA);
    RESOLVE_VERSION_FUNCTION(VerQueryValueW);
#undef RESOLVE_VERSION_FUNCTION

    return Functions;
}

VersionFunctions& RealVersion() {
    static VersionFunctions Functions = LoadVersionFunctions();
    return Functions;
}

void MissingVersionFunction() {
    SetLastError(ERROR_PROC_NOT_FOUND);
}

} // namespace

extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeA(
    LPCSTR Filename,
    LPDWORD Handle) {
    auto Function = RealVersion().GetFileVersionInfoSizeA;
    if (!Function) {
        MissingVersionFunction();
        return 0;
    }
    return Function(Filename, Handle);
}

extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeW(
    LPCWSTR Filename,
    LPDWORD Handle) {
    auto Function = RealVersion().GetFileVersionInfoSizeW;
    if (!Function) {
        MissingVersionFunction();
        return 0;
    }
    return Function(Filename, Handle);
}

extern "C" BOOL WINAPI Proxy_GetFileVersionInfoA(
    LPCSTR Filename,
    DWORD Handle,
    DWORD DataLength,
    LPVOID Data) {
    auto Function = RealVersion().GetFileVersionInfoA;
    if (!Function) {
        MissingVersionFunction();
        return FALSE;
    }
    return Function(Filename, Handle, DataLength, Data);
}

extern "C" BOOL WINAPI Proxy_GetFileVersionInfoW(
    LPCWSTR Filename,
    DWORD Handle,
    DWORD DataLength,
    LPVOID Data) {
    auto Function = RealVersion().GetFileVersionInfoW;
    if (!Function) {
        MissingVersionFunction();
        return FALSE;
    }
    return Function(Filename, Handle, DataLength, Data);
}

extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeExA(
    DWORD Flags,
    LPCSTR Filename,
    LPDWORD Handle) {
    auto Function = RealVersion().GetFileVersionInfoSizeExA;
    if (!Function) {
        MissingVersionFunction();
        return 0;
    }
    return Function(Flags, Filename, Handle);
}

extern "C" DWORD WINAPI Proxy_GetFileVersionInfoSizeExW(
    DWORD Flags,
    LPCWSTR Filename,
    LPDWORD Handle) {
    auto Function = RealVersion().GetFileVersionInfoSizeExW;
    if (!Function) {
        MissingVersionFunction();
        return 0;
    }
    return Function(Flags, Filename, Handle);
}

extern "C" BOOL WINAPI Proxy_GetFileVersionInfoExA(
    DWORD Flags,
    LPCSTR Filename,
    DWORD Handle,
    DWORD DataLength,
    LPVOID Data) {
    auto Function = RealVersion().GetFileVersionInfoExA;
    if (!Function) {
        MissingVersionFunction();
        return FALSE;
    }
    return Function(Flags, Filename, Handle, DataLength, Data);
}

extern "C" BOOL WINAPI Proxy_GetFileVersionInfoExW(
    DWORD Flags,
    LPCWSTR Filename,
    DWORD Handle,
    DWORD DataLength,
    LPVOID Data) {
    auto Function = RealVersion().GetFileVersionInfoExW;
    if (!Function) {
        MissingVersionFunction();
        return FALSE;
    }
    return Function(Flags, Filename, Handle, DataLength, Data);
}

extern "C" BOOL WINAPI Proxy_GetFileVersionInfoByHandle(
    DWORD Flags,
    HANDLE File,
    LPVOID* Data,
    PDWORD DataLength) {
    auto Function = RealVersion().GetFileVersionInfoByHandle;
    if (!Function) {
        MissingVersionFunction();
        return FALSE;
    }
    return Function(Flags, File, Data, DataLength);
}

extern "C" DWORD WINAPI Proxy_VerFindFileA(
    DWORD Flags,
    LPCSTR FileName,
    LPCSTR WinDir,
    LPCSTR AppDir,
    LPSTR CurDir,
    PUINT CurDirLen,
    LPSTR DestDir,
    PUINT DestDirLen) {
    auto Function = RealVersion().VerFindFileA;
    if (!Function) {
        MissingVersionFunction();
        return 0;
    }
    return Function(Flags, FileName, WinDir, AppDir, CurDir, CurDirLen, DestDir, DestDirLen);
}

extern "C" DWORD WINAPI Proxy_VerFindFileW(
    DWORD Flags,
    LPCWSTR FileName,
    LPCWSTR WinDir,
    LPCWSTR AppDir,
    LPWSTR CurDir,
    PUINT CurDirLen,
    LPWSTR DestDir,
    PUINT DestDirLen) {
    auto Function = RealVersion().VerFindFileW;
    if (!Function) {
        MissingVersionFunction();
        return 0;
    }
    return Function(Flags, FileName, WinDir, AppDir, CurDir, CurDirLen, DestDir, DestDirLen);
}

extern "C" DWORD WINAPI Proxy_VerInstallFileA(
    DWORD Flags,
    LPCSTR SrcFileName,
    LPCSTR DestFileName,
    LPCSTR SrcDir,
    LPCSTR DestDir,
    LPCSTR CurDir,
    LPSTR TmpFile,
    PUINT TmpFileLen) {
    auto Function = RealVersion().VerInstallFileA;
    if (!Function) {
        MissingVersionFunction();
        return 0;
    }
    return Function(Flags, SrcFileName, DestFileName, SrcDir, DestDir, CurDir, TmpFile, TmpFileLen);
}

extern "C" DWORD WINAPI Proxy_VerInstallFileW(
    DWORD Flags,
    LPCWSTR SrcFileName,
    LPCWSTR DestFileName,
    LPCWSTR SrcDir,
    LPCWSTR DestDir,
    LPCWSTR CurDir,
    LPWSTR TmpFile,
    PUINT TmpFileLen) {
    auto Function = RealVersion().VerInstallFileW;
    if (!Function) {
        MissingVersionFunction();
        return 0;
    }
    return Function(Flags, SrcFileName, DestFileName, SrcDir, DestDir, CurDir, TmpFile, TmpFileLen);
}

extern "C" DWORD WINAPI Proxy_VerLanguageNameA(
    DWORD Lang,
    LPSTR LangString,
    DWORD Size) {
    auto Function = RealVersion().VerLanguageNameA;
    if (!Function) {
        MissingVersionFunction();
        return 0;
    }
    return Function(Lang, LangString, Size);
}

extern "C" DWORD WINAPI Proxy_VerLanguageNameW(
    DWORD Lang,
    LPWSTR LangString,
    DWORD Size) {
    auto Function = RealVersion().VerLanguageNameW;
    if (!Function) {
        MissingVersionFunction();
        return 0;
    }
    return Function(Lang, LangString, Size);
}

extern "C" BOOL WINAPI Proxy_VerQueryValueA(
    LPCVOID Block,
    LPCSTR SubBlock,
    LPVOID* Buffer,
    PUINT Length) {
    auto Function = RealVersion().VerQueryValueA;
    if (!Function) {
        MissingVersionFunction();
        return FALSE;
    }
    return Function(Block, SubBlock, Buffer, Length);
}

extern "C" BOOL WINAPI Proxy_VerQueryValueW(
    LPCVOID Block,
    LPCWSTR SubBlock,
    LPVOID* Buffer,
    PUINT Length) {
    auto Function = RealVersion().VerQueryValueW;
    if (!Function) {
        MissingVersionFunction();
        return FALSE;
    }
    return Function(Block, SubBlock, Buffer, Length);
}
