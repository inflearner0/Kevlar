/*
 * bridge_client.exe -- an ordinary usermode driver client. It knows nothing about
 * KEVLAR: it installs a kernel service, starts it, opens the device by its DOS name and
 * talks to it, exactly as it would against a real driver.
 *
 * Run on its own it fails at the first step without administrator rights, which is the
 * control case. Run under kevlar_inject it should reach the end, with every answer
 * coming from bridge_driver.sys executing inside the emulator.
 */

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* Deliberately unlike the device name and unlike the .sys filename: the bridge is
 * found by a fixed channel and the device is matched by name, so how the client
 * chose to install the driver must not matter. */
#define SERVICE_NAME   L"UnrelatedServiceName"
#define DEVICE_PATH    L"\\\\.\\KevlarBridgeTest"
#define IMAGE_PATH     L"C:\\Windows\\System32\\drivers\\kevlarbridgetest.sys"

#define IOCTL_KEVLAR_PING  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KEVLAR_ECHO  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KEVLAR_STATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define KEVLAR_PING_MAGIC 0x4B564C42UL

typedef struct _KEVLAR_TEST_STATE {
    ULONG CreateCount;
    ULONG IoctlCount;
    ULONG WriteBytes;
    ULONG ReadCount;
} KEVLAR_TEST_STATE;

static int g_Failures;

static void Check(const char *Label, BOOL Ok, const char *Format, ...)
{
    char Detail[256] = { 0 };
    va_list Args;

    va_start(Args, Format);
    if (Format)
        vsnprintf(Detail, sizeof(Detail), Format, Args);
    va_end(Args);

    printf("%-26s %s %s\n", Label, Ok ? "OK  " : "FAIL", Detail);
    fflush(stdout);
    if (!Ok)
        g_Failures++;
}

/* Second half of the child-propagation test. The child never touches the SCM: it only
 * opens the device and pings it. Reaching the driver at all means two things worked --
 * the parent's CreateProcess hook injected this DLL into a process it spawned, and the
 * pipe name reached the child through the inherited environment. */
static int RunAsChild(void)
{
    HANDLE Device;
    DWORD Returned = 0;
    ULONG Magic = 0;

    Device = CreateFileW(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                         OPEN_EXISTING, 0, NULL);
    Check("child: CreateFile(device)", Device != INVALID_HANDLE_VALUE, "handle=%p gle=%lu",
          Device, GetLastError());
    if (Device == INVALID_HANDLE_VALUE)
        return 1;

    DeviceIoControl(Device, IOCTL_KEVLAR_PING, NULL, 0, &Magic, sizeof(Magic),
                    &Returned, NULL);
    Check("child: IOCTL_PING", Returned == sizeof(Magic) && Magic == KEVLAR_PING_MAGIC,
          "returned=%lu magic=0x%08lX", Returned, Magic);

    CloseHandle(Device);
    return g_Failures ? 1 : 0;
}

/* Relaunches this same exe as a child while the parent is still running and still holds
 * its own bridge session, so the run also covers two clients on the pipe at once. */
static void SpawnChildAndCheck(void)
{
    wchar_t SelfPath[MAX_PATH];
    wchar_t CommandLine[MAX_PATH + 16];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    DWORD ExitCode = 1;

    ZeroMemory(&StartupInfo, sizeof(StartupInfo));
    ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));
    StartupInfo.cb = sizeof(StartupInfo);

    if (!GetModuleFileNameW(NULL, SelfPath, MAX_PATH)) {
        Check("spawn child", FALSE, "GetModuleFileName failed");
        return;
    }
    _snwprintf_s(CommandLine, MAX_PATH + 16, _TRUNCATE, L"\"%s\" --child", SelfPath);

    if (!CreateProcessW(SelfPath, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL,
                        &StartupInfo, &ProcessInfo)) {
        Check("spawn child", FALSE, "CreateProcess failed gle=%lu", GetLastError());
        return;
    }

    WaitForSingleObject(ProcessInfo.hProcess, 60000);
    GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);

    Check("child reached the driver", ExitCode == 0, "child exit=%lu", ExitCode);
}

/* The device half of the test: every assertion whose answer only the emulated driver
 * could produce, kept separate from the SCM dance in main() that has to happen first.
 * Returns 0 on success. */
static int RunDeviceBattery(BOOL WithChild)
{
    HANDLE Device;
    DWORD Returned = 0, Transferred = 0;
    ULONG Magic = 0;
    KEVLAR_TEST_STATE State = { 0 };
    /* Lower case on the way in; the driver upper-cases it. */
    const char EchoIn[] = "kevlar-bridge-echo";
    const char WritePayload[] = "state-through-the-emulator";
    char EchoOut[64] = { 0 };
    char ReadBack[64] = { 0 };

    Device = CreateFileW(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                         OPEN_EXISTING, 0, NULL);
    Check("CreateFile(device)", Device != INVALID_HANDLE_VALUE, "handle=%p gle=%lu",
          Device, GetLastError());
    if (Device == INVALID_HANDLE_VALUE)
        return 1;

    /* A value only the driver knows. A stub returning zero cannot produce it. */
    Returned = 0;
    DeviceIoControl(Device, IOCTL_KEVLAR_PING, NULL, 0, &Magic, sizeof(Magic),
                    &Returned, NULL);
    Check("IOCTL_PING", Returned == sizeof(Magic) && Magic == KEVLAR_PING_MAGIC,
          "returned=%lu magic=0x%08lX", Returned, Magic);

    /* A transform, not a copy: proves the dispatch routine executed. */
    Returned = 0;
    DeviceIoControl(Device, IOCTL_KEVLAR_ECHO, (LPVOID)EchoIn, (DWORD)strlen(EchoIn),
                    EchoOut, sizeof(EchoOut), &Returned, NULL);
    Check("IOCTL_ECHO (uppercased)",
          Returned == strlen(EchoIn) && strcmp(EchoOut, "KEVLAR-BRIDGE-ECHO") == 0,
          "returned=%lu \"%s\"", Returned, EchoOut);

    Transferred = 0;
    WriteFile(Device, WritePayload, (DWORD)strlen(WritePayload), &Transferred, NULL);
    Check("WriteFile", Transferred == strlen(WritePayload), "written=%lu", Transferred);

    /* The driver hands back what the write left behind -- state across two IRPs. */
    Transferred = 0;
    ReadFile(Device, ReadBack, sizeof(ReadBack), &Transferred, NULL);
    Check("ReadFile (write echoed back)",
          Transferred == strlen(WritePayload) && strcmp(ReadBack, WritePayload) == 0,
          "read=%lu \"%s\"", Transferred, ReadBack);

    /* Counters the driver kept across every request in this session. IoctlCount is 3
     * because this call is itself the third: PING, ECHO, then STATE. */
    Returned = 0;
    DeviceIoControl(Device, IOCTL_KEVLAR_STATE, NULL, 0, &State, sizeof(State),
                    &Returned, NULL);
    Check("IOCTL_STATE (counters)",
          Returned == sizeof(State) && State.CreateCount == 1 && State.IoctlCount == 3 &&
          State.WriteBytes == strlen(WritePayload) && State.ReadCount == 1,
          "create=%lu ioctl=%lu written=%lu reads=%lu", State.CreateCount,
          State.IoctlCount, State.WriteBytes, State.ReadCount);

    /* Still holding the device open, so the child is a second concurrent client. */
    if (WithChild)
        SpawnChildAndCheck();

    Check("CloseHandle(device)", CloseHandle(Device), NULL);
    return g_Failures ? 1 : 0;
}

int main(int argc, char **argv)
{
    SC_HANDLE Manager, Service, Reopened;
    SERVICE_STATUS_PROCESS StatusProcess;
    SERVICE_STATUS Status = { 0 };
    DWORD Needed = 0;

    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        int Result = RunAsChild();
        printf("\nRESULT: %s\n", Result ? "FAIL" : "PASS");
        fflush(stdout);
        return Result;
    }

    Manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    Check("OpenSCManager", Manager != NULL, "handle=%p gle=%lu", Manager, GetLastError());
    if (!Manager)
        goto done;

    Service = CreateServiceW(Manager, SERVICE_NAME, SERVICE_NAME, SERVICE_ALL_ACCESS,
                             SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                             SERVICE_ERROR_NORMAL, IMAGE_PATH,
                             NULL, NULL, NULL, NULL, NULL);
    Check("CreateService", Service != NULL, "handle=%p gle=%lu", Service, GetLastError());
    if (!Service)
        goto done;

    Check("StartService", StartServiceW(Service, 0, NULL), "gle=%lu", GetLastError());

    StatusProcess.dwCurrentState = 0;
    QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO, (LPBYTE)&StatusProcess,
                         sizeof(StatusProcess), &Needed);
    Check("QueryServiceStatusEx", StatusProcess.dwCurrentState == SERVICE_RUNNING,
          "state=%lu (4 = SERVICE_RUNNING)", StatusProcess.dwCurrentState);

    Reopened = OpenServiceW(Manager, SERVICE_NAME, SERVICE_ALL_ACCESS);
    Check("OpenService", Reopened != NULL, "handle=%p", Reopened);
    if (Reopened)
        CloseServiceHandle(Reopened);

    RunDeviceBattery(TRUE);

cleanup:
    Check("ControlService(STOP)",
          ControlService(Service, SERVICE_CONTROL_STOP, &Status) &&
          Status.dwCurrentState == SERVICE_STOPPED,
          "state=%lu (1 = SERVICE_STOPPED)", Status.dwCurrentState);
    Check("DeleteService", DeleteService(Service), NULL);
    CloseServiceHandle(Service);
    CloseServiceHandle(Manager);

done:
    printf("\nRESULT: %s\n", g_Failures ? "FAIL" : "PASS");
    fflush(stdout);
    return g_Failures ? 1 : 0;
}
