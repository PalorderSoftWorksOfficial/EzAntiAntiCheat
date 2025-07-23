#pragma once
#include <wdm.h>

#define MY_BUGCHECK_CODE 0x139
#define IOCTL_ENABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#ifdef __cplusplus
extern "C" {
#endif

    extern UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

    extern volatile LONG g_IntegrityOk;
    extern PVOID g_DriverBase;
    extern SIZE_T g_DriverSize;
    extern ULONG g_ExpectedCrc;
    extern HANDLE g_IntegrityThreadHandle;

    BOOLEAN IsManagerProcess();

    ULONG Crc32(const void* data, SIZE_T length);

    VOID InitializeIntegrityCheck(PVOID base, SIZE_T size);

    NTSTATUS StartIntegrityThread();

    VOID StopIntegrityThread();

    VOID IntegrityThread(_In_ PVOID StartContext);

#ifdef __cplusplus
}
#endif

inline BOOLEAN IsProtectedProcess(PEPROCESS Process)
{
    if (!Process) return FALSE;
    UCHAR* imageName = PsGetProcessImageFileName(Process);
    if (imageName)
        if (_stricmp((const char*)imageName, "ShieldController.exe") == 0)
            return TRUE;
    return FALSE;
}
