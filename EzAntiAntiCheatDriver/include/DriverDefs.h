#pragma once
#include <wdm.h>
// ==================== Build-time protected EAC executable ====================
#if defined(_M_ARM64)
#ifdef _DEBUG
#define PROTECTED_EAC_EXE "EzAntiAntiCheat-arm64-Debug.exe"
#else
#define PROTECTED_EAC_EXE "EzAntiAntiCheat-arm64-Release.exe"
#endif
#elif defined(_M_X64) || defined(_WIN64)
#ifdef _DEBUG
#define PROTECTED_EAC_EXE "EzAntiAntiCheat-x64-Debug.exe"
#else
#define PROTECTED_EAC_EXE "EzAntiAntiCheat-x64-Release.exe"
#endif
#elif defined(_M_IX86)
#ifdef _DEBUG
#define PROTECTED_EAC_EXE "EzAntiAntiCheat-x86-Debug.exe"
#else
#define PROTECTED_EAC_EXE "EzAntiAntiCheat-x86-Release.exe"
#endif
#else
#error Unsupported architecture
#endif
#define IOCTL_ENABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
// PLEASE DO NOT CHANGE THESE BUGCHECK CODE DEFINITIONS AS THEY ALL USED AND MUST STAY CONSISTENT AS THEY ARE

// Critical Kernel Errors
#define KERNEL_SECURITY_CHECK_FAILURE_Win_env    0x139  // Kernel detected corruption in critical data structures
#define CRITICAL_STRUCTURE_CORRUPTION_Win_env    0x109  // Kernel detected corruption in critical data structures

// Memory Management Errors
#define MEMORY_MANAGEMENT_Win_env                0x1A   // Memory management error
#define PFN_LIST_CORRUPT_Win_env                 0x4E   // Page Frame Number list is corrupt
#define NO_SPIN_LOCK_AVAILABLE_Win_env           0x1D   // No spin lock is available

// File System Errors
#define FILE_SYSTEM_Win_env                      0x22   // File system error
#define FAT_FILE_SYSTEM_Win_env                  0x23   // FAT file system error
#define NTFS_FILE_SYSTEM_Win_env                 0x24   // NTFS file system error
#define CDFS_FILE_SYSTEM_Win_env                 0x26   // CDFS file system error
#define RDR_FILE_SYSTEM_Win_env                  0x27   // RDR file system error

// Driver Errors
#define DRIVER_VERIFIER_DETECTED_VIOLATION_Win_env 0xE6  // Driver Verifier detected a violation
#define SCSI_VERIFIER_DETECTED_VIOLATION_Win_env  0xF1  // SCSI Verifier detected a violation
#define DRIVER_OVERRAN_STACK_BUFFER_Win_env      0xF7   // Driver overran a stack buffer

// Hardware Errors
#define WHEA_UNCORRECTABLE_ERROR_Win_env         0x124  // Windows Hardware Error Architecture error
#define WHEA_INTERNAL_ERROR_Win_env              0x122  // WHEA internal error
#define RECURSIVE_NMI_Win_env                    0x111  // Non-maskable interrupt occurred while another was in progress

// Miscellaneous Errors
#define SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_Win_env 0x7E // System thread generated an exception not handled
#define UNEXPECTED_KERNEL_MODE_TRAP_Win_env      0x7F   // Unexpected kernel mode trap
#define THREAD_STUCK_IN_DEVICE_DRIVER_Win_env    0xEA   // Thread stuck in device driver
#define CRITICAL_PROCESS_DIED_Win_env            0xEF   // Critical system process died
#define UNMOUNTABLE_BOOT_VOLUME_Win_env          0xED   // Unmountable boot volume
#define KMODE_EXCEPTION_NOT_HANDLED_Win_env      0x1E   // KMODE exception not handled
#define STATUS_CANNOT_LOAD_REGISTRY_FILE_Win_env 0xC0000218 // Cannot load registry file
#define STATUS_SYSTEM_PROCESS_TERMINATED_Win_env 0xC000021A // System process terminated

#define MAX_ERROR_LOGS 128
#define MAX_ERROR_LENGTH 1024

extern CHAR g_ErrorLogBuffer[MAX_ERROR_LOGS][MAX_ERROR_LENGTH];
extern LONG g_ErrorLogIndex;

void SetLastErrorLog(const char* format, ...);
#ifdef __cplusplus
extern "C" {
#endif

    extern UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

    extern volatile LONG g_IntegrityOk;
    extern PVOID g_DriverBase;
    extern SIZE_T g_DriverSize;
    extern ULONG g_ExpectedCrc;
    extern HANDLE g_IntegrityThreadHandle;
    extern char g_LastErrorLog[256];

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
        if (_stricmp((const char*)imageName, PROTECTED_EAC_EXE) == 0)
            return TRUE;
    return FALSE;
}
