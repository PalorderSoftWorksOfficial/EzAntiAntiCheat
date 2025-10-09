#include <ntifs.h>
#include <ntstrsafe.h>
#include "../include/DriverDefs.h"
#include "IoctlDefs.h"
#define DRIVER_TAG 'EzAntiAntiCheat'
NTSTATUS TerminateProcessById(HANDLE pid);

// ==================== Build-time EXE + symlink names ====================
#if defined(_M_ARM64)
#ifdef _DEBUG
#define PROTECTED_EXE_NAME   "EzAntiAntiCheat-arm64-Debug.exe"
#define SYM_LINK_LITERAL     L"\\DosDevices\\EzAntiAntiCheat-arm64-Debug.exe"
#else
#define PROTECTED_EXE_NAME   "EzAntiAntiCheat-arm64-Release.exe"
#define SYM_LINK_LITERAL     L"\\DosDevices\\EzAntiAntiCheat-arm64-Release.exe"
#endif

#elif defined(_M_X64) || defined(_WIN64)
#ifdef _DEBUG
#define PROTECTED_EXE_NAME_LONG L"EzAntiAntiCheat-x64-Debug.exe"
#define PROTECTED_EXE_NAME   "EzAntiAntiCheat-x64-Debug.exe"
#define SYM_LINK_LITERAL     L"\\DosDevices\\EzAntiAntiCheat-x64-Debug.exe"
#else
#define PROTECTED_EXE_NAME_LONG L"EzAntiAntiCheat-x64-Release.exe"
#define PROTECTED_EXE_NAME   "EzAntiAntiCheat-x64-Release.exe"
#define SYM_LINK_LITERAL     L"\\DosDevices\\EzAntiAntiCheat-x64-Release.exe"
#endif

#elif defined(_M_IX86)
#ifdef _DEBUG
#define PROTECTED_EXE_NAME_LONG   L"EzAntiAntiCheat-x86-Debug.exe"
#define PROTECTED_EXE_NAME   "EzAntiAntiCheat-x86-Debug.exe"
#define SYM_LINK_LITERAL     L"\\DosDevices\\EzAntiAntiCheat-x86-Debug.exe"
#else
#define PROTECTED_EXE_NAME_LONG   L"EzAntiAntiCheat-x86-Release.exe"
#define PROTECTED_EXE_NAME   "EzAntiAntiCheat-x86-Release.exe"
#define SYM_LINK_LITERAL     L"\\DosDevices\\EzAntiAntiCheat-x86-Release.exe"
#endif

#else
#error Unsupported architecture
#endif
// OH NO ME HEART STOP LULAOWEJGAWPGJOEJRHJAEIORHAORHSH IM FUCKING DIEING
// i almost got an heart attack from this as its hardcoded shit that is uh broken
UNICODE_STRING g_SymLinkName = RTL_CONSTANT_STRING(SYM_LINK_LITERAL);
const char* g_ProtectedProcessNameA = PROTECTED_EXE_NAME;

// ==================== Global state ====================
static volatile LONG g_ProtectionEnabled = 0;
PDEVICE_OBJECT g_DeviceObject = nullptr;

// ==================== Helpers ====================
BOOLEAN IsCallerSystem()
{
    PEPROCESS caller = PsGetCurrentProcess();
    UCHAR* imageName = PsGetProcessImageFileName(caller);
    if (!imageName) return FALSE;

    if (_stricmp((const char*)imageName, "System") == 0)
        return TRUE;

    if (_stricmp((const char*)imageName, g_ProtectedProcessNameA) == 0)
        return TRUE;

    return FALSE;
}

NTSTATUS RemoveCriticalFlag(PEPROCESS Process)
{
    __try {
        PUCHAR criticalFlag = (PUCHAR)Process + 0x2e0; // verify offset!
        *criticalFlag = 0;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[EzAntiAntiCheatDriver] Critical flag removed\n");
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[EzAntiAntiCheatDriver] Failed to remove critical flag\n");
        return STATUS_UNSUCCESSFUL;
    }
}

BOOLEAN IsSafeToTerminate(HANDLE pid)
{
    if (pid == (HANDLE)0 || pid == (HANDLE)4)
        return FALSE;

    PEPROCESS process;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return FALSE;

    UCHAR* imageName = PsGetProcessImageFileName(process);
    if (imageName && (_stricmp((const char*)imageName, "System") == 0 ||
        _stricmp((const char*)imageName, "csrss.exe") == 0 ||
        _stricmp((const char*)imageName, "wininit.exe") == 0 ||
        _stricmp((const char*)imageName, "winlogon.exe") == 0))
    {
        ObDereferenceObject(process);
        return FALSE;
    }

    ObDereferenceObject(process);
    return TRUE;
}

// ==================== Image load notification ====================
extern "C" VOID ImageLoadNotify(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ProcessId);
    if (!InterlockedCompareExchange(&g_ProtectionEnabled, 0, 0))
        return;

    if (ImageName && ImageName->Buffer)
    {
        if (wcsstr(ImageName->Buffer, L"rbxhyperion.sys") ||
            wcsstr(ImageName->Buffer, L"EasyAntiCheat.sys") ||
            wcsstr(ImageName->Buffer, L"vgk.sys") ||
            wcsstr(ImageName->Buffer, L"Vanguard"))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[EzAntiAntiCheatDriver] Blocking driver: %wZ\n", ImageName);

            ImageInfo->ImageBase = nullptr;
            ImageInfo->ImageSize = 0;
        }
    }
}

extern "C" NTSTATUS RegisterImageLoadNotify() { return PsSetLoadImageNotifyRoutine(ImageLoadNotify); }
extern "C" NTSTATUS UnregisterImageLoadNotify() { return PsRemoveLoadImageNotifyRoutine(ImageLoadNotify); }

// ==================== IRP handlers ====================
NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    ULONG pid = 0; // Declare here, before switch

    // Access control: Only allow SYSTEM or protected process
    if (!IsCallerSystem())
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[EzAntiAntiCheatDriver] Unauthorized IOCTL caller\n");
        status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = info;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_ENABLE_PROTECTION:
        if (stack->Parameters.DeviceIoControl.InputBufferLength != 0 ||
            stack->Parameters.DeviceIoControl.OutputBufferLength != 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        InterlockedExchange(&g_ProtectionEnabled, 1);
        status = STATUS_SUCCESS;
        break;

    case IOCTL_DISABLE_PROTECTION:
        if (stack->Parameters.DeviceIoControl.InputBufferLength != 0 ||
            stack->Parameters.DeviceIoControl.OutputBufferLength != 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        InterlockedExchange(&g_ProtectionEnabled, 0);
        status = STATUS_SUCCESS;
        break;

    case IOCTL_KILL_AND_WIPE_PROCESS:
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        pid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;
        // Validate PID: must not be system/critical
        if (!IsSafeToTerminate((HANDLE)pid))
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        status = TerminateProcessById((HANDLE)pid);
        break;
    case IOCTL_GET_LAST_ERROR_LOG:
        if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(g_LastErrorLog)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, g_LastErrorLog, sizeof(g_LastErrorLog));
        Irp->IoStatus.Information = sizeof(g_LastErrorLog);
        status = STATUS_SUCCESS;
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS TerminateProcessById(HANDLE pid)
{
    if (!IsSafeToTerminate(pid))
        return STATUS_ACCESS_DENIED;

    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) return status;

    RemoveCriticalFlag(process);
    status = ZwTerminateProcess(process, STATUS_SUCCESS);
    ObDereferenceObject(process);
    return status;
}

// ==================== Driver unload ====================
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UnregisterImageLoadNotify();
    IoDeleteSymbolicLink(&g_SymLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[EzAntiAntiCheatDriver] Unloaded\n");
}

// ==================== Driver entry ====================
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(PROTECTED_EXE_NAME_LONG);
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&g_SymLinkName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    status = RegisterImageLoadNotify();
    if (!NT_SUCCESS(status))
    {
        IoDeleteSymbolicLink(&g_SymLinkName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    InterlockedExchange(&g_ProtectionEnabled, 0);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[EzAntiAntiCheatDriver] Loaded successfully (symlink: %wZ)\n", &g_SymLinkName);

    return STATUS_SUCCESS;
}