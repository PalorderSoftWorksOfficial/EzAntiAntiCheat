#include <ntifs.h>
#include "DriverDefs.h"
#include "IoctlDefs.h"

#define DRIVER_TAG 'shLD'

// Global state
static volatile LONG g_ProtectionEnabled = 0;

// Device and symbolic link names
PDEVICE_OBJECT g_DeviceObject = nullptr;
UNICODE_STRING g_SymLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\KernelShield");

// Helper: Remove critical flag from EPROCESS
NTSTATUS RemoveCriticalFlag(PEPROCESS Process)
{
    // Windows 10/11: EPROCESS + 0x2e0 is usually the critical flag (verify for your target build!)
    __try {
        PUCHAR criticalFlag = (PUCHAR)Process + 0x2e0;
        *criticalFlag = 0;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[EzAntiAntiCheatDriver] Critical flag removed from process\n");
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] Failed to remove critical flag\n");
        return STATUS_UNSUCCESSFUL;
    }
}

// Helper: Terminate process by PID
NTSTATUS TerminateProcessById(HANDLE pid)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) return status;

    RemoveCriticalFlag(process);

    // Terminate process
    status = ZwTerminateProcess(process, STATUS_SUCCESS);
    ObDereferenceObject(process);
    return status;
}

// Helper: Check for suspicious anti-tamper activity (stub, expand as needed)
BOOLEAN IsAntiCheatTamperingDetected()
{
    // TODO: Implement real detection (e.g., scan for suspicious memory writes, registry changes, etc.)
    // For now, always return FALSE
    return FALSE;
}

// Helper: Validate anti-cheat PID (stub, expand as needed)
HANDLE GetAntiCheatPid()
{
    // TODO: Implement actual PID lookup for anti-cheat process
    // For now, return an invalid PID
    return nullptr;
}

// Image load callback
extern "C" VOID ImageLoadNotify(
    PUNICODE_STRING ImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(ProcessId);
    if (!InterlockedCompareExchange(&g_ProtectionEnabled, 0, 0))
        return; // Protection disabled

    if (ImageName && ImageName->Buffer)
    {
        if (wcsstr(ImageName->Buffer, L"rbxhyperion.sys") != nullptr ||
            wcsstr(ImageName->Buffer, L"EasyAntiCheat.sys") != nullptr)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[EzAntiAntiCheatDriver] Blocking driver: %wZ\n", ImageName);

            // Block the driver from loading
            ImageInfo->ImageBase = nullptr;
            ImageInfo->ImageSize = 0;
        }
    }
}

extern "C" NTSTATUS RegisterImageLoadNotify()
{
    return PsSetLoadImageNotifyRoutine(ImageLoadNotify);
}

extern "C" NTSTATUS UnregisterImageLoadNotify()
{
    return PsRemoveLoadImageNotifyRoutine(ImageLoadNotify);
}

// Create/Close handler
NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// DeviceControl handler
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_ENABLE_PROTECTION:
        InterlockedExchange(&g_ProtectionEnabled, 1);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[EzAntiAntiCheatDriver] Protection ENABLED\n");
        status = STATUS_SUCCESS;
        break;

    case IOCTL_DISABLE_PROTECTION:
        InterlockedExchange(&g_ProtectionEnabled, 0);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[EzAntiAntiCheatDriver] Protection DISABLED\n");
        status = STATUS_SUCCESS;
        break;

    case IOCTL_KILL_AND_WIPE_PROCESS:
    {
        // Validate input buffer size
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        ULONG pid = *(ULONG*)Irp->AssociatedIrp.SystemBuffer;

        // Step 1: Check for tampering (expand IsAntiCheatTamperingDetected as needed)
        if (IsAntiCheatTamperingDetected()) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] Tampering detected! Forcibly terminating anti-cheat.\n");
            TerminateProcessById((HANDLE)pid);
            status = STATUS_SUCCESS;
            break;
        }

        // Step 2: Remove critical flag
        PEPROCESS process;
        status = PsLookupProcessByProcessId((HANDLE)pid, &process);
        if (NT_SUCCESS(status)) {
            RemoveCriticalFlag(process);
            ObDereferenceObject(process);
        }

        // Step 3: Terminate process
        status = TerminateProcessById((HANDLE)pid);

        // Step 4: (Optional) Wipe file in user-mode after process is killed

        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Unload routine
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UnregisterImageLoadNotify();
    IoDeleteSymbolicLink(&g_SymLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[EzAntiAntiCheatDriver] Unloaded\n");
}

// Entry point
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\KernelShield");

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymLinkName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] IoCreateSymbolicLink failed: 0x%X\n", status);
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] PsSetLoadImageNotifyRoutine failed: 0x%X\n", status);
        IoDeleteSymbolicLink(&g_SymLinkName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[EzAntiAntiCheatDriver] Loaded successfully\n");

    InterlockedExchange(&g_ProtectionEnabled, 0);
    return STATUS_SUCCESS;
}
