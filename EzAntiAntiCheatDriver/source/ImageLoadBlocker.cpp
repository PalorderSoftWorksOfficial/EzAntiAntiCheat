#include <ntifs.h>
#include <ntstrsafe.h>
#include "../include/DriverDefs.h"
#include "../include/IoctlDefs.h"

#define DRIVER_TAG 'shLD'
NTSTATUS TerminateProcessById(HANDLE pid);
// Global state
static volatile LONG g_ProtectionEnabled = 0;

// Device and symbolic link names
PDEVICE_OBJECT g_DeviceObject = nullptr;
UNICODE_STRING g_SymLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\EasyAntiAntiCheat.exe");

// Helper: Check if caller is SYSTEM or trusted process
BOOLEAN IsCallerSystem()
{
    PEPROCESS caller = PsGetCurrentProcess();
    UCHAR* imageName = PsGetProcessImageFileName(caller);
    if (imageName && _stricmp((const char*)imageName, "System") == 0)
        return TRUE;
    if (imageName && _stricmp((const char*)imageName, "EasyAntiAntiCheat.exe") == 0)
        return TRUE;
    return FALSE;
}

// Helper: Remove critical flag from EPROCESS
NTSTATUS RemoveCriticalFlag(PEPROCESS Process)
{
    // Windows 10/11: EPROCESS + 0x2e0 is usually the critical flag (verify for your target build!)
    __try {
        PUCHAR criticalFlag = (PUCHAR)Process + 0x2e0; // Verify offset for your target build!
        *criticalFlag = 0;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[EzAntiAntiCheatDriver] Critical flag removed from process\n");
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] Failed to remove critical flag\n");
        return STATUS_UNSUCCESSFUL;
    }
}

// Helper: Check if PID is safe to terminate
BOOLEAN IsSafeToTerminate(HANDLE pid)
{
    if (pid == (HANDLE)0 || pid == (HANDLE)4) // System Idle or System process
        return FALSE;
    PEPROCESS process;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return FALSE;
    UCHAR* imageName = PsGetProcessImageFileName(process);
    if (imageName && (
        _stricmp((const char*)imageName, "System") == 0 ||
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

// Helper: Check for suspicious anti-tamper activity
BOOLEAN IsAntiCheatTamperingDetected()
{
    const wchar_t* services[] = { L"EasyAntiCheat", L"rbxhyperion", L"vgk", L"Vanguard"};
    for (int i = 0; i < ARRAYSIZE(services); ++i)
    {
        WCHAR fullPath[256];
        UNICODE_STRING regPath;
        OBJECT_ATTRIBUTES objAttr;
        HANDLE keyHandle = NULL;

        RtlStringCchPrintfW(fullPath, 256, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%ws", services[i]);
        RtlInitUnicodeString(&regPath, fullPath);
        InitializeObjectAttributes(&objAttr, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        if (NT_SUCCESS(ZwOpenKey(&keyHandle, KEY_READ, &objAttr))) {
            UNICODE_STRING valueName;
            RtlInitUnicodeString(&valueName, L"Start");
            UCHAR valueBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
            ULONG resultLength = 0;
            NTSTATUS status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, valueBuffer, sizeof(valueBuffer), &resultLength);
            if (NT_SUCCESS(status)) {
                KEY_VALUE_PARTIAL_INFORMATION* info = (KEY_VALUE_PARTIAL_INFORMATION*)valueBuffer;
                if (info->Type == REG_DWORD && *(ULONG*)info->Data == 4) { // 4 = Disabled
                    ZwClose(keyHandle);
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] %ws service disabled in registry\n", services[i]);
                    return TRUE;
                }
            }
            ZwClose(keyHandle);
        }
    }
    return FALSE;
}

// Helper: Delete stubborn driver service registry key as last resort
NTSTATUS DeleteDriverServiceRegistryKey(PCWSTR ServiceName)
{
    if (_wcsicmp(ServiceName, L"EasyAntiCheat") != 0 &&
        _wcsicmp(ServiceName, L"rbxhyperion") != 0 &&
        _wcsicmp(ServiceName, L"vgk") != 0 &&
        _wcsicmp(ServiceName, L"Vanguard") != 0)
        return STATUS_ACCESS_DENIED;

    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING regPath;
    HANDLE keyHandle;

    WCHAR fullPath[256];
    RtlStringCchPrintfW(fullPath, 256, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%ws", ServiceName);

    RtlInitUnicodeString(&regPath, fullPath);
    InitializeObjectAttributes(&objAttr, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&keyHandle, DELETE, &objAttr);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] Failed to open service registry key '%ws': 0x%X\n", ServiceName, status);
        return status;
    }

    status = ZwDeleteKey(keyHandle);
    ZwClose(keyHandle);

    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[EzAntiAntiCheatDriver] Service registry key '%ws' deleted\n", ServiceName);
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] Failed to delete service registry key '%ws': 0x%X\n", ServiceName, status);
    }

    return status;
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
        return;

    if (ImageName && ImageName->Buffer)
    {
        if (wcsstr(ImageName->Buffer, L"rbxhyperion.sys") != nullptr ||
            wcsstr(ImageName->Buffer, L"EasyAntiCheat.sys") != nullptr ||
            wcsstr(ImageName->Buffer, L"vgk.sys") != nullptr ||
            wcsstr(ImageName->Buffer, L"Vanguard") != nullptr)
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

    // SECURITY PATCH: Only allow SYSTEM or trusted process to send IOCTLs
    if (!IsCallerSystem())
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] Unauthorized IOCTL caller\n");
        status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = info;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

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

        PEPROCESS process;
        status = PsLookupProcessByProcessId((HANDLE)pid, &process);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] Invalid PID: %lu\n", pid);
            break;
        }

        UCHAR* imageName = PsGetProcessImageFileName(process);
        if (imageName && (
            _stricmp((const char*)imageName, "vgk.sys") == 0 ||
            _stricmp((const char*)imageName, "Vanguard") == 0))
        {
            // Riot Vanguard detected, perform robust removal
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] Riot Vanguard detected! Forcibly removing...\n");
            RemoveCriticalFlag(process);
            status = ZwTerminateProcess(process, STATUS_SUCCESS);
            DeleteDriverServiceRegistryKey(L"vgk");
            DeleteDriverServiceRegistryKey(L"Vanguard");
            // Optionally: Add file wipe logic here if needed
            ObDereferenceObject(process);
            break;
        }

        // Validate PID before acting
        if (!IsSafeToTerminate((HANDLE)pid)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] Unsafe PID requested: %lu\n", pid);
            ObDereferenceObject(process);
            status = STATUS_ACCESS_DENIED;
            break;
        }

        // Step 1: Check tampering
        if (IsAntiCheatTamperingDetected()) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] Tampering detected! Forcibly terminating anti-cheat.\n");
            TerminateProcessById((HANDLE)pid);
            ObDereferenceObject(process);
            status = STATUS_SUCCESS;
            break;
        }

        // Step 2: Remove critical flagB
        status = PsLookupProcessByProcessId((HANDLE)pid, &process);
        if (NT_SUCCESS(status)) {
            RemoveCriticalFlag(process);
            ObDereferenceObject(process);
        }

        // Step 3: Terminate process
        status = TerminateProcessById((HANDLE)pid);

        // Step 4: If termination failed, attempt deleting driver service registry keys as last resort
        if (!NT_SUCCESS(status)) {
            DeleteDriverServiceRegistryKey(L"EasyAntiCheat");
            DeleteDriverServiceRegistryKey(L"rbxhyperion");
			DeleteDriverServiceRegistryKey(L"vgk");
        }

        ObDereferenceObject(process);
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

// Helper: Terminate process by PID
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
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\EzAntiAntiCheatDriver");

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
