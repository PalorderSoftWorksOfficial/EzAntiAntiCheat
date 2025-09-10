/**
 * @file ObCallbacks.cpp
 * @brief Implements object callbacks to protect anti-cheat processes.
 */

// Undefine common macros that might conflict.
#ifdef Enabled
#undef Enabled
#endif

#ifdef Reserved
#undef Reserved
#endif

#ifdef Version
#undef Version
#endif

#ifdef Size
#undef Size
#endif

#include <wdm.h>
#include "DriverDefs.h"

/**
 * @var g_ProtectedProcesses
 * @brief A list of process names to protect from handle creation.
 */
static const char* const g_ProtectedProcesses[] = {
    "EasyAntiCheat.exe", "rbxhyperion.exe", "vgk.exe", "Vanguard.exe"
};

/**
 * @var g_CallbackHandle
 * @brief A handle to the registered object callback.
 */
PVOID g_CallbackHandle = nullptr;

/**
 * @brief Checks if a process is a whitelisted anti-cheat process.
 *
 * This function checks the image name of a process to see if it is on the
 * list of protected processes.
 *
 * @param Process A pointer to the EPROCESS object.
 * @return TRUE if the process is whitelisted, FALSE otherwise.
 */
BOOLEAN IsWhitelistedAntiCheatProcess(PEPROCESS Process)
{
    UCHAR* imageName = PsGetProcessImageFileName(Process);
    if (!imageName) return FALSE;

    for (size_t i = 0; i < ARRAYSIZE(g_ProtectedProcesses); ++i)
    {
        if (_stricmp((const char*)imageName, g_ProtectedProcesses[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

/**
 * @brief The pre-operation callback for process handle creation.
 *
 * This function is called by the system before a handle to a process is
 * created. It checks if the target process is a protected anti-cheat process
 * and, if so, blocks the handle creation by zeroing out the desired access.
 *
 * @param RegistrationContext The context supplied during callback registration.
 * @param Info A pointer to a structure containing information about the
 * operation.
 * @return OB_PREOP_SUCCESS to allow the operation to continue (with modified
 * parameters), or an appropriate status code to block the operation.
 */
OB_PREOP_CALLBACK_STATUS PreOpCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Info->ObjectType == *PsProcessType)
    {
        if (IsWhitelistedAntiCheatProcess((PEPROCESS)Info->Object))
        {
            // Block handle creation by zeroing desired access
            Info->Parameters->CreateHandleInformation.DesiredAccess = 0;
            Info->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0;
            // No HandleAttributes member in this struct
        }
    }
    return OB_PREOP_SUCCESS;
}

/**
 * @brief Registers the object callbacks.
 *
 * This function registers the pre-operation callback for process handle
 * creation.
 */
extern "C" void RegisterObCallbacks()
{
    OB_OPERATION_REGISTRATION opReg = {};
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = PreOpCallback;
    opReg.PostOperation = nullptr; // Not needed

    OB_CALLBACK_REGISTRATION cbReg = {};
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistration = &opReg;
    cbReg.OperationRegistrationCount = 1;
    cbReg.RegistrationContext = nullptr;

    NTSTATUS status = ObRegisterCallbacks(&cbReg, &g_CallbackHandle);
    if (!NT_SUCCESS(status))
    {
        g_CallbackHandle = nullptr;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[EzAntiAntiCheatDriver] ObRegisterCallbacks failed: 0x%X\n", status);
    }
}

/**
 * @brief Unregisters the object callbacks.
 *
 * This function unregisters the object callbacks that were previously
 * registered.
 */
extern "C" void UnregisterObCallbacks()
{
    PVOID handle = (PVOID)InterlockedExchangePointer(&g_CallbackHandle, nullptr);
    if (handle)
    {
        ObUnRegisterCallbacks(handle);
    }
}
