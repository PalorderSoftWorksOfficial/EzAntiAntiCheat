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
#include "../include/DriverDefs.h"

// Whitelist of protected anti-cheat process names
static const char* const g_ProtectedProcesses[] = {
    "EasyAntiCheat.exe", "rbxhyperion.exe", "vgk.exe", "Vanguard.exe"
};

PVOID g_CallbackHandle = nullptr;

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

OB_PREOP_CALLBACK_STATUS PreOpCallback(PVOID, POB_PRE_OPERATION_INFORMATION Info)
{
    if (Info->ObjectType == *PsProcessType)
    {
        if (IsWhitelistedAntiCheatProcess((PEPROCESS)Info->Object))
        {
            // Remove all desired access to prevent handle creation
            Info->Parameters->CreateHandleInformation.DesiredAccess = 0;
            return OB_PREOP_SUCCESS;
        }
    }
    return OB_PREOP_SUCCESS;
}

extern "C" void RegisterObCallbacks()
{
    OB_OPERATION_REGISTRATION opReg = {};
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE;
    opReg.PreOperation = PreOpCallback;

    OB_CALLBACK_REGISTRATION cbReg = {};
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistration = &opReg;
    cbReg.OperationRegistrationCount = 1;

    NTSTATUS status = ObRegisterCallbacks(&cbReg, &g_CallbackHandle);
    if (!NT_SUCCESS(status))
    {
        g_CallbackHandle = nullptr;
    }
}

extern "C" void UnregisterObCallbacks()
{
    if (g_CallbackHandle)
    {
        ObUnRegisterCallbacks(g_CallbackHandle);
        g_CallbackHandle = nullptr;
    }
}
