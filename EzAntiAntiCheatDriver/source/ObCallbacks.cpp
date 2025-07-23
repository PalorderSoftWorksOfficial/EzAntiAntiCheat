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

PVOID g_CallbackHandle = nullptr;

OB_PREOP_CALLBACK_STATUS PreOpCallback(PVOID, POB_PRE_OPERATION_INFORMATION Info)
{
    if (Info->ObjectType == *PsProcessType)
    {
        if (IsProtectedProcess((PEPROCESS)Info->Object))
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
