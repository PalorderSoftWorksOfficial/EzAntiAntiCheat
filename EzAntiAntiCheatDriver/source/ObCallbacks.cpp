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

// ==================== Whitelist of protected anti-cheat process names ====================
static const char* const g_ProtectedProcesses[] = {
    PROTECTED_EAC_EXE,
    "rbxhyperion.exe",
    "vgk.exe",
    "Vanguard.exe"
};

// ==================== Global callback handle ====================
PVOID g_CallbackHandle = nullptr;

// ==================== Helper: check if process is whitelisted ====================
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

// ==================== Pre-operation callback ====================
OB_PREOP_CALLBACK_STATUS PreOpCallback(PVOID, POB_PRE_OPERATION_INFORMATION Info)
{
    if (Info->ObjectType == *PsProcessType)
    {
        if (IsWhitelistedAntiCheatProcess((PEPROCESS)Info->Object))
        {
            // Block handle creation by zeroing desired access
            Info->Parameters->CreateHandleInformation.DesiredAccess = 0;
            Info->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0;
            // No HandleAttributes member in this struct, so don’t touch it
        }
    }
    return OB_PREOP_SUCCESS;
}

// ==================== Register OB callbacks ====================
extern "C" void RegisterObCallbacks()
{
    // Operation registration struct
    static OB_OPERATION_REGISTRATION opReg = {};
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = PreOpCallback;
    opReg.PostOperation = nullptr; // Not needed, we only care about pre-op

    // Callback registration struct
    static OB_CALLBACK_REGISTRATION cbReg = {};
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistration = &opReg;
    cbReg.OperationRegistrationCount = 1;
    cbReg.RegistrationContext = nullptr;

    NTSTATUS status = ObRegisterCallbacks(&cbReg, &g_CallbackHandle);
    if (!NT_SUCCESS(status))
    {
        g_CallbackHandle = nullptr;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[EzAntiAntiCheatDriver] ObRegisterCallbacks failed: 0x%X\n", status);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[EzAntiAntiCheatDriver] OB callbacks registered successfully\n");
    }
}

// ==================== Unregister OB callbacks ====================
extern "C" void UnregisterObCallbacks()
{
    PVOID handle = (PVOID)InterlockedExchangePointer(&g_CallbackHandle, nullptr);
    if (handle)
    {
        ObUnRegisterCallbacks(handle);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[EzAntiAntiCheatDriver] OB callbacks unregistered\n");
    }
}
