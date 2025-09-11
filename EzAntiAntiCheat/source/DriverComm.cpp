#include <windows.h>
#include <iostream>
#include "../include/ControllerDefs.h"
#include "IoctlDefs.h"
// IF YOU WANT TO MAKE A FUCKING CMAKE VERSION IT WONT WORK AS THE WHOLE FUCKING PROJECT NEEDS MVSC COMPILER MACROS, DONT TRY IT ASSHOLE.
// ==================== Build-time device name ====================
#if defined(_M_ARM64)
#ifdef _DEBUG
#define DEVICE_NAME L"\\\\.\\EzAntiAntiCheat-arm64-Debug.exe"
#else
#define DEVICE_NAME L"\\\\.\\EzAntiAntiCheat-arm64-Release.exe"
#endif

#elif defined(_M_X64) || defined(_WIN64)
#ifdef _DEBUG
#define DEVICE_NAME L"\\\\.\\EzAntiAntiCheat-x64-Debug.exe"
#else
#define DEVICE_NAME L"\\\\.\\EzAntiAntiCheat-x64-Release.exe"
#endif

#elif defined(_M_IX86)
#ifdef _DEBUG
#define DEVICE_NAME L"\\\\.\\EzAntiAntiCheat-x86-Debug.exe"
#else
#define DEVICE_NAME L"\\\\.\\EzAntiAntiCheat-x86-Release.exe"
#endif

#else
#error Unsupported architecture
#endif

bool SendIoctl(DWORD ioctl, void* inBuf, DWORD inBufSize)
{
    HANDLE hDevice = CreateFileW(
        DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to open driver device: " << GetLastError() << "\n";
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        hDevice,
        ioctl,
        inBuf,
        inBufSize,
        nullptr,
        0,
        &bytesReturned,
        nullptr
    );

    CloseHandle(hDevice);
    return ok != FALSE;
}
