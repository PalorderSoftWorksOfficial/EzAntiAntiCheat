#include <windows.h>
#include <iostream>
#include "ControllerDefs.h"
#include "IoctlDefs.h"

bool SendIoctl(DWORD ioctl, void* inBuf, DWORD inBufSize)
{
    HANDLE hDevice = CreateFileW(L"\\\\.\\EasyAntiAntiCheat", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to open driver device\n";
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
