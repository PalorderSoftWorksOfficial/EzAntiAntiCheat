/**
 * @file DriverComm.cpp
 * @brief Implements communication with the driver.
 */

#include <windows.h>
#include <iostream>
#include "ControllerDefs.h"
#include "IoctlDefs.h"

/**
 * @brief Sends an IOCTL to the driver.
 *
 * This function opens a handle to the driver's device object and sends the
 * specified IOCTL code with the given input buffer.
 *
 * @param ioctl The IOCTL code to send.
 * @param inBuf A pointer to the input buffer.
 * @param inBufSize The size of the input buffer, in bytes.
 * @return true if the IOCTL was sent successfully, false otherwise.
 */
bool SendIoctl(DWORD ioctl, void* inBuf, DWORD inBufSize)
{
    // Use the symbolic link defined in ControllerDefs.h
    HANDLE hDevice = CreateFileW(DRIVER_SYMBOLIC_LINK, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
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
