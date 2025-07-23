#include <windows.h>
#include <iostream>
#include <string>

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

#include "ControllerDefs.h"

// Globals
extern "C" bool g_ServiceInstalled = false;
extern "C" SC_HANDLE g_hService = nullptr;
extern "C" SC_HANDLE g_hSCManager = nullptr;

const std::wstring DRIVER_FILE_NAME = L"EzAntiAntiCheatDriver.sys";

bool CopyDriverToSystemDrivers()
{
    wchar_t systemDir[MAX_PATH];
    if (!GetSystemDirectoryW(systemDir, MAX_PATH))
    {
        std::cout << "GetSystemDirectory failed: " << GetLastError() << "\n";
        return false;
    }

    std::wstring targetPath = std::wstring(systemDir) + L"\\drivers\\" + DRIVER_FILE_NAME;
    if (!CopyFileW(DRIVER_FILE_NAME.c_str(), targetPath.c_str(), FALSE))
    {
        DWORD err = GetLastError();
        if (err != ERROR_FILE_EXISTS)
        {
            std::wcout << L"Failed to copy driver to System32\\drivers: " << err << "\n";
            return false;
        }
    }

    std::wcout << L"Driver copied to: " << targetPath << "\n";
    return true;
}
bool InstallService()
{
    g_hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!g_hSCManager)
    {
        std::cout << "OpenSCManager failed: " << GetLastError() << "\n";
        return false;
    }

    g_hService = OpenService(
        g_hSCManager,
        DRIVER_SERVICE_NAME,
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP
    );

    if (!g_hService)
    {
        // Service does not exist, create it
        if (!CopyDriverToSystemDrivers())
        {
            std::cout << "Failed to prepare driver\n";
            CloseServiceHandle(g_hSCManager);
            return false;
        }

        std::wstring systemDriverPath = L"\\SystemRoot\\System32\\drivers\\EzAntiAntiCheatDriver.sys";

        g_hService = CreateService(
            g_hSCManager,
            DRIVER_SERVICE_NAME,
            DRIVER_SERVICE_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            systemDriverPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr
        );

        if (!g_hService)
        {
            std::cout << "CreateService failed: " << GetLastError() << "\n";
            CloseServiceHandle(g_hSCManager);
            g_hSCManager = nullptr;
            return false;
        }

        std::cout << "Service created successfully\n";
    }
    else
    {
        std::cout << "Service already exists\n";
    }

    bool started = StartService(g_hService, 0, nullptr);
    if (!started)
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
        {
            std::cout << "Service already running\n";
        }
        else
        {
            std::cout << "StartService failed: " << err << "\n";
            CloseServiceHandle(g_hService);
            CloseServiceHandle(g_hSCManager);
            g_hService = nullptr;
            g_hSCManager = nullptr;
            return false;
        }
    }
    else
    {
        std::cout << "Service started successfully\n";
    }

    g_ServiceInstalled = true; // 💥 Always set true here
    return true;
}

bool LoadDriver()
{
    if (!g_hService)
    {
        std::cout << "Service handle invalid\n";
        return false;
    }

    SERVICE_STATUS status;
    if (!ControlService(g_hService, SERVICE_CONTROL_STOP, &status))
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_NOT_ACTIVE)
        {
            std::cout << "Failed to stop service before loading: " << err << "\n";
            return false;
        }
    }

    if (!StartService(g_hService, 0, nullptr))
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING)
        {
            std::cout << "Failed to start service: " << err << "\n";
            return false;
        }
    }

    std::cout << "Driver loaded successfully\n";
    return true;
}

bool UnloadDriver()
{
    if (!g_hService)
    {
        std::cout << "Service handle invalid\n";
        return false;
    }

    SERVICE_STATUS status;
    if (!ControlService(g_hService, SERVICE_CONTROL_STOP, &status))
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_NOT_ACTIVE)
        {
            std::cout << "Failed to stop service: " << err << "\n";
            return false;
        }
    }
    else
    {
        std::cout << "Service stopped successfully\n";
    }

    if (!DeleteService(g_hService))
    {
        DWORD err = GetLastError();
        std::cout << "Failed to delete service: " << err << "\n";
        return false;
    }

    std::cout << "Service deleted successfully\n";

    CloseServiceHandle(g_hService);
    g_hService = nullptr;

    if (g_hSCManager)
    {
        CloseServiceHandle(g_hSCManager);
        g_hSCManager = nullptr;
    }

    return true;
}
