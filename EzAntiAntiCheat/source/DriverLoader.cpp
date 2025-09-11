#include <windows.h>
#include <iostream>
#include <string>
#include <strsafe.h>

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

#include "../include/ControllerDefs.h"

// Globals
extern "C" bool g_ServiceInstalled = false;
extern "C" SC_HANDLE g_hService = nullptr;
extern "C" SC_HANDLE g_hSCManager = nullptr;

#if defined(_M_ARM64)
#ifdef _DEBUG
const std::wstring DRIVER_FILE_NAME = L"EzAntiAntiCheatDriver-arm64-Debug.sys";
#else
const std::wstring DRIVER_FILE_NAME = L"EzAntiAntiCheatDriver-arm64-Release.sys";
#endif

#elif defined(_M_X64) || defined(_WIN64)
#ifdef _DEBUG
const std::wstring DRIVER_FILE_NAME = L"EzAntiAntiCheatDriver-x64-Debug.sys";
#else
const std::wstring DRIVER_FILE_NAME = L"EzAntiAntiCheatDriver-x64-Release.sys";
#endif

#elif defined(_M_IX86)
#ifdef _DEBUG
const std::wstring DRIVER_FILE_NAME = L"EzAntiAntiCheatDriver-x86-Debug.sys";
#else
const std::wstring DRIVER_FILE_NAME = L"EzAntiAntiCheatDriver-x86-Release.sys";
#endif

#else
#error Unsupported architecture
#endif
#if defined(_M_ARM64)
#ifdef _DEBUG
std::wstring systemDriverPath = L"\\SystemRoot\\System32\\drivers\\EzAntiAntiCheatDriver-arm64-Debug.sys";
#else
std::wstring systemDriverPath = L"\\SystemRoot\\System32\\drivers\\EzAntiAntiCheatDriver-arm64-Release.sys";
#endif

#elif defined(_M_X64) || defined(_WIN64)
#ifdef _DEBUG
std::wstring systemDriverPath = L"\\SystemRoot\\System32\\drivers\\EzAntiAntiCheatDriver-x64-Debug.sys";
#else
std::wstring systemDriverPath = L"\\SystemRoot\\System32\\drivers\\EzAntiAntiCheatDriver-x64-Release.sys";
#endif

#elif defined(_M_IX86)
#ifdef _DEBUG
std::wstring systemDriverPath = L"\\SystemRoot\\System32\\drivers\\EzAntiAntiCheatDriver-x86-Debug.sys";
#else
std::wstring systemDriverPath = L"\\SystemRoot\\System32\\drivers\\EzAntiAntiCheatDriver-x86-Release.sys";
#endif

#else
#error Unsupported architecture
#endif
// this is needed otherwise the shit will get an heartattack

// Check if a service is running
bool IsServiceRunning(SC_HANDLE service)
{
    SERVICE_STATUS_PROCESS ssp = { 0 };
    DWORD bytesNeeded = 0;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
    {
        return (ssp.dwCurrentState == SERVICE_RUNNING);
    }
    return false;
}

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

    g_hService = OpenService(g_hSCManager, DRIVER_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!g_hService)
    {
        // Service does not exist, create it :3
        if (!CopyDriverToSystemDrivers())
        {
            std::cout << "Failed to prepare driver\n";
            CloseServiceHandle(g_hSCManager);
            return false;
        }

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

        if (IsServiceRunning(g_hService))
        {
            std::cout << "Service already running\n";
            g_ServiceInstalled = true;
            return true;
        }
        else
        {
            // Try to start service
            // Programmer comment: Yeah you can see what the fuck it is :3
            if (!StartService(g_hService, 0, nullptr))
            {
                DWORD err = GetLastError();
                if (err != ERROR_SERVICE_ALREADY_RUNNING)
                {
                    std::cout << "Failed to start existing service: " << err << "\n";
                    CloseServiceHandle(g_hService);
                    CloseServiceHandle(g_hSCManager);
                    g_hService = nullptr;
                    g_hSCManager = nullptr;
                    return false;
                }
            }
            std::cout << "Service started successfully\n";
            g_ServiceInstalled = true;
            return true;
    }
    }

    // Start the service if newly created
    // Yup yup good comment.
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

    g_ServiceInstalled = true;
    return true;
}

bool LoadDriver()
{
    if (!g_hService)
    {
        std::cout << "Service handle invalid\n";
        return false;
    }

    SERVICE_STATUS_PROCESS ssp = { 0 };
    DWORD bytesNeeded = 0;
    if (QueryServiceStatusEx(g_hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded))
    {
        if (ssp.dwCurrentState == SERVICE_RUNNING)
        {
            std::cout << "Service already running\n";
            return true;
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

    g_ServiceInstalled = false;
    return true;
}