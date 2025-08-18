#include <windows.h>
#undef max
#undef min
#include <sddl.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <psapi.h>
#include <string>
#include <algorithm> 
#include "../include/ControllerDefs.h"
#include "../include/IoctlDefs.h"
#include <csignal>

// Global state
bool g_ServiceInstalled = false;
SC_HANDLE g_hService = nullptr;
SC_HANDLE g_hSCManager = nullptr;

bool InstallService();
bool LoadDriver();
bool UnloadDriver();
bool SendIoctl(DWORD ioctl, void* inBuf = nullptr, DWORD inBufSize = 0);
void RunMenu();
void CleanupOnExit()
{
    RunMenu();

    if (g_ServiceInstalled)
        UnloadDriver();
}

BOOL WINAPI ConsoleHandler(DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        CleanupOnExit();
        return TRUE;
    default:
        return FALSE;
}
}

void ListAndWipeProcess()
{
    // Whitelist of allowed anti-cheat executables
    static const std::vector<std::wstring> allowedExecutables = {
        L"EasyAntiCheat.exe", L"rbxhyperion.exe", L"vgk.exe", L"Vanguard.exe"
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to create process snapshot\n";
        return;
    }

    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);

    int index = 1;
    std::vector<std::wstring> processNames;
    std::vector<DWORD> processIds;

    if (Process32First(hSnap, &pe32))
    {
        do
        {
            std::wstring exe(pe32.szExeFile);
            // Only show whitelisted anti-cheat processes
            if (std::find(allowedExecutables.begin(), allowedExecutables.end(), exe) != allowedExecutables.end())
            {
                std::wcout << index << ". " << exe << " (PID: " << pe32.th32ProcessID << ")\n";
                processNames.push_back(exe);
            processIds.push_back(pe32.th32ProcessID);
            ++index;
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);

    if (processNames.empty())
    {
        std::cout << "No allowed anti-cheat processes found\n";
        return;
    }

    int selection = 0;
    std::cout << "Select process to terminate and wipe (0 to cancel): ";
    std::cin >> selection;

    if (std::cin.fail() || selection <= 0 || selection > (int)processNames.size())
    {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Cancelled\n";
        return;
    }

    DWORD pid = processIds[selection - 1];
    std::wstring exeName = processNames[selection - 1];

    // --- Driver-assisted kill & wipe ---
    if (g_ServiceInstalled)
    {
        if (SendIoctl(IOCTL_KILL_AND_WIPE_PROCESS, &pid, sizeof(pid)))
        {
            std::wcout << L"Driver: Kill & Wipe request sent for PID " << pid << L"\n";
        }
        else
        {
            std::wcout << L"Driver: Kill & Wipe request failed for PID " << pid << L"\n";
        }
    }

    // --- User-mode backup and wipe ---
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess)
    {
        std::cout << "Failed to open process for query and termination\n";
        return;
    }

    wchar_t exePath[MAX_PATH] = { 0 };
    if (!GetModuleFileNameExW(hProcess, nullptr, exePath, MAX_PATH))
    {
        std::cout << "Failed to get executable path\n";
        CloseHandle(hProcess);
        return;
    }

    // Block system directory wipes
    std::wstring exePathStr(exePath);
    if (exePathStr.find(L"\\Windows\\") != std::wstring::npos ||
        exePathStr.find(L"\\System32\\") != std::wstring::npos)
    {
        std::wcout << L"Refusing to wipe system file: " << exePath << L"\n";
        CloseHandle(hProcess);
        return;
    }

    std::wcout << L"Target: " << exePath << L"\n";

    // Terminate the process (user-mode fallback)
    if (!TerminateProcess(hProcess, 1))
    {
        std::cout << "Failed to terminate process\n";
        CloseHandle(hProcess);
        return;
    }

    // Wait for process to actually exit
    WaitForSingleObject(hProcess, 5000); // wait max 5 seconds
    CloseHandle(hProcess);

    std::wcout << L"Process terminated: " << exeName << L"\n";

    // Backup EXE
    std::wstring bakPath = exePath;
    bakPath += L".bak";
    if (!CopyFileW(exePath, bakPath.c_str(), FALSE))
    {
        std::wcout << L"Failed to create backup at: " << bakPath << L"\n";
    }
    else
    {
        std::wcout << L"Backup created: " << bakPath << L"\n";
    }

    // Overwrite EXE with null bytes
    HANDLE hFile = CreateFileW(
        exePath,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to open file for overwrite\n";
        return;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize))
    {
        std::cout << "Failed to get file size\n";
        CloseHandle(hFile);
        return;
    }

    std::vector<BYTE> zeroBuffer(4096, 0);
    DWORD bytesWritten = 0;
    LONGLONG totalWritten = 0;
    bool writeFailed = false;

    while (totalWritten < fileSize.QuadPart)
    {
        DWORD toWrite = static_cast<DWORD>(std::min<LONGLONG>(zeroBuffer.size(), fileSize.QuadPart - totalWritten));
        if (!WriteFile(hFile, zeroBuffer.data(), toWrite, &bytesWritten, nullptr) || bytesWritten != toWrite)
        {
            std::cout << "Failed to write zeros to file\n";
            writeFailed = true;
            break;
        }
        totalWritten += bytesWritten;
    }

    CloseHandle(hFile);

    if (!writeFailed)
        std::cout << "Executable wiped successfully\n";
    else
        std::cout << "Executable wipe incomplete due to write failure\n";
}

void RunMenu()
{
    int choice = -1;

    while (choice != 0)
    {
        std::cout << "\n1. Enable Protection"
            << "\n2. Disable Protection"
            << "\n3. Create Service (required)"
            << "\n4. Kill & Wipe Anti-Cheat EXE"
            << "\n0. Exit\nChoice: ";
        std::cin >> choice;

        if (std::cin.fail())
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input\n";
            continue;
        }

        switch (choice)
        {
        case 1:
            if (SendIoctl(IOCTL_ENABLE_PROTECTION))
                std::cout << "Protection enabled\n";
            else
                std::cout << "Failed to enable protection\n";
            break;

        case 2:
            if (SendIoctl(IOCTL_DISABLE_PROTECTION))
                std::cout << "Protection disabled\n";
            else
                std::cout << "Failed to disable protection\n";
            break;
        case 3:
        {
            if (InstallService())
            {
                std::cout << "Service installed and started successfully\n";
                g_ServiceInstalled = true;
            }
            else
            {
                std::cout << "Failed to install/start service\n";
            }
            break;
        }

        case 4:
            ListAndWipeProcess();
            break;

        case 0:
            std::cout << "Exiting\n";
            break;

        default:
            std::cout << "Invalid choice\n";
            break;
        }
    }
}

bool IsSystemAccount()
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);
    PTOKEN_USER ptu = (PTOKEN_USER)malloc(size);
    if (!ptu) {
        CloseHandle(hToken);
        return false;
    }

    bool isSystem = false;
    if (GetTokenInformation(hToken, TokenUser, ptu, size, &size)) {
        WCHAR* sidString = nullptr;
        if (ConvertSidToStringSidW(ptu->User.Sid, &sidString)) {
            // SID for NT AUTHORITY\SYSTEM is S-1-5-18
            if (wcscmp(sidString, L"S-1-5-18") == 0)
                isSystem = true;
            LocalFree(sidString);
        }
    }
    free(ptu);
    CloseHandle(hToken);
    return isSystem;
}

int main()
{
    if (!IsSystemAccount()) {
        std::cout << "This application must be run as NT AUTHORITY\\SYSTEM.\nPress any key to exit...";
        std::cin.get();
        return 1;
    }

    atexit(CleanupOnExit);
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    RunMenu();

    if (g_ServiceInstalled)
        UnloadDriver();

    return 0;
}