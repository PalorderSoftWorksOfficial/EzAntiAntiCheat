#define NOMINMAX
#include <windows.h>
#include <algorithm>
#undef max
#undef min
#include <aclapi.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <psapi.h>
#include <string>
#include <csignal>
#include <random>
#include <limits>
#include "../include/IoctlDefs.h"
#include "../include/ControllerDefs.h"
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

bool IsSafeWipePath(const std::wstring& exePath) {
    // Block system folders
    std::wstring lowerPath = exePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    if (lowerPath.find(L"\\windows\\") != std::wstring::npos ||
        lowerPath.find(L"\\system32\\") != std::wstring::npos ||
        lowerPath.find(L"\\windows\\system32\\drivers\\") != std::wstring::npos)
        return false;
    // Allow only Program Files locations
    if (lowerPath.find(L"c:\\program files\\") == std::wstring::npos &&
        lowerPath.find(L"c:\\program files (x86)\\") == std::wstring::npos)
        return false;
    return true;
}

bool IsFileOwnerSystemOrAdmin(const std::wstring& filePath) {
    PSID ownerSid = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(filePath.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &ownerSid, nullptr, nullptr, nullptr, &sd) != ERROR_SUCCESS)
        return false;
    WCHAR* sidString = nullptr;
    bool isSystemOrAdmin = false;
    if (ConvertSidToStringSidW(ownerSid, &sidString)) {
        if (wcscmp(sidString, L"S-1-5-18") == 0 || // SYSTEM
            wcscmp(sidString, L"S-1-5-32-544") == 0) // Administrators
            isSystemOrAdmin = true;
        LocalFree(sidString);
    }
    if (sd) LocalFree(sd);
    return isSystemOrAdmin;
}

void SecureWipeFile(const std::wstring& filePath, LARGE_INTEGER fileSize) {
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open file for overwrite\n";
        return;
    }

    std::vector<BYTE> randomBuffer(4096);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    DWORD bytesWritten = 0;
    LONGLONG totalWritten = 0;
    bool writeFailed = false;

    while (totalWritten < fileSize.QuadPart) {
        for (auto& b : randomBuffer) b = static_cast<BYTE>(dis(gen));
        DWORD toWrite = static_cast<DWORD>(std::min<LONGLONG>(randomBuffer.size(), fileSize.QuadPart - totalWritten));
        if (!WriteFile(hFile, randomBuffer.data(), toWrite, &bytesWritten, nullptr) || bytesWritten != toWrite) {
            std::cout << "Failed to write random data to file\n";
            writeFailed = true;
            break;
        }
        totalWritten += bytesWritten;
    }
    CloseHandle(hFile);
    if (!writeFailed)
        std::cout << "Executable securely wiped\n";
    else
        std::cout << "Executable wipe incomplete due to write failure\n";
}

void ListAndWipeProcess()
{
    static const std::vector<std::wstring> allowedExecutables = {
        L"EasyAntiCheat.exe", L"rbxhyperion.exe", L"vgk.exe", L"Vanguard.exe"
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to create process snapshot\n";
        return;
    }

    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);

    int index = 1;
    std::vector<std::wstring> processNames;
    std::vector<DWORD> processIds;

    if (Process32First(hSnap, &pe32)) {
        do {
            std::wstring exe(pe32.szExeFile);
            if (std::find(allowedExecutables.begin(), allowedExecutables.end(), exe) != allowedExecutables.end()) {
                std::wcout << index << ". " << exe << " (PID: " << pe32.th32ProcessID << ")\n";
                processNames.push_back(exe);
                processIds.push_back(pe32.th32ProcessID);
                ++index;
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);

    if (processNames.empty()) {
        std::cout << "No allowed anti-cheat processes found\n";
        return;
    }

    int selection = 0;
    std::cout << "Select process to terminate and wipe (0 to cancel): ";
    std::cin >> selection;

    if (std::cin.fail() || selection <= 0 || selection > (int)processNames.size()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Cancelled\n";
        return;
    }

    DWORD pid = processIds[selection - 1];
    std::wstring exeName = processNames[selection - 1];

    // --- Driver-assisted kill & wipe ---
    if (g_ServiceInstalled) {
        if (SendIoctl(IOCTL_KILL_AND_WIPE_PROCESS, &pid, sizeof(pid))) {
            std::wcout << L"Driver: Kill & Wipe request sent for PID " << pid << L"\n";
        } else {
            std::wcout << L"Driver: Kill & Wipe request failed for PID " << pid << L"\n";
        }
    }

    // --- User-mode backup and wipe ---
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        std::cout << "Failed to open process for query and termination\n";
        return;
    }

    wchar_t exePath[MAX_PATH] = { 0 };
    if (!GetModuleFileNameExW(hProcess, nullptr, exePath, MAX_PATH)) {
        std::cout << "Failed to get executable path\n";
        CloseHandle(hProcess);
        return;
    }

    std::wstring exePathStr(exePath);
    if (!IsSafeWipePath(exePathStr)) {
        std::wcout << L"Refusing to wipe system or non-Program Files file: " << exePath << L"\n";
        CloseHandle(hProcess);
        return;
    }

    if (!IsFileOwnerSystemOrAdmin(exePathStr)) {
        std::wcout << L"Refusing to wipe file not owned by SYSTEM or Administrators: " << exePath << L"\n";
        CloseHandle(hProcess);
        return;
    }

    std::wcout << L"Target: " << exePath << L"\n";

    // Terminate the process (user-mode fallback)
    if (!TerminateProcess(hProcess, 1)) {
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
    if (!CopyFileW(exePath, bakPath.c_str(), FALSE)) {
        std::wcout << L"Failed to create backup at: " << bakPath << L"\n";
    } else {
        std::wcout << L"Backup created: " << bakPath << L"\n";
    }

    LARGE_INTEGER fileSize;
    HANDLE hFile = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE || !GetFileSizeEx(hFile, &fileSize)) {
        std::cout << "Failed to get file size\n";
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
        return;
    }
    CloseHandle(hFile);

    SecureWipeFile(exePathStr, fileSize);
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