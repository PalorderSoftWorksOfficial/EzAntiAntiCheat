#define NOMINMAX
#include <windows.h>
#include <string>
#include <winreg.h>
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
#include <ctime>
#include <iomanip>
#include <sstream>
#include <wincrypt.h>
#include "IoctlDefs.h"
#include "../include/ControllerDefs.h"
#include <shellapi.h>
#pragma comment(lib, "crypt32.lib")
#if defined(_M_ARM64)
#ifdef _DEBUG
#define PROTECTED_EXE_NAME   L"EzAntiAntiCheat-arm64-Debug.exe"
#define SYM_LINK_LITERAL     L"\\DosDevices\\EzAntiAntiCheatDriver-arm64-Debug"
#else
#define PROTECTED_EXE_NAME   L"EzAntiAntiCheat-arm64-Release.exe"
#define SYM_LINK_LITERAL     L"\\DosDevices\\EzAntiAntiCheatDriver-arm64-Release"
#endif

#elif defined(_M_X64) || defined(_WIN64)
#ifdef _DEBUG
#define PROTECTED_EXE_NAME   L"EzAntiAntiCheat-x64-Debug.exe"
#define SYM_LINK_LITERAL     L"\\DosDevices\\EzAntiAntiCheatDriver-x64-Debug"
#else
#define PROTECTED_EXE_NAME   L"EzAntiAntiCheat-x64-Release.exe"
#define SYM_LINK_LITERAL     L"\\DosDevices\\EzAntiAntiCheatDriver-x64-Release"
#endif

#elif defined(_M_IX86)
#ifdef _DEBUG
#define PROTECTED_EXE_NAME   L"EzAntiAntiCheat-x86-Debug.exe"
#define SYM_LINK_LITERAL     L"\\DosDevices\\EzAntiAntiCheatDriver-x86-Debug"
#else
#define PROTECTED_EXE_NAME   L"EzAntiAntiCheat-x86-Release.exe"
#define SYM_LINK_LITERAL     L"\\DosDevices\\EzAntiAntiCheatDriver-x86-Release"
#endif

#else
#error Unsupported architecture
#endif

// --- Error Logging ---
void InitErrorLog() {
    std::ofstream logFile("errorlog.txt", std::ios::out | std::ios::trunc);
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    logFile << "EzAntiAntiCheat Log Started: " << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "\n";
    logFile.close();
}

void LogError(const std::string& msg) {
    std::ofstream logFile("errorlog.txt", std::ios::app);
    if (logFile.is_open()) {
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        logFile << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] " << msg << "\n";
        logFile.close();
    }
}

bool IsCertificatePresent(const std::wstring& subjectSubstring) {
    HCERTSTORE hStore = CertOpenSystemStoreW(0, L"MY");
    if (!hStore) return false;
    PCCERT_CONTEXT pCert = nullptr;
    bool found = false;
    while ((pCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING, 0, CERT_FIND_ANY, nullptr, pCert)) != nullptr) {
        DWORD size = CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
        std::wstring subject(size, L'\0');
        CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, &subject[0], size);
        if (subject.find(subjectSubstring) != std::wstring::npos) {
            found = true;
            break;
        }
    }
    CertCloseStore(hStore, 0);
    return found;
}

// --- Global state ---
bool g_ServiceInstalled = false;
SC_HANDLE g_hService = nullptr;
SC_HANDLE g_hSCManager = nullptr;
bool InstallService();
bool LoadDriver();
bool UnloadDriver();
bool SendIoctl(DWORD ioctl, void* inBuf = nullptr, DWORD inBufSize = 0, void* outBuf = nullptr, DWORD outBufSize = 0);
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
    std::wstring lowerPath = exePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    if (lowerPath.find(L"\\windows\\") != std::wstring::npos ||
        lowerPath.find(L"\\system32\\") != std::wstring::npos ||
        lowerPath.find(L"\\windows\\system32\\drivers\\") != std::wstring::npos)
        return false;
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
        std::string msg = "Failed to open file for overwrite: " + std::string(filePath.begin(), filePath.end());
        std::cout << msg << "\n";
        LogError(msg);
        return;
    }

    std::vector<BYTE> randomBuffer(4096);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int pass = 0; pass < 3; ++pass) {
        DWORD bytesWritten = 0;
        LONGLONG totalWritten = 0;
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
        while (totalWritten < fileSize.QuadPart) {
            for (auto& b : randomBuffer) b = static_cast<BYTE>(dis(gen));
            DWORD toWrite = static_cast<DWORD>(std::min<LONGLONG>(randomBuffer.size(), fileSize.QuadPart - totalWritten));
            if (!WriteFile(hFile, randomBuffer.data(), toWrite, &bytesWritten, nullptr) || bytesWritten != toWrite) {
                std::string msg = "Failed to write random data to file: " + std::string(filePath.begin(), filePath.end());
                std::cout << msg << "\n";
                LogError(msg);
                break;
            }
            totalWritten += bytesWritten;
        }
        FlushFileBuffers(hFile);
    }
    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    SetEndOfFile(hFile);
    CloseHandle(hFile);
    SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(filePath.c_str());
    std::string msg = "Executable securely wiped and deleted: " + std::string(filePath.begin(), filePath.end());
    std::cout << msg << "\n";
    LogError(msg);
}

void ListAndWipeProcess()
{
    static const std::vector<std::wstring> allowedExecutables = {
         PROTECTED_EXE_NAME, L"rbxhyperion.exe", L"vgk.exe", L"Vanguard.exe", L"RobloxPlayerBeta.exe"
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::string msg = "Failed to create process snapshot";
        std::cout << msg << "\n";
        LogError(msg);
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
        std::string msg = "No allowed anti-cheat processes found";
        std::cout << msg << "\n";
        LogError(msg);
        return;
    }

    int selection = 0;
    std::cout << "Select process to terminate and wipe (0 to cancel): ";
    std::cin >> selection;

    if (std::cin.fail() || selection <= 0 || selection > (int)processNames.size()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::string msg = "Cancelled";
        std::cout << msg << "\n";
        LogError(msg);
        return;
    }

    DWORD pid = processIds[selection - 1];
    std::wstring exeName = processNames[selection - 1];

    // --- Driver-assisted kill & wipe ---
    if (g_ServiceInstalled) {
        if (SendIoctl(IOCTL_KILL_AND_WIPE_PROCESS, &pid, sizeof(pid))) {
            std::wcout << L"Driver: Kill & Wipe request sent for PID " << pid << L"\n";
            LogError("Driver: Kill & Wipe request sent for PID " + std::to_string(pid));
        } else {
            std::wcout << L"Driver: Kill & Wipe request failed for PID " << pid << L"\n";
            LogError("Driver: Kill & Wipe request failed for PID " + std::to_string(pid));
        }
    }

    // --- User-mode backup and wipe ---
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        std::string msg = "Failed to open process for query and termination";
        std::cout << msg << "\n";
        LogError(msg);
        return;
    }

    wchar_t exePath[MAX_PATH] = { 0 };
    if (!GetModuleFileNameExW(hProcess, nullptr, exePath, MAX_PATH)) {
        std::string msg = "Failed to get executable path";
        std::cout << msg << "\n";
        LogError(msg);
        CloseHandle(hProcess);
        return;
    }

    std::wstring exePathStr(exePath);
    if (!IsSafeWipePath(exePathStr)) {
        std::wcout << L"Refusing to wipe system or non-Program Files file: " << exePath << L"\n";
        LogError("Refusing to wipe system or non-Program Files file: " + std::string(exePathStr.begin(), exePathStr.end()));
        CloseHandle(hProcess);
        return;
    }

    if (!IsFileOwnerSystemOrAdmin(exePathStr)) {
        std::wcout << L"Refusing to wipe file not owned by SYSTEM or Administrators: " << exePath << L"\n";
        LogError("Refusing to wipe file not owned by SYSTEM or Administrators: " + std::string(exePathStr.begin(), exePathStr.end()));
        CloseHandle(hProcess);
        return;
    }

    std::wcout << L"Target: " << exePath << L"\n";
    LogError("Target: " + std::string(exePathStr.begin(), exePathStr.end()));

    // Terminate the process (user-mode fallback)
    if (!TerminateProcess(hProcess, 1)) {
        std::string msg = "Failed to terminate process";
        std::cout << msg << "\n";
        LogError(msg);
        CloseHandle(hProcess);
        return;
    }

    WaitForSingleObject(hProcess, 5000); // wait max 5 seconds
    CloseHandle(hProcess);

    std::wcout << L"Process terminated: " << exeName << L"\n";
    LogError("Process terminated: " + std::string(exeName.begin(), exeName.end()));

    // Backup EXE
    std::wstring bakPath = exePath;
    bakPath += L".bak";
    if (!CopyFileW(exePath, bakPath.c_str(), FALSE)) {
        std::wcout << L"Failed to create backup at: " << bakPath << L"\n";
        LogError("Failed to create backup at: " + std::string(bakPath.begin(), bakPath.end()));
    } else {
        std::wcout << L"Backup created: " << bakPath << L"\n";
        LogError("Backup created: " + std::string(bakPath.begin(), bakPath.end()));
    }

    LARGE_INTEGER fileSize;
    HANDLE hFile = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE || !GetFileSizeEx(hFile, &fileSize)) {
        std::string msg = "Failed to get file size";
        std::cout << msg << "\n";
        LogError(msg);
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
            std::string msg = "Invalid input";
            std::cout << msg << "\n";
            LogError(msg);
            continue;
        }

        switch (choice)
        {
        case 1:
            if (SendIoctl(IOCTL_ENABLE_PROTECTION)) {
                std::cout << "Protection enabled\n";
                LogError("Protection enabled");
            }
            else {
                std::cout << "Failed to enable protection\n";
                LogError("Failed to enable protection");
            }
            break;

        case 2:
            if (SendIoctl(IOCTL_DISABLE_PROTECTION)) {
                std::cout << "Protection disabled\n";
                LogError("Protection disabled");
            }
            else {
                std::cout << "Failed to disable protection\n";
                LogError("Failed to disable protection");
            }
            break;
        case 3:
        {
            if (InstallService())
            {
                std::cout << "Service installed and started successfully\n";
                LogError("Service installed and started successfully");
                g_ServiceInstalled = true;
            }
            else
            {
                std::string msg = "Failed to install/start service";
                std::cout << msg << "\n";
                LogError(msg);
            }
            break;
        }

        case 4:
            ListAndWipeProcess();
            break;

        case 0:
            std::cout << "Exiting\n";
            LogError("Exiting");
            break;

        default:
            std::cout << "Invalid choice\n";
            LogError("Invalid choice");
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
            if (wcscmp(sidString, L"S-1-5-18") == 0)
                isSystem = true;
            LocalFree(sidString);
        }
    }
    free(ptu);
    CloseHandle(hToken);
    return isSystem;
}

bool EnsureTestSigningAndDisableSecureBoot()
{
    bool secureBootEnabled = false;
    HKEY hKey;
    DWORD value = 0, valueSize = sizeof(DWORD);
    LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        0, KEY_QUERY_VALUE, &hKey);
    if (status == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"UEFISecureBootEnabled", nullptr, nullptr, (LPBYTE)&value, &valueSize) == ERROR_SUCCESS) {
            secureBootEnabled = (value != 0);
        }
        RegCloseKey(hKey);
    }

    bool testSigningEnabled = false;
    valueSize = sizeof(DWORD);
    status = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SystemStartOptions",
        0, KEY_QUERY_VALUE, &hKey);
    if (status == ERROR_SUCCESS) {
        WCHAR options[256] = {0};
        DWORD optionsSize = sizeof(options);
        if (RegQueryValueExW(hKey, L"SystemStartOptions", nullptr, nullptr, (LPBYTE)options, &optionsSize) == ERROR_SUCCESS) {
            std::wstring opts(options);
            if (opts.find(L"TESTSIGNING") != std::wstring::npos)
                testSigningEnabled = true;
        }
        RegCloseKey(hKey);
    }

    if (secureBootEnabled) {
        std::string msg = "Secure Boot is enabled. Please disable it in your UEFI firmware settings.";
        std::cout << msg << "\n";
        LogError(msg);
        std::cin.get();
        return false;
    }

    if (!testSigningEnabled) {
        std::string msg = "Test Signing is not enabled. Attempting to enable...";
        std::cout << msg << "\n";
        LogError(msg);
        int ret = system("bcdedit /set testsigning on");
        if (ret != 0) {
            std::string msg2 = "Failed to enable test signing. Run as administrator.";
            std::cout << msg2 << "\n";
            LogError(msg2);
            std::cin.get();
            return false;
        }
        std::string msg3 = "Test signing enabled. Please reboot your system for changes to take effect.";
        std::cout << msg3 << "\n";
        LogError(msg3);
        std::cin.get();
        return false;
    }

    std::string msg = "Secure Boot is disabled and Test Signing is enabled.";
    std::cout << msg << "\n";
    LogError(msg);
    return true;
}

void RetrieveAndWriteErrorLog() {
    char errorLog[256] = {0};
    if (SendIoctl(IOCTL_GET_LAST_ERROR_LOG, nullptr, 0, errorLog, sizeof(errorLog))) {
        std::ofstream logFile("errorlog.txt", std::ios::app);
        if (strlen(errorLog) > 0) {
            logFile << "[KERNEL] " << errorLog << "\n";
        }
        logFile.close();
    }
}

void ShowErrorPopupIfNeeded() {
    std::ifstream logFile("errorlog.txt");
    std::string logContent((std::istreambuf_iterator<char>(logFile)), std::istreambuf_iterator<char>());
    logFile.close();

    if (!logContent.empty()) {
        MessageBoxA(nullptr,
            "A kernel security error was detected.\nPlease create an issue on our GitHub repository and attach errorlog.txt.",
            "EzAntiAntiCheat Error", MB_OK | MB_ICONERROR);

        ShellExecuteA(nullptr, "open",
            "https://github.com/PalorderSoftWorksOfficial/EzAntiAntiCheat/issues",
            nullptr, nullptr, SW_SHOWNORMAL);
    }
}

bool SendIoctl(DWORD ioctl, void* inBuf, DWORD inBufSize, void* outBuf, DWORD outBufSize) {
    std::wstring protectedExe = L"\\\\.\\" + std::wstring(PROTECTED_EXE_NAME);
    HANDLE hDevice = CreateFileW(protectedExe.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::ostringstream oss;
        oss << "Failed to open device for IOCTL (" << GetLastError() << ")";
        LogError(oss.str());
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(hDevice, ioctl, inBuf, inBufSize, outBuf, outBufSize, &bytesReturned, nullptr);
    if (!result) {
        std::ostringstream oss;
        oss << "DeviceIoControl failed (IOCTL=" << ioctl << ", Error=" << GetLastError() << ")";
        LogError(oss.str());
    }
    CloseHandle(hDevice);
    return result && bytesReturned > 0;
}

// --- Main ---
int main()
{
    InitErrorLog();
    LogError("Program started.");

    // Optionally check for certificate
    bool certPresent = IsCertificatePresent(L"EzAntiAntiCheat");
    LogError(std::string("Certificate present in store: ") + (certPresent ? "YES" : "NO"));

    RetrieveAndWriteErrorLog();
    ShowErrorPopupIfNeeded();

    if (!IsSystemAccount()) {
        std::string msg = "This application must be run as NT AUTHORITY\\SYSTEM, and disable secure boot and enable test signing.";
        std::cout << msg << "\nPress any key to exit...";
        LogError(msg);
        std::cin.get();
        return 1;
    }

    if (!EnsureTestSigningAndDisableSecureBoot()) {
        LogError("Test signing or secure boot requirements not met.");
        return 1;
    }

    atexit(CleanupOnExit);
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    RunMenu();

    if (g_ServiceInstalled)
        UnloadDriver();

    LogError("Program exited.");
    return 0;
}