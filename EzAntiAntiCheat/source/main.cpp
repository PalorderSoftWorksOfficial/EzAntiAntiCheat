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
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <wincrypt.h>
#include "IoctlDefs.h"
#include "../include/ControllerDefs.h"
#include <shellapi.h>
#include <external_data.h>
#include <json.hpp>
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

using json = nlohmann::json;

json g_languageJson;
std::wstring g_languageCode = L"en";

void EnsureLanguagesFileExists()
{
    wchar_t exePath[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    size_t lastSlash = exeDir.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos)
        exeDir = exeDir.substr(0, lastSlash);

    std::filesystem::path languagesFolder = exeDir + L"\\languages";
    std::filesystem::create_directories(languagesFolder);

    std::filesystem::path langFilePath = languagesFolder / "languages.json";

    if (!std::filesystem::exists(langFilePath))
    {
        json defaultLang = {
            {"en", {
                {"program_started", "Program started."},
                {"protection_enabled", "Protection enabled"},
                {"protection_disabled", "Protection disabled"},
                {"exit_msg", "Exiting"},
                {"invalid_choice", "Invalid choice"},
                {"service_installed", "Service installed and started successfully"},
                {"service_failed", "Failed to install/start service"},
                {"select_process", "Select process to terminate and wipe (0 to cancel):"},
                {"cancelled", "Cancelled"},
                {"process_terminated", "Process terminated:"},
                {"backup_created", "Backup created:"},
                {"failed_backup", "Failed to create backup at:"},
                {"failed_wipe", "Failed to write random data to file:"},
                {"kernel_error_detected", "A kernel security error was detected.\nPlease create an issue on our GitHub repository and attach errorlog.txt."}
            }},
            {"de", {
                {"program_started", "Programm gestartet."},
                {"protection_enabled", "Schutz aktiviert"},
                {"protection_disabled", "Schutz deaktiviert"},
                {"exit_msg", "Beenden"},
                {"invalid_choice", "Ungültige Auswahl"},
                {"service_installed", "Dienst erfolgreich installiert und gestartet"},
                {"service_failed", "Dienstinstallation/-start fehlgeschlagen"},
                {"select_process", "Prozess zum Beenden und Löschen auswählen (0 zum Abbrechen):"},
                {"cancelled", "Abgebrochen"},
                {"process_terminated", "Prozess beendet:"},
                {"backup_created", "Backup erstellt:"},
                {"failed_backup", "Backup konnte nicht erstellt werden:"},
                {"failed_wipe", "Fehler beim Überschreiben der Datei:"},
                {"kernel_error_detected", "Ein Kernel-Sicherheitsfehler wurde erkannt.\nBitte erstellen Sie ein Issue auf unserem GitHub-Repository und fügen Sie errorlog.txt bei."}
            }},
            {"fr", {
                {"program_started", "Programme démarré."},
                {"protection_enabled", "Protection activée"},
                {"protection_disabled", "Protection désactivée"},
                {"exit_msg", "Quitter"},
                {"invalid_choice", "Choix invalide"},
                {"service_installed", "Service installé et démarré avec succès"},
                {"service_failed", "Échec de l'installation/démarrage du service"},
                {"select_process", "Sélectionnez le processus à terminer et effacer (0 pour annuler):"},
                {"cancelled", "Annulé"},
                {"process_terminated", "Processus terminé:"},
                {"backup_created", "Sauvegarde créée:"},
                {"failed_backup", "Échec de la création de la sauvegarde:"},
                {"failed_wipe", "Échec de l'écriture de données aléatoires sur le fichier:"},
                {"kernel_error_detected", "Une erreur de sécurité du noyau a été détectée.\nVeuillez créer un problème sur notre dépôt GitHub et joindre errorlog.txt."}
            }},
            {"es", {
                {"program_started", "Programa iniciado."},
                {"protection_enabled", "Protección activada"},
                {"protection_disabled", "Protección desactivada"},
                {"exit_msg", "Salir"},
                {"invalid_choice", "Opción inválida"},
                {"service_installed", "Servicio instalado e iniciado correctamente"},
                {"service_failed", "Error al instalar/iniciar el servicio"},
                {"select_process", "Seleccione el proceso a terminar y borrar (0 para cancelar):"},
                {"cancelled", "Cancelado"},
                {"process_terminated", "Proceso terminado:"},
                {"backup_created", "Copia de seguridad creada:"},
                {"failed_backup", "Error al crear la copia de seguridad:"},
                {"failed_wipe", "Error al escribir datos aleatorios en el archivo:"},
                {"kernel_error_detected", "Se detectó un error de seguridad del kernel.\nPor favor, cree un issue en nuestro repositorio de GitHub y adjunte errorlog.txt."}
            }}
        };

        std::ofstream ofs(langFilePath);
        ofs << std::setw(4) << defaultLang << std::endl;
    }
}

void LoadLanguage()
{
    EnsureLanguagesFileExists();

    LANGID langId = GetUserDefaultUILanguage();
    switch (PRIMARYLANGID(langId))
    {
    case LANG_GERMAN: g_languageCode = L"de"; break;
    case LANG_FRENCH: g_languageCode = L"fr"; break;
    case LANG_SPANISH: g_languageCode = L"es"; break;
    case LANG_ITALIAN: g_languageCode = L"it"; break;
    case LANG_RUSSIAN: g_languageCode = L"ru"; break;
    case LANG_CHINESE: g_languageCode = L"zh"; break;
    case LANG_JAPANESE: g_languageCode = L"ja"; break;
    default: g_languageCode = L"en"; break;
    }

    wchar_t exePath[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    exeDir = exeDir.substr(0, exeDir.find_last_of(L"\\/"));

    std::filesystem::path langFilePath = exeDir + L"\\languages\\languages.json";

    std::ifstream langFile(langFilePath);
    if (!langFile.is_open())
        return;

    try
    {
        json allLanguages;
        langFile >> allLanguages;

        std::string codeStr(g_languageCode.begin(), g_languageCode.end());
        if (allLanguages.contains(codeStr))
            g_languageJson = allLanguages[codeStr];
        else
            g_languageJson = allLanguages["en"];
    }
    catch (...) {}
}

std::string LStr(const std::string& key)
{
    if (g_languageJson.contains(key))
        return g_languageJson[key].get<std::string>();
    return key;
}
// --- Error Logging ---
void InitErrorLog() {
    std::ofstream logFile("errorlog.txt", std::ios::out | std::ios::trunc);
    if (!logFile.is_open()) return;

    std::time_t t = std::time(nullptr);
    std::tm tm;
    localtime_s(&tm, &t);

    logFile << "EzAntiAntiCheat Log Started: "
        << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "\n";
    logFile.close();
}

void LogError(const std::string& msg) {
    std::ofstream logFile("errorlog.txt", std::ios::app);
    if (!logFile.is_open()) return;

    std::time_t t = std::time(nullptr);
    std::tm tm;
    localtime_s(&tm, &t);

    logFile << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] [EzAntiAntiCheat] "
        << msg << "\n";
    logFile.close();
}
void LogTextA(const char* format, ...)
{
    char buffer[512] = { 0 };
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    std::ofstream logFile("logs.txt", std::ios::app);
    logFile << "[EzAntiAntiCheat] " << buffer << "\n";
    logFile.close();
}

void LogTextW(const wchar_t* format, ...)
{
    wchar_t buffer[512] = { 0 };
    va_list args;
    va_start(args, format);
    vswprintf(buffer, sizeof(buffer) / sizeof(wchar_t), format, args);
    va_end(args);

    std::wofstream logFile("logs.txt", std::ios::app);
    logFile << L"[EzAntiAntiCheat] " << buffer << L"\n";
    logFile.close();
}

bool IsCertificatePresent(const std::wstring& subjectSubstring) {
    HCERTSTORE hStore = CertOpenSystemStoreW(0, L"ROOT");
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
	// If you find this unclear this defines the anti cheats that are allowed to be targeted.
    static const std::vector<std::wstring> allowedExecutables = {
    L"BattlEyeA.exe",
    L"BEService.exe",
    L"EasyAntiCheat.exe",
    L"EasyAntiCheat_EOS.exe",
    L"faceit.exe",
    L"faceitclient.exe",
    L"PnkBstrA.exe",
    L"PnkBstrB.exe",
    L"RobloxPlayerBeta.exe",
    L"steamservice.exe",
    L"vgc.exe",
    L"vgk.exe",
    L"Vanguard.exe"
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
bool IsTestSigningEnabledViaBcdedit() {
    FILE* pipe = _popen("bcdedit /enum", "r");
    if (!pipe) return false;

    std::string output;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        output += buffer;
    }
    _pclose(pipe);

    // Search for "testsigning" and "Yes" in the output
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        std::transform(line.begin(), line.end(), line.begin(), ::tolower);
        if (line.find("testsigning") != std::string::npos && line.find("yes") != std::string::npos) {
            return true;
        }
    }
    return false;
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

    // Use bcdedit parsing instead of registry for test signing
    bool testSigningEnabled = IsTestSigningEnabledViaBcdedit();

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

void RetrieveAndWriteKernelErrorLog()
{
    char errorLog[256] = { 0 };
    if (SendIoctl(IOCTL_GET_LAST_ERROR_LOG, nullptr, 0, errorLog, sizeof(errorLog)))
    {
        if (strlen(errorLog) > 0)
        {
            std::ofstream logFile("logs.txt", std::ios::app);
            logFile << "[EzAntiAntiCheatDriver] " << errorLog << "\n";
            logFile.close();
        }
    }
}
void RetrieveAndWriteErrorLog() {
    char errorLog[256] = {0};
    if (SendIoctl(IOCTL_GET_LAST_ERROR_LOG, nullptr, 0, errorLog, sizeof(errorLog))) {
        std::ofstream logFile("errorlog.txt", std::ios::app);
        if (strlen(errorLog) > 0) {
            logFile << "[KERNEL] [EzAntiAntiCheatDriver] " << errorLog << "\n";
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
void ShowKernelErrorPopupIfNeeded()
{
    std::ifstream logFile("logs.txt");
    std::string logContent((std::istreambuf_iterator<char>(logFile)),
        std::istreambuf_iterator<char>());
    logFile.close();

    if (logContent.find("[EzAntiAntiCheatDriver]") != std::string::npos)
    {
        MessageBoxA(nullptr,
            "A kernel security error was detected.\nPlease create an issue on our GitHub repository and attach logs.txt.",
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
    size_t count = sizeof(CAPS) / sizeof(CAPS[0]);
    SerialEntry* dyn = (SerialEntry*)malloc(count * sizeof(SerialEntry));

    for (size_t i = 0; i < count; i++) {
        dyn[i].id = CAPS[i].id;
        dyn[i].hash = CAPS[i].hash;
        dyn[i].serial = _wcsdup(CAPS[i].serial);
    }

    LoadLanguage();

    InitErrorLog();
    LogError("Program started.");

    std::cout << LStr("welcome_message") << "\n";

    if (!IsSystemAccount()) {
        std::cout << LStr("run_as_system") << "\n";
        LogError("Not running as SYSTEM account.");
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