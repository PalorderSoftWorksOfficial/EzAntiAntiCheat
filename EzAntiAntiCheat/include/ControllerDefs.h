#pragma once
#include <winioctl.h>

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

#ifdef Set
#undef Set
#endif
// CMake is ass for this project :3
// ==================== Build-time symbolic link ====================
#if defined(_M_ARM64)
#ifdef _DEBUG
#define DRIVER_SERVICE_NAME L"EzAntiAntiCheatDriver-arm64-Debug"
#define DRIVER_SYMBOLIC_LINK L"\\\\.\\EzAntiAntiCheat-arm64-Debug.exe"
#else
#define DRIVER_SERVICE_NAME L"EzAntiAntiCheatDriver-arm64-Release"
#define DRIVER_SYMBOLIC_LINK L"\\\\.\\EzAntiAntiCheat-arm64-Release.exe"
#endif

#elif defined(_M_X64) || defined(_WIN64)
#ifdef _DEBUG
#define DRIVER_SERVICE_NAME L"EzAntiAntiCheatDriver-x64-Debug"
#define DRIVER_SYMBOLIC_LINK L"\\\\.\\EzAntiAntiCheat-x64-Debug.exe"
#else
#define DRIVER_SERVICE_NAME L"EzAntiAntiCheatDriver-x64-Release"
#define DRIVER_SYMBOLIC_LINK L"\\\\.\\EzAntiAntiCheat-x64-Release.exe"
#endif

#elif defined(_M_IX86)
#ifdef _DEBUG
#define DRIVER_SERVICE_NAME L"EzAntiAntiCheatDriver-x86-Debug"
#define DRIVER_SYMBOLIC_LINK L"\\\\.\\EzAntiAntiCheat-x86-Debug.exe"
#else
#define DRIVER_SERVICE_NAME L"EzAntiAntiCheatDriver-x86-Release"
#define DRIVER_SYMBOLIC_LINK L"\\\\.\\EzAntiAntiCheat-x86-Release.exe"
#endif

#else
#error Unsupported architecture
#endif

// ==================== IOCTL codes ====================
#define IOCTL_ENABLE_PROTECTION  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) // Disable prrrrotection
#define IOCTL_DISABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) // Enabled prrrrotection
#define IOCTL_KILL_AND_WIPE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) // pew pew
// I love cats :3