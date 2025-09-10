/**
 * @file ControllerDefs.h
 * @brief Definitions for the user-mode controller application.
 */

#pragma once

#include <winioctl.h>

// Undefine common macros that might conflict with Windows headers.
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

/**
 * @def DRIVER_SERVICE_NAME
 * @brief The name of the driver service to be installed.
 */
#define DRIVER_SERVICE_NAME L"EzAntiAntiCheatDriver"

/**
 * @def DRIVER_SYMBOLIC_LINK
 * @brief The symbolic link to the driver's device object.
 * This is the path used by user-mode applications to open a handle to the driver.
 */
#define DRIVER_SYMBOLIC_LINK L"\\\\.\\EzAntiAntiCheatDriver"