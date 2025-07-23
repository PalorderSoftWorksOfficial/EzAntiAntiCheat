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

#define DRIVER_SERVICE_NAME L"AntiShield"

#define IOCTL_ENABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DRIVER_SYMBOLIC_LINK L"\\\\.\\AntiShield"