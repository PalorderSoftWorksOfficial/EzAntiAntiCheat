#pragma once

/**
 * @file IoctlDefs.h
 * @brief Shared IOCTL code definitions for EzAntiAntiCheat user-mode and driver components.
 *
 * These codes are used for communication between the controller and the kernel driver.
 */

 /// Enables protection features in the driver.
#define IOCTL_ENABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

/// Disables protection features in the driver.
#define IOCTL_DISABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

/// Terminates and securely wipes a target process.
#define IOCTL_KILL_AND_WIPE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)