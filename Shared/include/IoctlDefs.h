#pragma once

//
// IOCTL definitions for EzAntiAntiCheat
//

/**
 * @brief Enables the anti-cheat protection.
 * This IOCTL is sent by the user-mode controller to the driver to activate
 * the image load blocking and other protective measures.
 */
#define IOCTL_ENABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

/**
 * @brief Disables the anti-cheat protection.
 * This IOCTL is sent by the user-mode controller to the driver to deactivate
 * the image load blocking.
 */
#define IOCTL_DISABLE_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

/**
 * @brief Terminates and wipes a target process.
 * This IOCTL is sent by the user-mode controller to the driver. The input
 * buffer should contain the process ID (PID) of the target process. The
 * driver will attempt to terminate the process and overwrite the executable
 * file on disk.
 */
#define IOCTL_KILL_AND_WIPE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
