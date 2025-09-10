/**
 * @file DriverDefs.h
 * @brief Definitions and declarations for the driver.
 */

#pragma once
#include <wdm.h>

/**
 * @def MY_BUGCHECK_CODE
 * @brief The bugcheck code to use when a fatal error occurs.
 */
#define MY_BUGCHECK_CODE 0x139

#ifdef __cplusplus
extern "C" {
#endif

    //
    // External function prototypes
    //

    /**
     * @brief Gets the image file name of a process.
     * @param Process A pointer to the EPROCESS object.
     * @return A pointer to the image file name.
     */
    extern UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

    //
    // Global variables for integrity checking
    //

    /**
     * @var g_IntegrityOk
     * @brief A flag indicating whether the driver's integrity is intact.
     */
    extern volatile LONG g_IntegrityOk;

    /**
     * @var g_DriverBase
     * @brief The base address of the driver image.
     */
    extern PVOID g_DriverBase;

    /**
     * @var g_DriverSize
     * @brief The size of the driver image, in bytes.
     */
    extern SIZE_T g_DriverSize;

    /**
     * @var g_ExpectedCrc
     * @brief The expected CRC32 checksum of the driver image.
     */
    extern ULONG g_ExpectedCrc;

    /**
     * @var g_IntegrityThreadHandle
     * @brief A handle to the integrity check thread.
     */
    extern HANDLE g_IntegrityThreadHandle;


    //
    // Function prototypes for anti-tampering
    //

    /**
     * @brief Checks if the current process is the manager application.
     * @return TRUE if the current process is the manager, FALSE otherwise.
     */
    BOOLEAN IsManagerProcess();

    /**
     * @brief Calculates the CRC32 checksum of a buffer.
     * @param data A pointer to the data.
     * @param length The length of the data, in bytes.
     * @return The CRC32 checksum.
     */
    ULONG Crc32(const void* data, SIZE_T length);

    /**
     * @brief Initializes the integrity check.
     * @param base The base address of the driver image.
     * @param size The size of the driver image, in bytes.
     */
    VOID InitializeIntegrityCheck(PVOID base, SIZE_T size);

    /**
     * @brief Starts the integrity check thread.
     * @return STATUS_SUCCESS on success, or an NTSTATUS error code on failure.
     */
    NTSTATUS StartIntegrityThread();

    /**
     * @brief Stops the integrity check thread.
     */
    VOID StopIntegrityThread();

    /**
     * @brief The main function for the integrity check thread.
     * @param StartContext The start context for the thread.
     */
    VOID IntegrityThread(_In_ PVOID StartContext);

#ifdef __cplusplus
}
#endif

/**
 * @brief Checks if a process is the protected process.
 *
 * This is an inline function for performance.
 *
 * @param Process A pointer to the EPROCESS object.
 * @return TRUE if the process is the protected process, FALSE otherwise.
 */
inline BOOLEAN IsProtectedProcess(PEPROCESS Process)
{
    if (!Process) return FALSE;
    UCHAR* imageName = PsGetProcessImageFileName(Process);
    if (imageName)
        if (_stricmp((const char*)imageName, "ShieldController.exe") == 0)
            return TRUE;
    return FALSE;
}
