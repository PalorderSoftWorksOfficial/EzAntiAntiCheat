# EzAntiAntiCheat

EzAntiAntiCheat is a Windows kernel-mode driver and user-mode controller application designed to demonstrate techniques for interacting with and disabling kernel-level anti-cheat systems. This project is intended for educational and research purposes only.

**WARNING: This tool interacts with low-level system components and can cause system instability, data loss, or other unintended consequences. Use at your own risk. The authors are not responsible for any damage caused by this software.**

## Features

*   **Driver Loading/Unloading**: The user-mode application can install, start, stop, and uninstall the kernel-mode driver.
*   **IOCTL Communication**: The user-mode application communicates with the driver via IOCTLs to enable and disable protection.
*   **Image Load Blocking**: The driver can block the loading of specific kernel-mode drivers (e.g., anti-cheat drivers) using an image load notify routine.
*   **Process Termination**: The application can terminate and "wipe" (overwrite) the executable files of specific processes.
*   **Process Protection**: The driver demonstrates techniques for protecting a process from being terminated or having its memory accessed, using object callbacks.
*   **Anti-Tampering**: The driver includes a self-protection mechanism that periodically checks its own integrity.

## Building the Project

To build this project, you will need:

*   **Visual Studio**: The latest version of Visual Studio with the "Desktop development with C++" and "Driver development" workloads installed.
*   **Windows SDK**: The latest version of the Windows SDK.
*   **Windows WDK**: The latest version of the Windows Driver Kit.

To build the project:

1.  Clone the repository.
2.  Open the `EzAntiAntiCheat.sln` file in Visual Studio.
3.  Select the desired build configuration (e.g., "Release" and "x64").
4.  Build the solution.

The output files will be located in the `$(SolutionDir)\$(Platform)\$(Configuration)` directory.

## Usage

**IMPORTANT: The user-mode application (`EzAntiAntiCheat.exe`) must be run with the highest privileges (as `NT AUTHORITY\SYSTEM`). You can use a tool like `psexec` or `AdvancedRun` to achieve this.**

For example, using `psexec`:

```
psexec -i -s EzAntiAntiCheat.exe
```

Once the application is running, you will be presented with a menu of options:

1.  **Enable Protection**: Sends an IOCTL to the driver to enable the image load blocking.
2.  **Disable Protection**: Sends an IOCTL to the driver to disable the image load blocking.
3.  **Create Service (required)**: Installs and starts the driver service. This must be done before any other options will work.
4.  **Kill & Wipe Anti-Cheat EXE**: Lists a set of whitelisted anti-cheat processes and allows you to select one to terminate and wipe.
5.  **Exit**: Exits the application and unloads the driver.

## Disclaimer

This project is provided "as is" and without warranty of any kind. The authors are not responsible for any damage or loss of data that may result from the use of this software. Use at your own risk.

This project is intended for educational purposes only. Do not use this software to cheat in online games or to violate the terms of service of any software.
