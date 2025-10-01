using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
// I am ass at using designer so i just used copilot for this - PalorderSoftWorksOfficial

namespace EzAntiAntiCheatSetup
{
    /// <summary>
    /// Main form of the EzAntiAntiCheatSetup application.
    /// </summary>
    public class Form1 : Form
    {
        private TextBox instructionsTextBox;
        private Button btnAdvancedRun;
        private Button btnExecTI;
        private Button btnGitHub;
        private Button btnHelp;
        /// <summary>
        /// Main form of the EzAntiAntiCheatSetup application.
        /// </summary>
        /// i hate CS now
        public Form1()
        {
            this.Text = "EzAntiAntiCheat Setup Wizard";
            this.ClientSize = new Size(640, 420);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;

            instructionsTextBox = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Size = new Size(600, 280),
                Location = new Point(20, 20),
                Font = new Font("Segoe UI", 10),
            };
            this.Controls.Add(instructionsTextBox);

            btnAdvancedRun = new Button
            {
                Text = "Open AdvancedRun Download",
                Size = new Size(180, 32),
                Location = new Point(20, 320)
            };
            btnAdvancedRun.Click += btnAdvancedRun_Click;
            this.Controls.Add(btnAdvancedRun);

            btnExecTI = new Button
            {
                Text = "Open ExecTI Download",
                Size = new Size(180, 32),
                Location = new Point(220, 320)
            };
            btnExecTI.Click += btnExecTI_Click;
            this.Controls.Add(btnExecTI);

            btnGitHub = new Button
            {
                Text = "Open GitHub Repository",
                Size = new Size(180, 32),
                Location = new Point(420, 320)
            };
            btnGitHub.Click += btnGitHub_Click;
            this.Controls.Add(btnGitHub);

            btnHelp = new Button
            {
                Text = "Help",
                Size = new Size(80, 32),
                Location = new Point(20, 370)
            };
            btnHelp.Click += btnHelp_Click;
            this.Controls.Add(btnHelp);

            SetupInstructions();
        }

        private void SetupInstructions()
        {
            instructionsTextBox.Text =
@"Welcome to the EzAntiAntiCheat Setup Wizard!

To use EzAntiAntiCheat, you must follow these steps:

1. Download AdvancedRun (recommended) or ExecTI:
   - AdvancedRun: https://www.nirsoft.net/utils/advanced_run.html
   - ExecTI: https://winaero.com/run-programs-trustedinstaller-windows/

2. Extract AdvancedRun or ExecTI to a folder.

3. Use AdvancedRun or ExecTI to launch EzAntiAntiCheat.exe as 'TrustedInstaller' or 'NT AUTHORITY\SYSTEM'.
   - In AdvancedRun, set 'Run As' to 'TrustedInstaller' and select EzAntiAntiCheat.exe.
   - Click 'Run'.

4. Make sure Secure Boot is DISABLED in your UEFI/BIOS settings.
   - This is required for kernel driver loading.

5. Make sure Windows Test Signing mode is ENABLED.
   - The program will attempt to enable it automatically, but you may need to reboot.

6. Once launched as SYSTEM/TrustedInstaller, use the menu to install the driver and use the program.

For help, visit the EzAntiAntiCheat GitHub repository:
https://github.com/PalorderSoftWorksOfficial/EzAntiAntiCheat

If you need help, click the buttons below for more info or to open AdvancedRun's download page.";
        }

        private void btnAdvancedRun_Click(object sender, EventArgs e)
        {
            Process.Start(new ProcessStartInfo("https://www.nirsoft.net/utils/advanced_run.html") { UseShellExecute = true });
        }

        private void btnExecTI_Click(object sender, EventArgs e)
        {
            Process.Start(new ProcessStartInfo("https://winaero.com/run-programs-trustedinstaller-windows/") { UseShellExecute = true });
        }

        private void btnGitHub_Click(object sender, EventArgs e)
        {
            Process.Start(new ProcessStartInfo("https://github.com/PalorderSoftWorksOfficial/EzAntiAntiCheat") { UseShellExecute = true });
        }

        private void btnHelp_Click(object sender, EventArgs e)
        {
            MessageBox.Show(
                "For best results, use AdvancedRun to launch EzAntiAntiCheat.exe as TrustedInstaller.\n" +
                "If you have issues, ensure Secure Boot is disabled and Test Signing is enabled.\n" +
                "Visit the GitHub repository for troubleshooting and updates.",
                "EzAntiAntiCheat Help", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}