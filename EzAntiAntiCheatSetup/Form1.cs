using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace EzAntiAntiCheatSetup
{
    /// <summary>
    /// Main setup wizard form for EzAntiAntiCheat. Provides instructions and quick access buttons
    /// for downloading required tools, opening the program folder, and accessing help resources.
    /// </summary>
    public class Form1 : Form
    {
        private TextBox instructionsTextBox;
        private Button btnAdvancedRun;
        private Button btnExecTI;
        private Button btnOpenEzAnti;
        private Button btnHelp;

        /// <summary>
        /// Initializes a new instance of the <see cref="Form1"/> class.
        /// </summary>
        public Form1()
        {
            InitializeComponent();
            SetupUi();
        }

        private void InitializeComponent()
        {
            this.Text = "EzAntiAntiCheat Setup Wizard";
            this.Width = 600;
            this.Height = 500;
        }

        private void SetupUi()
        {
            instructionsTextBox = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Dock = DockStyle.Top,
                Height = 320,
                Font = new Font("Segoe UI", 10),
                Text =
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
https://palordersoftworksofficial.github.io/EzAntiAntiCheat"
            };
            this.Controls.Add(instructionsTextBox);

            int topOffset = instructionsTextBox.Bottom + 10;

            btnAdvancedRun = new Button
            {
                Text = "Open AdvancedRun Download",
                Top = topOffset,
                Left = 20,
                Width = 200
            };
            btnAdvancedRun.Click += BtnAdvancedRun_Click;
            this.Controls.Add(btnAdvancedRun);

            btnExecTI = new Button
            {
                Text = "Open ExecTI Download",
                Top = topOffset,
                Left = btnAdvancedRun.Right + 10,
                Width = 200
            };
            btnExecTI.Click += BtnExecTI_Click;
            this.Controls.Add(btnExecTI);

            btnOpenEzAnti = new Button
            {
                Text = "Open Install Folder",
                Top = btnAdvancedRun.Bottom + 10,
                Left = 20,
                Width = 200
            };
            btnOpenEzAnti.Click += BtnOpenEzAnti_Click;
            this.Controls.Add(btnOpenEzAnti);

            btnHelp = new Button
            {
                Text = "Help / Website",
                Top = btnAdvancedRun.Bottom + 10,
                Left = btnOpenEzAnti.Right + 10,
                Width = 200
            };
            btnHelp.Click += BtnHelp_Click;
            this.Controls.Add(btnHelp);
        }

        private void BtnAdvancedRun_Click(object sender, EventArgs e)
        {
            Process.Start(new ProcessStartInfo("https://www.nirsoft.net/utils/advanced_run.html") { UseShellExecute = true });
        }

        private void BtnExecTI_Click(object sender, EventArgs e)
        {
            Process.Start(new ProcessStartInfo("https://winaero.com/run-programs-trustedinstaller-windows/") { UseShellExecute = true });
        }

        private void BtnOpenEzAnti_Click(object sender, EventArgs e)
        {
            Process.Start(new ProcessStartInfo(System.IO.Path.GetDirectoryName(Application.ExecutablePath)) { UseShellExecute = true });
        }

        private void BtnHelp_Click(object sender, EventArgs e)
        {
            Process.Start(new ProcessStartInfo("https://palordersoftworksofficial.github.io/EzAntiAntiCheat") { UseShellExecute = true });
            MessageBox.Show(
                "For best results, use AdvancedRun to launch EzAntiAntiCheat-x64-Release.exe (for example.) as TrustedInstaller.\n" +
                "If you have issues, ensure Secure Boot is disabled and Test Signing is enabled.\n" +
                "Visit the GitHub repository for troubleshooting and updates.",
                "EzAntiAntiCheat Help", MessageBoxButtons.OK, MessageBoxIcon.Information);
            
        }
    }
}
