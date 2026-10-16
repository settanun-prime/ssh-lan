using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;

[assembly: AssemblyTitle("SSH LAN Prime Studio")]
[assembly: AssemblyDescription("SSH LAN Prime Studio Desktop Launcher")]
[assembly: AssemblyCompany("Prime Studio")]
[assembly: AssemblyProduct("SSH LAN Prime Studio")]
[assembly: AssemblyCopyright("Copyright (c) 2026")]
[assembly: ComVisible(false)]

internal static class Launcher {
    [STAThread]
    private static void Main(string[] args) {
        try {
            string root = AppDomain.CurrentDomain.BaseDirectory;
            string script = Path.Combine(root, "scripts", "app.ps1");
            if (!File.Exists(script)) throw new IOException("Extract the complete SSH LAN Prime Studio folder before opening the app.");
            var start = new ProcessStartInfo {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
                Arguments = "-NoProfile -STA -File \"" + script + "\"",
                WorkingDirectory = root,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            start.EnvironmentVariables.Remove("PSModulePath");
            start.EnvironmentVariables["PSExecutionPolicyPreference"] = "Bypass";
            if (args.Length > 0 && args[0] == "--data-dir" && args.Length > 1) {
                string data = Path.GetFullPath(args[1]);
                start.EnvironmentVariables["SSH_LAN_DATA_DIR"] = data;
            }
            Process.Start(start);
        } catch (Exception error) {
            MessageBox.Show(error.Message, "SSH LAN Prime Studio", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
