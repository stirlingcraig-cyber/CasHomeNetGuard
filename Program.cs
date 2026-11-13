using CasHomeNetGuard.Core;
using CasHomeNetGuard.UI;

namespace CasHomeNetGuard;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        using var mutex = new Mutex(true, @"Global\CAS.HomeNetGuard.SingleInstance", out bool first);
        if (!first)
        {
            MessageBox.Show("CAS HomeNet Guard is already running – look for the shield icon in the system tray.",
                "CAS HomeNet Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => EngineLog.Write("UI", "Unhandled: " + e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) => EngineLog.Write("FATAL", e.ExceptionObject.ToString() ?? "");

        AppPaths.Ensure();
        var settings = Settings.Load();
        bool hidden = args.Contains("--tray", StringComparer.OrdinalIgnoreCase) && settings.StartMinimised;

        using var engine = new GuardEngine(settings);
        engine.Start();
        Application.Run(new MainForm(engine, hidden));
    }
}
