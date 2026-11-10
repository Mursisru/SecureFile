using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Windows;

namespace SecureFile;

public partial class App : Application
{
    private const string MutexName = @"Local\SecureFile.SingleInstance";
    private static readonly string PipeName =
        $"SecureFile.Instance.{Process.GetCurrentProcess().SessionId}";

    private Mutex? _instanceMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var request = AppRequest.FromArguments(e.Args);

        var isFirstInstance = true;
        try
        {
            _instanceMutex = new Mutex(initiallyOwned: true, MutexName, out isFirstInstance);
        }
        catch (Exception)
        {
            // If the mutex cannot be created, keep the app usable rather than blocking startup.
            isFirstInstance = true;
        }

        if (!isFirstInstance)
        {
            SingleInstance.Send(request);
            Shutdown();
            return;
        }

        Loc.SetLanguage(AppSettings.Load().Language);
        MachineKey.Initialize();
        ExplorerIntegration.Register();

        var window = new SecureFile.MainWindow(request);
        MainWindow = window;
        SingleInstance.Listen(window.HandleExternalRequest);
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _instanceMutex?.Dispose();
        base.OnExit(e);
    }

    private static class SingleInstance
    {
        public static void Listen(Action<AppRequest> onRequest)
        {
            // Try to create the first pipe synchronously so a second instance
            // launched right after startup can connect without a race.
            NamedPipeServerStream? server = null;
            for (var attempt = 0; attempt < 10 && server is null; attempt++)
            {
                try { server = CreateServer(); }
                catch (Exception) { Thread.Sleep(100); }
            }

            var thread = new Thread(() => ListenLoop(server, onRequest))
            {
                IsBackground = true,
                Name = "SecureFile single-instance listener",
            };
            thread.Start();
        }

        public static bool Send(AppRequest request)
        {
            for (var attempt = 0; attempt < 20; attempt++)
            {
                try
                {
                    using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out, PipeOptions.None);
                    client.Connect(250);
                    using var writer = new StreamWriter(
                        client, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
                    {
                        AutoFlush = true,
                    };
                    writer.WriteLine(request.ToMessage());
                    return true;
                }
                catch (Exception)
                {
                    Thread.Sleep(100);
                }
            }

            return false;
        }

        private static NamedPipeServerStream CreateServer() =>
            new(PipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.None);

        private static void ListenLoop(NamedPipeServerStream? server, Action<AppRequest> onRequest)
        {
            while (true)
            {
                try
                {
                    server ??= CreateServerWithRetry();
                    server.WaitForConnection();

                    string? line;
                    using (var reader = new StreamReader(
                        server, Encoding.UTF8, detectEncodingFromByteOrderMarks: false,
                        bufferSize: 1024, leaveOpen: true))
                    {
                        line = reader.ReadLine();
                    }

                    server.Dispose();
                    server = CreateServerWithRetry();

                    var request = AppRequest.ParseMessage(line);
                    Application.Current?.Dispatcher.BeginInvoke(new Action(() => onRequest(request)));
                }
                catch (Exception)
                {
                    try { server?.Dispose(); } catch { }
                    server = null;
                    Thread.Sleep(200);
                }
            }
        }

        private static NamedPipeServerStream CreateServerWithRetry()
        {
            while (true)
            {
                try { return CreateServer(); }
                catch (Exception) { Thread.Sleep(250); }
            }
        }
    }
}

internal enum AppAction
{
    Activate,
    Encrypt,
    Decrypt,
}

internal sealed record AppRequest(AppAction Action, string? Path)
{
    public static AppRequest FromArguments(string[] args)
    {
        if (args.Length >= 2 && args[0].Equals("--encrypt", StringComparison.OrdinalIgnoreCase))
            return new AppRequest(AppAction.Encrypt, args[1]);

        if (args.Length >= 2 && args[0].Equals("--decrypt", StringComparison.OrdinalIgnoreCase))
            return new AppRequest(AppAction.Decrypt, args[1]);

        if (args.Length >= 1 && !string.IsNullOrWhiteSpace(args[0]) && !args[0].StartsWith("--", StringComparison.Ordinal))
        {
            var path = args[0];
            if (Directory.Exists(path)) return new AppRequest(AppAction.Encrypt, path);
            return CryptoEngine.IsContainerPath(path)
                ? new AppRequest(AppAction.Decrypt, path)
                : new AppRequest(AppAction.Encrypt, path);
        }

        return new AppRequest(AppAction.Activate, null);
    }

    public string ToMessage() => Action switch
    {
        AppAction.Encrypt when Path is not null => "E|" + Path,
        AppAction.Decrypt when Path is not null => "D|" + Path,
        _ => "A|",
    };

    public static AppRequest ParseMessage(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return new AppRequest(AppAction.Activate, null);

        var text = line.Trim();
        if (text.Length >= 2 && text[1] == '|')
        {
            var path = text.Length > 2 ? text[2..] : null;
            return text[0] switch
            {
                'E' when path is not null => new AppRequest(AppAction.Encrypt, path),
                'D' when path is not null => new AppRequest(AppAction.Decrypt, path),
                _ => new AppRequest(AppAction.Activate, null),
            };
        }

        // Messages from older builds carried only a file path.
        return CryptoEngine.IsContainerPath(text)
            ? new AppRequest(AppAction.Decrypt, text)
            : new AppRequest(AppAction.Encrypt, text);
    }
}
