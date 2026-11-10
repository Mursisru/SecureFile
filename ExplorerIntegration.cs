using System;
using Microsoft.Win32;

namespace SecureFile;

internal static class ExplorerIntegration
{
    public static void Register()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe)) return;

            using var classes = Registry.CurrentUser.CreateSubKey(@"Software\Classes");
            if (classes is null) return;

            RegisterProgid(classes, ".secf", "SecureFile.secf", exe);
            RegisterProgid(classes, ".secf1", "SecureFile.secf1", exe);
            RegisterProgid(classes, ".secf1v2", "SecureFile.secf1v2", exe);

            using (var app = classes.CreateSubKey(@"Applications\SecureFile.exe"))
            {
                if (app is null) return;
                app.SetValue("FriendlyAppName", "SecureFile");
                using (var command = app.CreateSubKey(@"shell\open\command"))
                    command?.SetValue(null, $"\"{exe}\" \"%1\"");
                using var types = app.CreateSubKey("SupportedTypes");
                types?.SetValue(".secf", string.Empty);
                types?.SetValue(".secf1", string.Empty);
                types?.SetValue(".secf1v2", string.Empty);
            }

            const string encrypted = "System.FileExtension:=.secf OR System.FileExtension:=.secf1 OR System.FileExtension:=.secf1v2";
            const string plain = "NOT System.FileExtension:=.secf AND NOT System.FileExtension:=.secf1 AND NOT System.FileExtension:=.secf1v2";

            RegisterVerb(classes, @"*\shell\SecureFile.Encrypt", Loc.T("verb.encrypt"), plain, exe, "--encrypt");
            RegisterVerb(classes, @"*\shell\SecureFile.Decrypt", Loc.T("verb.decrypt"), encrypted, exe, "--decrypt");
            RegisterVerb(classes, @"Directory\shell\SecureFile.Encrypt", Loc.T("verb.folder"), null, exe, "--encrypt");
        }
        catch (Exception)
        {
            // Shell integration is best-effort; the app remains fully usable without it.
        }
    }

    private static void RegisterProgid(RegistryKey classes, string extension, string progId, string exe)
    {
        using (var ext = classes.CreateSubKey(extension))
        {
            if (ext is null) return;
            ext.SetValue(null, progId);
            using var openWith = ext.CreateSubKey("OpenWithProgids");
            openWith?.SetValue(progId, string.Empty);
        }

        using var prog = classes.CreateSubKey(progId);
        if (prog is null) return;
        prog.SetValue(null, "SecureFile encrypted file");
        using (var icon = prog.CreateSubKey("DefaultIcon"))
            icon?.SetValue(null, $"\"{exe}\",0");
        using var command = prog.CreateSubKey(@"shell\open\command");
        command?.SetValue(null, $"\"{exe}\" \"%1\"");
    }

    private static void RegisterVerb(
        RegistryKey classes,
        string path,
        string label,
        string? appliesTo,
        string exe,
        string argument)
    {
        using var verb = classes.CreateSubKey(path);
        if (verb is null) return;
        verb.SetValue(null, label);
        if (!string.IsNullOrWhiteSpace(appliesTo)) verb.SetValue("AppliesTo", appliesTo);
        verb.SetValue("Icon", $"\"{exe}\",0");
        using var command = verb.CreateSubKey("command");
        command?.SetValue(null, $"\"{exe}\" {argument} \"%1\"");
    }
}
