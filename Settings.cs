using System;
using System.Globalization;
using Microsoft.Win32;

namespace SecureFile;

internal enum EncryptionMethod
{
    Fast,
    Medium,
    Maximum,
}

internal sealed class AppSettings
{
    private const string RegPath = @"Software\SecureFile";

    public static AppSettings Current { get; private set; } = new();

    public string ThemeId { get; set; } = "dark-neon-cyan";
    public string Language { get; set; } = DefaultLanguage();
    public EncryptionMethod Method { get; set; } = EncryptionMethod.Medium;
    public string? KeyFilePath { get; set; }
    public bool SecureDelete { get; set; }
    public bool Verify { get; set; }
    public string? BackgroundColor { get; set; }

    public static AppSettings Load()
    {
        var settings = new AppSettings();
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RegPath);
            if (key is not null)
            {
                if (key.GetValue("Theme") is string theme && !string.IsNullOrWhiteSpace(theme))
                    settings.ThemeId = theme;
                if (key.GetValue("Language") is string language && Loc.IsSupported(language))
                    settings.Language = Loc.Normalize(language);
                if (key.GetValue("Method") is string method &&
                    Enum.TryParse<EncryptionMethod>(method, ignoreCase: true, out var parsed))
                    settings.Method = parsed;
                if (key.GetValue("KeyFile") is string keyFile && !string.IsNullOrWhiteSpace(keyFile))
                    settings.KeyFilePath = keyFile;
                if (key.GetValue("SecureDelete") is int secureDelete)
                    settings.SecureDelete = secureDelete != 0;
                if (key.GetValue("Verify") is int verify)
                    settings.Verify = verify != 0;
                if (key.GetValue("Background") is string background && !string.IsNullOrWhiteSpace(background))
                    settings.BackgroundColor = background;
            }
        }
        catch (Exception)
        {
            // Unreadable settings fall back to defaults.
        }

        Current = settings;
        return settings;
    }

    public void Save()
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RegPath);
            if (key is null) return;
            key.SetValue("Theme", ThemeId, RegistryValueKind.String);
            key.SetValue("Language", Language, RegistryValueKind.String);
            key.SetValue("Method", Method.ToString(), RegistryValueKind.String);
            key.SetValue("SecureDelete", SecureDelete ? 1 : 0, RegistryValueKind.DWord);
            key.SetValue("Verify", Verify ? 1 : 0, RegistryValueKind.DWord);

            if (string.IsNullOrWhiteSpace(KeyFilePath)) key.DeleteValue("KeyFile", throwOnMissingValue: false);
            else key.SetValue("KeyFile", KeyFilePath, RegistryValueKind.String);

            if (string.IsNullOrWhiteSpace(BackgroundColor)) key.DeleteValue("Background", throwOnMissingValue: false);
            else key.SetValue("Background", BackgroundColor, RegistryValueKind.String);
        }
        catch (Exception)
        {
            // Persistence is best-effort; the app keeps the values for this session.
        }
    }

    private static string DefaultLanguage()
    {
        var language = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.ToLowerInvariant();
        return Loc.IsSupported(language) ? language : "en";
    }
}
