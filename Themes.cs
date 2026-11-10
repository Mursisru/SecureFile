using System;
using System.Globalization;
using System.Linq;
using System.Windows.Media;

namespace SecureFile;

public sealed class ThemeInfo
{
    internal ThemeInfo(string id, string name, bool isDark, bool isNeon, double hue, ThemePalette palette)
    {
        Id = id;
        Name = name;
        IsDark = isDark;
        IsNeon = isNeon;
        Hue = hue;
        Palette = palette;
        PreviewBackground = ThemeCatalog.CreateBrush(palette.Background);
        PreviewPanel = ThemeCatalog.CreateBrush(palette.Panel);
        PreviewBorder = ThemeCatalog.CreateBrush(palette.Border);
        PreviewText = ThemeCatalog.CreateBrush(palette.Text);
        PreviewMuted = ThemeCatalog.CreateBrush(palette.Muted);
        PreviewAccent = ThemeCatalog.CreateBrush(palette.Accent);
    }

    public string Id { get; }
    public string Name { get; }
    public bool IsDark { get; }
    public bool IsNeon { get; }
    public double Hue { get; }
    public Brush PreviewBackground { get; }
    public Brush PreviewPanel { get; }
    public Brush PreviewBorder { get; }
    public Brush PreviewText { get; }
    public Brush PreviewMuted { get; }
    public Brush PreviewAccent { get; }
    internal ThemePalette Palette { get; }
}

internal readonly record struct ThemePalette(
    Color Background,
    Color Panel,
    Color Surface,
    Color Border,
    Color Text,
    Color Muted,
    Color Accent,
    Color AccentSoft,
    Color Overlay,
    Color Hover,
    Color Pressed);

public sealed class BackgroundChoice
{
    internal BackgroundChoice(string hex, Color color)
    {
        Hex = hex;
        Color = color;
        Brush = ThemeCatalog.CreateBrush(color);
    }

    public string Hex { get; }
    public Color Color { get; }
    public Brush Brush { get; }
    public bool IsDefault => string.IsNullOrEmpty(Hex);
}

internal static class ThemeCatalog
{
    private const string RegistryPath = @"Software\SecureFile";
    private const string RegistryValue = "Theme";

    public static readonly ThemeInfo[] All = Build();
    public static readonly ThemeInfo Default = All.First(theme => theme.Id == "dark-neon-cyan");
    public static readonly BackgroundChoice[] BackgroundChoices = BuildBackgroundChoices();

    public static ThemeInfo Find(string? id) =>
        All.FirstOrDefault(theme => theme.Id == id) ?? Default;

    public static ThemeInfo LoadSavedTheme() => Find(ReadSavedThemeId());

    private static string? ReadSavedThemeId()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegistryPath);
            return key?.GetValue(RegistryValue) as string;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static void Save(string id)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(RegistryPath);
            key?.SetValue(RegistryValue, id, Microsoft.Win32.RegistryValueKind.String);
        }
        catch (Exception)
        {
            // Theme persistence is best-effort.
        }
    }

    public static void Apply(ThemeInfo theme, string? backgroundOverride)
    {
        var palette = theme.Palette;
        var resources = System.Windows.Application.Current.Resources;

        resources["ThemeBackground"] = CreateBrush(palette.Background);
        resources["ThemePanel"] = CreateBrush(palette.Panel);
        resources["ThemeSurface"] = CreateBrush(palette.Surface);
        resources["ThemeBorder"] = CreateBrush(palette.Border);
        resources["ThemeText"] = CreateBrush(palette.Text);
        resources["ThemeMuted"] = CreateBrush(palette.Muted);
        resources["ThemeAccent"] = CreateBrush(palette.Accent);
        resources["ThemeAccentSoft"] = CreateBrush(palette.AccentSoft);
        resources["ThemeOverlay"] = CreateBrush(palette.Overlay);
        resources["ThemeHover"] = CreateBrush(palette.Hover);
        resources["ThemePressed"] = CreateBrush(palette.Pressed);
        resources["ThemeOnAccent"] = CreateBrush(OnAccent(palette.Accent));
        resources["ThemeSuccess"] = CreateBrush(theme.IsDark
            ? Color.FromRgb(0x7B, 0xD8, 0x8F)
            : Color.FromRgb(0x1B, 0x7A, 0x43));
        resources["ThemeError"] = CreateBrush(theme.IsDark
            ? Color.FromRgb(0xFF, 0x6B, 0x6B)
            : Color.FromRgb(0xC0, 0x39, 0x2B));

        if (TryParseColor(backgroundOverride, out var background))
            resources["ThemeBackground"] = CreateBrush(background);
    }

    public static bool TryParseColor(string? text, out Color color)
    {
        color = default;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var value = text.Trim();
        if (value.Length != 7 || value[0] != '#') return false;
        try
        {
            var r = byte.Parse(value.Substring(1, 2), NumberStyles.HexNumber);
            var g = byte.Parse(value.Substring(3, 2), NumberStyles.HexNumber);
            var b = byte.Parse(value.Substring(5, 2), NumberStyles.HexNumber);
            color = Color.FromRgb(r, g, b);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    internal static SolidColorBrush CreateBrush(Color color)
    {
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        return brush;
    }

    private static BackgroundChoice[] BuildBackgroundChoices()
    {
        var values = new (string Hex, string Fallback)[]
        {
            ("", "#0B1418"),
            ("#0B1418", "#0B1418"),
            ("#111014", "#111014"),
            ("#17110D", "#17110D"),
            ("#1A1024", "#1A1024"),
            ("#0E1A14", "#0E1A14"),
            ("#101820", "#101820"),
            ("#201410", "#201410"),
            ("#F4F1EA", "#F4F1EA"),
            ("#F7EFE6", "#F7EFE6"),
            ("#EEF3F8", "#EEF3F8"),
            ("#F6EEF6", "#F6EEF6"),
            ("#F0F4EF", "#F0F4EF"),
            ("#EFE9E1", "#EFE9E1"),
        };

        return values
            .Select(value =>
            {
                TryParseColor(value.Hex, out var color);
                if (value.Hex.Length == 0) TryParseColor(value.Fallback, out color);
                return new BackgroundChoice(value.Hex, color);
            })
            .ToArray();
    }

    private static ThemeInfo[] Build()
    {
        var definitions = new (string Id, string Name, bool Dark, bool Neon, double Hue, bool Coffee)[]
        {
            ("light-neon-lime", "Neon Lime", false, true, 88, false),
            ("light-neon-aqua", "Neon Aqua", false, true, 186, false),
            ("light-neon-magenta", "Neon Magenta", false, true, 316, false),
            ("light-neon-amber", "Neon Amber", false, true, 36, false),
            ("light-neon-coral", "Neon Coral", false, true, 14, false),
            ("light-neon-azure", "Neon Azure", false, true, 214, false),
            ("light-neon-emerald", "Neon Emerald", false, true, 158, false),
            ("light-neon-violet", "Neon Violet", false, true, 282, false),
            ("light-pastel-rose", "Pastel Rose", false, false, 344, false),
            ("light-pastel-peach", "Pastel Peach", false, false, 22, false),
            ("light-pastel-lemon", "Pastel Lemon", false, false, 50, false),
            ("light-pastel-mint", "Pastel Mint", false, false, 150, false),
            ("light-pastel-sky", "Pastel Sky", false, false, 204, false),
            ("light-pastel-lavender", "Pastel Lavender", false, false, 264, false),
            ("light-pastel-lilac", "Pastel Lilac", false, false, 292, false),
            ("light-pastel-sand", "Pastel Sand", false, false, 42, false),
            ("light-pastel-coffee", "Pastel Coffee", false, false, 28, true),
            ("light-pastel-sage", "Pastel Sage", false, false, 118, false),
            ("light-pastel-coral", "Pastel Coral", false, false, 8, false),
            ("light-pastel-ice", "Pastel Ice", false, false, 196, false),
            ("dark-neon-cyan", "Neon Cyan", true, true, 190, false),
            ("dark-neon-violet", "Neon Violet", true, true, 270, false),
            ("dark-neon-pink", "Neon Pink", true, true, 326, false),
            ("dark-neon-green", "Neon Green", true, true, 112, false),
            ("dark-neon-blue", "Neon Blue", true, true, 222, false),
            ("dark-neon-orange", "Neon Orange", true, true, 24, false),
            ("dark-neon-red", "Neon Red", true, true, 356, false),
            ("dark-neon-teal", "Neon Teal", true, true, 168, false),
            ("dark-pastel-rose", "Pastel Rose", true, false, 344, false),
            ("dark-pastel-peach", "Pastel Peach", true, false, 22, false),
            ("dark-pastel-gold", "Pastel Gold", true, false, 48, false),
            ("dark-pastel-mint", "Pastel Mint", true, false, 152, false),
            ("dark-pastel-sky", "Pastel Sky", true, false, 204, false),
            ("dark-pastel-lavender", "Pastel Lavender", true, false, 264, false),
            ("dark-pastel-orchid", "Pastel Orchid", true, false, 300, false),
            ("dark-pastel-sage", "Pastel Sage", true, false, 120, false),
            ("dark-pastel-coffee", "Pastel Coffee", true, false, 28, true),
            ("dark-pastel-steel", "Pastel Steel", true, false, 210, false),
            ("dark-pastel-wine", "Pastel Wine", true, false, 340, false),
            ("dark-pastel-moss", "Pastel Moss", true, false, 90, false),
        };

        return definitions
            .Select(definition => new ThemeInfo(
                definition.Id,
                definition.Name,
                definition.Dark,
                definition.Neon,
                definition.Hue,
                definition.Coffee
                    ? BuildCoffee(definition.Dark)
                    : BuildPalette(definition.Dark, definition.Neon, definition.Hue)))
            .ToArray();
    }

    private static ThemePalette BuildCoffee(bool isDark)
    {
        if (isDark)
        {
            return new ThemePalette(
                Background: Rgb(0x17, 0x11, 0x0D),
                Panel: Rgb(0x21, 0x18, 0x12),
                Surface: Rgb(0x2B, 0x20, 0x18),
                Border: Rgb(0x4A, 0x37, 0x28),
                Text: Rgb(0xF5, 0xE9, 0xDC),
                Muted: Rgb(0xB7, 0xA0, 0x8B),
                Accent: Rgb(0xD0, 0x8A, 0x4E),
                AccentSoft: Color.FromArgb(0x40, 0xD0, 0x8A, 0x4E),
                Overlay: Color.FromArgb(0xD9, 0, 0, 0),
                Hover: Rgb(0x2A, 0x1E, 0x16),
                Pressed: Rgb(0x34, 0x26, 0x1C));
        }

        return new ThemePalette(
            Background: Rgb(0xF6, 0xEE, 0xE4),
            Panel: Rgb(0xFF, 0xFB, 0xF5),
            Surface: Rgb(0xEF, 0xE2, 0xD3),
            Border: Rgb(0xD9, 0xC4, 0xAE),
            Text: Rgb(0x2F, 0x22, 0x18),
            Muted: Rgb(0x7B, 0x65, 0x53),
            Accent: Rgb(0x8A, 0x5A, 0x34),
            AccentSoft: Color.FromArgb(0x24, 0x8A, 0x5A, 0x34),
            Overlay: Color.FromArgb(0x66, 0x0C, 0x0A, 0x10),
            Hover: Rgb(0xEF, 0xE0, 0xCF),
            Pressed: Rgb(0xE7, 0xD5, 0xC0));
    }

    private static ThemePalette BuildPalette(bool isDark, bool isNeon, double hue)
    {
        if (isDark)
        {
            var tint = isNeon ? 0.34 : 0.20;
            var accent = Hsl(hue, isNeon ? 0.92 : 0.62, isNeon ? 0.62 : 0.78);
            return new ThemePalette(
                Background: Hsl(hue, tint, 0.065),
                Panel: Hsl(hue, tint * 0.85, 0.105),
                Surface: Hsl(hue, tint * 0.80, 0.15),
                Border: Hsl(hue, tint * 0.85, 0.25),
                Text: Hsl(hue, isNeon ? 0.14 : 0.10, 0.95),
                Muted: Hsl(hue, 0.10, 0.64),
                Accent: accent,
                AccentSoft: WithAlpha(accent, 0x30),
                Overlay: Color.FromArgb(0xD9, 0, 0, 0),
                Hover: Hsl(hue, tint * 0.85, 0.19),
                Pressed: Hsl(hue, tint * 0.85, 0.24));
        }

        var lightAccent = BuildLightAccent(hue, isNeon);
        return new ThemePalette(
            Background: Hsl(hue, 0.58, 0.965),
            Panel: Hsl(hue, 0.35, 0.995),
            Surface: Hsl(hue, 0.50, 0.925),
            Border: Hsl(hue, 0.34, 0.83),
            Text: Hsl(hue, isNeon ? 0.30 : 0.22, 0.16),
            Muted: Hsl(hue, 0.13, 0.42),
            Accent: lightAccent,
            AccentSoft: WithAlpha(lightAccent, 0x24),
            Overlay: Color.FromArgb(0x66, 0x0C, 0x0A, 0x10),
            Hover: Hsl(hue, 0.45, 0.90),
            Pressed: Hsl(hue, 0.45, 0.84));
    }

    private static Color BuildLightAccent(double hue, bool isNeon)
    {
        var saturation = isNeon ? 0.95 : 0.62;
        var lightness = isNeon ? 0.40 : 0.44;
        var panel = Hsl(hue, 0.35, 0.995);
        var accent = Hsl(hue, saturation, lightness);

        while (Contrast(accent, panel) < 3.1 && lightness > 0.16)
        {
            lightness -= 0.02;
            accent = Hsl(hue, saturation, lightness);
        }

        return accent;
    }

    private static Color Rgb(byte r, byte g, byte b) => Color.FromRgb(r, g, b);

    private static double Contrast(Color first, Color second)
    {
        var a = Luminance(first);
        var b = Luminance(second);
        return (Math.Max(a, b) + 0.05) / (Math.Min(a, b) + 0.05);
    }

    private static double Luminance(Color color)
    {
        static double Channel(byte value)
        {
            var s = value / 255.0;
            return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
        }

        return 0.2126 * Channel(color.R) + 0.7152 * Channel(color.G) + 0.0722 * Channel(color.B);
    }

    private static Color OnAccent(Color accent)
    {
        var luminance = (0.2126 * accent.R + 0.7152 * accent.G + 0.0722 * accent.B) / 255.0;
        return luminance > 0.58
            ? Color.FromRgb(0x10, 0x12, 0x16)
            : Colors.White;
    }

    private static Color WithAlpha(Color color, byte alpha) =>
        Color.FromArgb(alpha, color.R, color.G, color.B);

    private static Color Hsl(double hue, double saturation, double lightness)
    {
        hue = ((hue % 360) + 360) % 360 / 360.0;
        saturation = Math.Clamp(saturation, 0, 1);
        lightness = Math.Clamp(lightness, 0, 1);

        if (saturation <= 0)
        {
            var gray = ToByte(lightness);
            return Color.FromRgb(gray, gray, gray);
        }

        var q = lightness < 0.5
            ? lightness * (1 + saturation)
            : lightness + saturation - lightness * saturation;
        var p = 2 * lightness - q;

        return Color.FromRgb(
            ToByte(HueToRgb(p, q, hue + 1.0 / 3)),
            ToByte(HueToRgb(p, q, hue)),
            ToByte(HueToRgb(p, q, hue - 1.0 / 3)));
    }

    private static double HueToRgb(double p, double q, double t)
    {
        if (t < 0) t += 1;
        if (t > 1) t -= 1;
        if (t < 1.0 / 6) return p + (q - p) * 6 * t;
        if (t < 1.0 / 2) return q;
        if (t < 2.0 / 3) return p + (q - p) * (2.0 / 3 - t) * 6;
        return p;
    }

    private static byte ToByte(double value) =>
        (byte)Math.Round(Math.Clamp(value, 0, 1) * 255);
}
