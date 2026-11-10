using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

namespace SecureFile;

public partial class MainWindow : Window
{
    private const string HashName = "MasterHash";
    private const string StaticSalt = "Sf#2026!xK9mQ";

    private readonly AppSettings _settings;
    private readonly ObservableCollection<FileEntry> _encryptFiles = new();
    private readonly ObservableCollection<FileEntry> _decryptFiles = new();
    private readonly Queue<AppRequest> _requestQueue = new();
    private readonly List<Button> _swatchButtons = new();

    private bool _busy;
    private bool _loadingUi;
    private bool _queueRunning;
    private CancellationTokenSource? _cts;
    private TaskCompletionSource<string?>? _passwordCompletion;
    private Func<string, string?>? _passwordValidator;
    private ThemeInfo _currentTheme;
    private ViewKind _currentView = ViewKind.Home;
    private bool _isDarkMode;

    internal MainWindow(AppRequest request)
    {
        _settings = AppSettings.Load();
        Loc.SetLanguage(_settings.Language);
        _currentTheme = ThemeCatalog.Find(_settings.ThemeId);
        _isDarkMode = _currentTheme.IsDark;
        ThemeCatalog.Apply(_currentTheme, _settings.BackgroundColor);
        InitializeComponent();

        EncryptList.ItemsSource = _encryptFiles;
        DecryptList.ItemsSource = _decryptFiles;
        _encryptFiles.CollectionChanged += (_, _) => UpdateEmptyStates();
        _decryptFiles.CollectionChanged += (_, _) => UpdateEmptyStates();

        _loadingUi = true;
        ApplyLanguage();
        LoadSettingsIntoUi();
        _loadingUi = false;

        RefreshProtectionStatus();
        ShowView(ViewKind.Home);
        UpdateEmptyStates();

        if (request.Action != AppAction.Activate && request.Path is not null)
        {
            _requestQueue.Enqueue(request);
            Loaded += (_, _) => ProcessQueue();
        }
    }

    private void ApplyLanguage()
    {
        Title = "SecureFile";
        NavHome.Content = "🏠 " + Loc.T("nav.home");
        NavEncrypt.Content = "🔒 " + Loc.T("nav.encrypt");
        NavDecrypt.Content = "🔓 " + Loc.T("nav.decrypt");
        NavSettings.Content = "⚙ " + Loc.T("nav.settings");
        NavProtection.Content = "🛡 " + Loc.T("nav.protection");

        HomeTitle.Text = Loc.T("home.title");
        HomeSubtitle.Text = Loc.T("home.subtitle");
        HomeEncryptTitle.Text = Loc.T("home.encrypt.title");
        HomeEncryptText.Text = Loc.T("home.encrypt.text");
        HomeDecryptTitle.Text = Loc.T("home.decrypt.title");
        HomeDecryptText.Text = Loc.T("home.decrypt.text");
        HomeDropHint.Text = Loc.T("home.drop");

        EncryptTitle.Text = Loc.T("encrypt.title");
        EncryptSubtitle.Text = Loc.T("encrypt.subtitle");
        EncryptDropHint.Text = Loc.T("encrypt.dropHint");
        EncryptEmptyText.Text = Loc.T("encrypt.empty");
        EncryptAddButton.Content = Loc.T("encrypt.add");
        EncryptAddFolderButton.Content = Loc.T("encrypt.addFolder");
        EncryptClearButton.Content = Loc.T("encrypt.clear");
        EncryptActionButton.Content = Loc.T("encrypt.action");

        DecryptTitle.Text = Loc.T("decrypt.title");
        DecryptSubtitle.Text = Loc.T("decrypt.subtitle");
        DecryptDropHint.Text = Loc.T("decrypt.dropHint");
        DecryptEmptyText.Text = Loc.T("decrypt.empty");
        DecryptAddButton.Content = Loc.T("decrypt.add");
        DecryptAddFolderButton.Content = Loc.T("encrypt.addFolder");
        DecryptClearButton.Content = Loc.T("decrypt.clear");
        DecryptActionButton.Content = Loc.T("decrypt.action");

        SettingsTitle.Text = Loc.T("settings.title");
        SettingsSubtitle.Text = Loc.T("settings.subtitle");
        SettingsAppearanceTitle.Text = Loc.T("settings.appearance");
        SettingsAppearanceText.Text = Loc.T("settings.appearance.text");
        LightModeButton.Content = "☀ " + Loc.T("settings.light");
        DarkModeButton.Content = "🌙 " + Loc.T("settings.dark");
        BackgroundLabel.Text = Loc.T("settings.background");
        SettingsSecurityTitle.Text = Loc.T("settings.security");
        SettingsSecurityText.Text = Loc.T("settings.security.text");
        SettingsMethodLabel.Text = Loc.T("settings.method");
        FastMethodName.Text = Loc.T("method.fast.name");
        FastMethodDesc.Text = Loc.T("method.fast.desc");
        MediumMethodName.Text = Loc.T("method.medium.name");
        MediumMethodDesc.Text = Loc.T("method.medium.desc");
        MaxMethodName.Text = Loc.T("method.max.name");
        MaxMethodDesc.Text = Loc.T("method.max.desc");
        KeyFileTitle.Text = Loc.T("settings.keyfile");
        KeyFileCreateButton.Content = Loc.T("settings.keyfile.create");
        KeyFileSelectButton.Content = Loc.T("settings.keyfile.select");
        KeyFileClearButton.Content = Loc.T("settings.keyfile.clear");
        KeyFileNote.Text = Loc.T("settings.keyfile.note");
        SecureDeleteCheck.Content = Loc.T("settings.secureDelete");
        SecureDeleteNote.Text = Loc.T("settings.secureDelete.note");
        VerifyCheck.Content = Loc.T("settings.verify");
        VerifyNote.Text = Loc.T("settings.verify.note");
        SettingsLanguageTitle.Text = Loc.T("settings.language");
        SettingsCloseButton.Content = Loc.T("settings.close");

        ProtectionTitle.Text = Loc.T("protection.title");
        ChangePasswordButton.Content = Loc.T("protection.change");
        CloseProtectionButton.Content = Loc.T("protection.close");
        PasswordTitle.Text = Loc.T("password.title");
        PasswordOkButton.Content = Loc.T("password.ok");
        PasswordCancelButton.Content = Loc.T("password.cancel");
        CancelButton.Content = Loc.T("password.cancel");

        UpdateMethodBadge();
        UpdateThemeSummary();
        UpdateKeyFileUi();
        UpdateLanguageButtons();
        RefreshProtectionStatus();
        foreach (var entry in _encryptFiles) entry.Refresh();
        foreach (var entry in _decryptFiles) entry.Refresh();
        if (!_busy) StatusText.Text = Loc.T("status.idle");
    }

    private void LoadSettingsIntoUi()
    {
        SyncMethodRadios(_settings.Method);
        SecureDeleteCheck.IsChecked = _settings.SecureDelete;
        VerifyCheck.IsChecked = _settings.Verify;
        ShowThemeMode(_isDarkMode);
        BuildBackgroundSwatches();
        UpdateSwatchSelection();
        UpdateKeyFileUi();
        UpdateLanguageButtons();
        UpdateMethodBadge();
    }

    private void ShowThemeMode(bool isDark)
    {
        _isDarkMode = isDark;
        var themes = ThemeCatalog.All.Where(theme => theme.IsDark == isDark).ToList();
        ThemeList.ItemsSource = themes;
        ThemeList.SelectedItem = themes.FirstOrDefault(theme => theme.Id == _currentTheme.Id);
        ThemeSummaryText.Text = Loc.F("settings.themesCount", themes.Count);
        UpdateModeButtons(isDark);
    }

    private void UpdateThemeSummary()
    {
        var count = ThemeCatalog.All.Count(theme => theme.IsDark == _isDarkMode);
        ThemeSummaryText.Text = Loc.F("settings.themesCount", count);
    }

    private void ThemeList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ThemeList.SelectedItem is not ThemeInfo theme) return;
        if (theme.Id != _currentTheme.Id)
        {
            _currentTheme = theme;
            ThemeCatalog.Apply(theme, _settings.BackgroundColor);
            ThemeCatalog.Save(theme.Id);
            _settings.ThemeId = theme.Id;
            _settings.Save();
            UpdateSwatchSelection();
        }
        UpdateModeButtons(theme.IsDark);
    }

    private void LightMode_Click(object sender, RoutedEventArgs e) => ShowThemeMode(isDark: false);

    private void DarkMode_Click(object sender, RoutedEventArgs e) => ShowThemeMode(isDark: true);

    private void UpdateModeButtons(bool isDark)
    {
        var accent = (Brush)Application.Current.Resources["ThemeAccent"];
        var accentSoft = (Brush)Application.Current.Resources["ThemeAccentSoft"];
        var muted = (Brush)Application.Current.Resources["ThemeMuted"];
        var text = (Brush)Application.Current.Resources["ThemeText"];
        var border = (Brush)Application.Current.Resources["ThemeBorder"];

        LightModeButton.Background = isDark ? Brushes.Transparent : accentSoft;
        LightModeButton.Foreground = isDark ? muted : text;
        LightModeButton.BorderBrush = isDark ? border : accent;
        DarkModeButton.Background = isDark ? accentSoft : Brushes.Transparent;
        DarkModeButton.Foreground = isDark ? text : muted;
        DarkModeButton.BorderBrush = isDark ? accent : border;
    }

    private void BuildBackgroundSwatches()
    {
        BackgroundSwatchPanel.Children.Clear();
        _swatchButtons.Clear();
        var style = (Style)FindResource("SwatchButton");

        foreach (var choice in ThemeCatalog.BackgroundChoices)
        {
            var inner = new Border
            {
                Background = choice.Brush,
                CornerRadius = new CornerRadius(6),
            };
            var button = new Button
            {
                Style = style,
                Tag = choice.Hex,
                Content = inner,
                ToolTip = choice.IsDefault ? Loc.T("settings.background.default") : choice.Hex,
            };
            button.Click += BackgroundSwatch_Click;
            BackgroundSwatchPanel.Children.Add(button);
            _swatchButtons.Add(button);
        }
    }

    private void BackgroundSwatch_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button button) return;
        var hex = button.Tag as string;
        _settings.BackgroundColor = string.IsNullOrWhiteSpace(hex) ? null : hex;
        _settings.Save();
        ThemeCatalog.Apply(_currentTheme, _settings.BackgroundColor);
        UpdateSwatchSelection();
    }

    private void UpdateSwatchSelection()
    {
        var accent = (Brush)Application.Current.Resources["ThemeAccent"];
        var current = _settings.BackgroundColor ?? string.Empty;
        foreach (var button in _swatchButtons)
        {
            var selected = string.Equals(button.Tag as string, current, StringComparison.OrdinalIgnoreCase);
            button.BorderBrush = selected ? accent : Brushes.Transparent;
        }
    }

    private void Method_Checked(object sender, RoutedEventArgs e) => SelectMethod(sender);

    private void EncryptMethod_Checked(object sender, RoutedEventArgs e) => SelectMethod(sender);

    private void SelectMethod(object sender)
    {
        if (_loadingUi) return;
        if (sender is not RadioButton { Tag: string tag } || !Enum.TryParse<EncryptionMethod>(tag, out var method)) return;
        _settings.Method = method;
        _settings.Save();
        SyncMethodRadios(method);
        UpdateMethodBadge();
    }

    private void SyncMethodRadios(EncryptionMethod method)
    {
        var previous = _loadingUi;
        _loadingUi = true;
        FastMethodRadio.IsChecked = method == EncryptionMethod.Fast;
        MediumMethodRadio.IsChecked = method == EncryptionMethod.Medium;
        MaxMethodRadio.IsChecked = method == EncryptionMethod.Maximum;
        EncryptFastPill.IsChecked = method == EncryptionMethod.Fast;
        EncryptMediumPill.IsChecked = method == EncryptionMethod.Medium;
        EncryptMaxPill.IsChecked = method == EncryptionMethod.Maximum;
        _loadingUi = previous;
    }

    private void UpdateMethodBadge() =>
        EncryptMethodBadge.Text = Loc.F("badge.method", Loc.T(MethodNameKey(_settings.Method)));

    private static string MethodNameKey(EncryptionMethod method) => method switch
    {
        EncryptionMethod.Fast => "method.fast.name",
        EncryptionMethod.Maximum => "method.max.name",
        _ => "method.medium.name",
    };

    private void Option_Changed(object sender, RoutedEventArgs e)
    {
        if (_loadingUi) return;
        _settings.SecureDelete = SecureDeleteCheck.IsChecked == true;
        _settings.Verify = VerifyCheck.IsChecked == true;
        _settings.Save();
    }

    private void Language_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string language }) return;
        _settings.Language = language;
        _settings.Save();
        Loc.SetLanguage(language);
        ApplyLanguage();
        ExplorerIntegration.Register();
        UpdateLanguageButtons();
    }

    private void UpdateLanguageButtons()
    {
        var pairs = new (Button Button, string Code)[]
        {
            (LangEnButton, "en"),
            (LangRuButton, "ru"),
            (LangDeButton, "de"),
            (LangEsButton, "es"),
        };
        var accent = (Brush)Application.Current.Resources["ThemeAccent"];
        var accentSoft = (Brush)Application.Current.Resources["ThemeAccentSoft"];
        var panel = (Brush)Application.Current.Resources["ThemePanel"];
        var border = (Brush)Application.Current.Resources["ThemeBorder"];
        var text = (Brush)Application.Current.Resources["ThemeText"];
        var muted = (Brush)Application.Current.Resources["ThemeMuted"];

        foreach (var (button, code) in pairs)
        {
            var active = _settings.Language == code;
            button.Background = active ? accentSoft : panel;
            button.BorderBrush = active ? accent : border;
            button.Foreground = active ? text : muted;
        }
    }

    private void UpdateKeyFileUi()
    {
        var path = _settings.KeyFilePath;
        if (string.IsNullOrWhiteSpace(path))
        {
            KeyFileText.Text = Loc.T("settings.keyfile.none");
            KeyFileText.SetResourceReference(TextBlock.ForegroundProperty, "ThemeMuted");
            KeyFileClearButton.IsEnabled = false;
            return;
        }

        if (!File.Exists(path))
        {
            KeyFileText.Text = Loc.F("settings.keyfile.missing", Path.GetFileName(path));
            KeyFileText.SetResourceReference(TextBlock.ForegroundProperty, "ThemeError");
            KeyFileClearButton.IsEnabled = true;
            return;
        }

        KeyFileText.Text = Loc.F("settings.keyfile.active", Path.GetFileName(path));
        KeyFileText.SetResourceReference(TextBlock.ForegroundProperty, "ThemeSuccess");
        KeyFileClearButton.IsEnabled = true;
    }

    private void ShowSettingsMessage(string text, bool success)
    {
        SettingsMessageText.Text = text;
        SettingsMessageText.SetResourceReference(TextBlock.ForegroundProperty,
            success ? "ThemeSuccess" : "ThemeError");
        SettingsMessageText.Visibility = Visibility.Visible;
    }

    private void ShowView(ViewKind view)
    {
        _currentView = view;
        HomeView.Visibility = view == ViewKind.Home ? Visibility.Visible : Visibility.Collapsed;
        EncryptView.Visibility = view == ViewKind.Encrypt ? Visibility.Visible : Visibility.Collapsed;
        DecryptView.Visibility = view == ViewKind.Decrypt ? Visibility.Visible : Visibility.Collapsed;
        UpdateNavState();
        if (!_busy) StatusText.Text = Loc.T("status.idle");
    }

    private void UpdateNavState()
    {
        var accentSoft = (Brush)Application.Current.Resources["ThemeAccentSoft"];
        var muted = (Brush)Application.Current.Resources["ThemeMuted"];
        var text = (Brush)Application.Current.Resources["ThemeText"];

        void Set(Button button, bool active)
        {
            button.Background = active ? accentSoft : Brushes.Transparent;
            button.Foreground = active ? text : muted;
        }

        Set(NavHome, _currentView == ViewKind.Home);
        Set(NavEncrypt, _currentView == ViewKind.Encrypt);
        Set(NavDecrypt, _currentView == ViewKind.Decrypt);
    }

    private void UpdateEmptyStates()
    {
        EncryptEmptyText.Visibility = _encryptFiles.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        DecryptEmptyText.Visibility = _decryptFiles.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowHome_Click(object sender, RoutedEventArgs e) => ShowView(ViewKind.Home);

    private void ShowEncrypt_Click(object sender, RoutedEventArgs e) => ShowView(ViewKind.Encrypt);

    private void ShowDecrypt_Click(object sender, RoutedEventArgs e) => ShowView(ViewKind.Decrypt);

    private void SettingsToggle_Click(object sender, RoutedEventArgs e)
    {
        ProtectionOverlay.Visibility = Visibility.Collapsed;
        SettingsMessageText.Visibility = Visibility.Collapsed;
        ShowThemeMode(_currentTheme.IsDark);
        BuildBackgroundSwatches();
        UpdateSwatchSelection();
        UpdateKeyFileUi();
        SettingsOverlay.Visibility = Visibility.Visible;
        Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(() => ThemeList.Focus()));
    }

    private void CloseSettings_Click(object sender, RoutedEventArgs e) =>
        SettingsOverlay.Visibility = Visibility.Collapsed;

    private void ProtectionToggle_Click(object sender, RoutedEventArgs e)
    {
        SettingsOverlay.Visibility = Visibility.Collapsed;
        RefreshProtectionStatus();
        ProtectionMessageText.Visibility = Visibility.Collapsed;
        ProtectionOverlay.Visibility = Visibility.Visible;
    }

    private void CloseProtection_Click(object sender, RoutedEventArgs e) =>
        ProtectionOverlay.Visibility = Visibility.Collapsed;

    private void KeyFileCreate_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = Loc.T("dialog.keySave"),
            Filter = Loc.T("filter.key"),
            FileName = Loc.T("dialog.keyDefault") + "-" + Guid.NewGuid().ToString("N")[..8] + ".sfkey",
            DefaultExt = ".sfkey",
            AddExtension = true,
        };
        if (dialog.ShowDialog() != true) return;

        if (!KeyStore.TryCreateKeyFile(dialog.FileName))
        {
            ShowSettingsMessage(Loc.T("notice.keyInvalid"), false);
            return;
        }

        _settings.KeyFilePath = dialog.FileName;
        _settings.Save();
        UpdateKeyFileUi();
        RefreshProtectionStatus();
        ShowSettingsMessage(Loc.F("notice.keyCreated", dialog.FileName), true);
    }

    private void KeyFileSelect_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = Loc.T("dialog.keyOpen"),
            Filter = Loc.T("filter.key"),
        };
        if (dialog.ShowDialog() != true) return;

        if (KeyStore.TryReadKeyFileSecret(dialog.FileName) is null)
        {
            ShowSettingsMessage(Loc.T("notice.keyInvalid"), false);
            return;
        }

        _settings.KeyFilePath = dialog.FileName;
        _settings.Save();
        UpdateKeyFileUi();
        RefreshProtectionStatus();
        ShowSettingsMessage(Loc.F("notice.keySelected", dialog.FileName), true);
    }

    private void KeyFileClear_Click(object sender, RoutedEventArgs e)
    {
        _settings.KeyFilePath = null;
        _settings.Save();
        UpdateKeyFileUi();
        RefreshProtectionStatus();
        ShowSettingsMessage(Loc.T("notice.keyCleared"), true);
    }

    private void ChooseEncrypt_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = Loc.T("dialog.chooseEncrypt"),
            Filter = Loc.T("filter.all"),
            Multiselect = true,
        };
        if (dialog.ShowDialog() != true) return;

        AddFiles(_encryptFiles, dialog.FileNames.Where(path => !CryptoEngine.IsContainerPath(path)));
        ShowView(ViewKind.Encrypt);
    }

    private void ChooseEncryptFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = Loc.T("dialog.chooseFolder") };
        if (dialog.ShowDialog() != true) return;

        AddFiles(_encryptFiles, ExpandPaths(new[] { dialog.FolderName }, forEncrypt: true));
        ShowView(ViewKind.Encrypt);
    }

    private void ChooseDecrypt_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = Loc.T("dialog.chooseDecrypt"),
            Filter = Loc.T("filter.encrypted"),
            Multiselect = true,
        };
        if (dialog.ShowDialog() != true) return;

        AddFiles(_decryptFiles, dialog.FileNames.Where(CryptoEngine.IsContainerPath));
        ShowView(ViewKind.Decrypt);
    }

    private void ChooseDecryptFolder_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = Loc.T("dialog.chooseFolder") };
        if (dialog.ShowDialog() != true) return;

        AddFiles(_decryptFiles, ExpandPaths(new[] { dialog.FolderName }, forEncrypt: false));
        ShowView(ViewKind.Decrypt);
    }

    private void ClearEncrypt_Click(object sender, RoutedEventArgs e)
    {
        _encryptFiles.Clear();
        UpdateEmptyStates();
    }

    private void ClearDecrypt_Click(object sender, RoutedEventArgs e)
    {
        _decryptFiles.Clear();
        UpdateEmptyStates();
    }

    private void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = !_busy && e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (_busy) return;
        if (e.Data.GetData(DataFormats.FileDrop) is not string[] paths || paths.Length == 0) return;

        var containers = ExpandPaths(paths, forEncrypt: false);
        var plain = ExpandPaths(paths, forEncrypt: true);
        var decrypt = _currentView == ViewKind.Decrypt || (containers.Count > 0 && plain.Count == 0);

        if (decrypt)
        {
            AddFiles(_decryptFiles, containers);
            ShowView(ViewKind.Decrypt);
        }
        else
        {
            AddFiles(_encryptFiles, plain);
            ShowView(ViewKind.Encrypt);
        }
        e.Handled = true;
    }

    private static void AddFiles(ObservableCollection<FileEntry> target, IEnumerable<string> paths)
    {
        var known = new HashSet<string>(target.Select(entry => entry.Path), StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths)
        {
            if (known.Add(path)) target.Add(new FileEntry(path));
        }
    }

    private static List<string> ExpandPaths(IEnumerable<string> roots, bool forEncrypt)
    {
        var results = new List<string>();
        foreach (var root in roots)
        {
            if (File.Exists(root))
            {
                if (forEncrypt ? !CryptoEngine.IsContainerPath(root) : CryptoEngine.IsContainerPath(root))
                    results.Add(root);
                continue;
            }

            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    if (forEncrypt ? !CryptoEngine.IsContainerPath(file) : CryptoEngine.IsContainerPath(file))
                        results.Add(file);
                    if (results.Count >= 5000) return results;
                }
            }
            catch (Exception)
            {
                // Unreadable folders are skipped; accessible files still get added.
            }
        }
        return results;
    }

    private void ProcessQueue()
    {
        _ = ProcessQueueAsync();
    }

    private async Task ProcessQueueAsync()
    {
        if (_busy || _queueRunning) return;
        _queueRunning = true;
        try
        {
            while (_requestQueue.Count > 0)
            {
                var request = _requestQueue.Dequeue();
                if (request.Path is null) continue;

                if (request.Action == AppAction.Encrypt)
                {
                    AddFiles(_encryptFiles, ExpandPaths(new[] { request.Path }, forEncrypt: true));
                    ShowView(ViewKind.Encrypt);
                    await RunEncryptAsync();
                }
                else if (request.Action == AppAction.Decrypt)
                {
                    AddFiles(_decryptFiles, ExpandPaths(new[] { request.Path }, forEncrypt: false));
                    ShowView(ViewKind.Decrypt);
                    await RunDecryptAsync();
                }
            }
        }
        finally
        {
            _queueRunning = false;
            if (_requestQueue.Count > 0 && !_busy) ProcessQueue();
        }
    }

    internal void HandleExternalRequest(AppRequest request)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(new Action(() => HandleExternalRequest(request)));
            return;
        }

        RestoreAndActivate();
        if (request.Action == AppAction.Activate) return;
        if (request.Path is null) return;

        if (_passwordCompletion is not null)
            CompletePasswordPrompt(null);

        SettingsOverlay.Visibility = Visibility.Collapsed;
        ProtectionOverlay.Visibility = Visibility.Collapsed;
        _requestQueue.Enqueue(request);
        ProcessQueue();
    }

    private void RestoreAndActivate()
    {
        if (!IsVisible) Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
        Topmost = true;
        Topmost = false;
        Focus();
    }

    private async void Encrypt_Click(object sender, RoutedEventArgs e) => await RunEncryptAsync();

    private async void Decrypt_Click(object sender, RoutedEventArgs e) => await RunDecryptAsync();

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        if (_passwordCompletion is not null) CompletePasswordPrompt(null);
    }

    private byte[]? ResolveKeyFileKey()
    {
        if (!string.IsNullOrWhiteSpace(_settings.KeyFilePath))
        {
            var fromFile = KeyStore.TryReadKeyFileBytes(_settings.KeyFilePath);
            if (fromFile is null)
                throw new InvalidOperationException(
                    Loc.F("notice.keyMissing", Path.GetFileName(_settings.KeyFilePath)));
            return fromFile;
        }

        return null;
    }

    private async Task RunEncryptAsync()
    {
        if (_busy) return;
        var entries = _encryptFiles.ToList();
        if (entries.Count == 0)
        {
            ShowNotice(Loc.T("notice.noFiles"), false);
            return;
        }

        byte[]? keyFileKey;
        try
        {
            keyFileKey = ResolveKeyFileKey();
        }
        catch (Exception ex)
        {
            ShowNotice(ex.Message, false);
            return;
        }

        var method = _settings.Method;
        var count = entries.Count;
        var succeeded = 0;
        var failed = 0;
        var cancelled = false;
        string? lastOutput = null;

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        NoticeText.Visibility = Visibility.Collapsed;
        SetBusy(true, Loc.T("status.encrypting"));

        try
        {
            for (var index = 0; index < entries.Count; index++)
            {
                if (token.IsCancellationRequested)
                {
                    cancelled = true;
                    break;
                }

                var entry = entries[index];
                if (CryptoEngine.IsContainerPath(entry.Path))
                {
                    entry.SetStatus("status.skipped");
                    continue;
                }

                entry.SetStatus("status.encrypting");
                var current = index;
                var progress = new Progress<double>(value => ReportProgress(current, count, entry.Name, value));
                string? producedPath = null;
                try
                {
                    var outputPath = await CryptoEngine.EncryptAsync(entry.Path, method, keyFileKey, progress, token);
                    producedPath = outputPath;

                    if (_settings.Verify)
                    {
                        entry.SetStatus("status.verifying");
                        if (!await CryptoEngine.VerifyRoundTripAsync(entry.Path, outputPath, keyFileKey, token))
                        {
                            TryDeleteFile(outputPath);
                            throw new CryptographicException(Loc.F("notice.verifyFailed", entry.Name));
                        }
                    }

                    if (_settings.SecureDelete) await Task.Run(() => CryptoEngine.SecureDelete(entry.Path));

                    entry.SetStatus("status.done");
                    ReportProgress(current, count, entry.Name, 1);
                    succeeded++;
                    lastOutput = Path.GetFileName(outputPath);
                }
                catch (OperationCanceledException)
                {
                    if (producedPath is not null) TryDeleteFile(producedPath);
                    entry.SetStatus("status.cancelled");
                    cancelled = true;
                    break;
                }
                catch (Exception ex)
                {
                    entry.SetStatus(Loc.T("status.error") + ": " + ex.Message);
                    failed++;
                }
            }
        }
        finally
        {
            SetBusy(false, null);
            _cts.Dispose();
            _cts = null;
        }

        if (cancelled) ShowNotice(Loc.T("notice.cancelled"), false);
        else if (failed > 0) ShowNotice(Loc.F("notice.partial", failed, succeeded), false);
        else if (succeeded == 1 && lastOutput is not null) ShowNotice(Loc.F("notice.encryptDoneOne", lastOutput), true);
        else ShowNotice(Loc.F("notice.encryptDone", succeeded), true);

        if (_requestQueue.Count > 0 && !_busy) ProcessQueue();
    }

    private async Task RunDecryptAsync()
    {
        if (_busy) return;
        var entries = _decryptFiles.ToList();
        if (entries.Count == 0)
        {
            ShowNotice(Loc.T("notice.noFiles"), false);
            return;
        }

        var secrets = new List<string>();
        var keyFileKey = KeyStore.TryReadKeyFileBytes(_settings.KeyFilePath);
        var keyFileSecret = keyFileKey is null ? null : Convert.ToBase64String(keyFileKey);
        if (keyFileSecret is not null) secrets.Add(keyFileSecret);
        if (KeyStore.TryGetFileKey() is { } fileKey) secrets.Add(Convert.ToBase64String(fileKey));

        var keyBoundPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var machineBoundPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var hasContainers = false;
        var hasLegacyFiles = false;
        foreach (var entry in entries)
        {
            if (!CryptoEngine.IsContainerPath(entry.Path)) continue;
            hasContainers = true;
            var kind = await CryptoEngine.GetContainerKindAsync(entry.Path, CancellationToken.None);
            if (kind == ContainerKind.KeyBound)
                keyBoundPaths.Add(entry.Path);
            else if (kind == ContainerKind.MachineBound)
                machineBoundPaths.Add(entry.Path);
            else if (kind == ContainerKind.Legacy)
                hasLegacyFiles = true;
        }

        var hasCustomPassword = ReadMasterHash() is not null;
        var passwordRequested = false;
        var passwordCancelled = false;

        async Task<bool> EnsurePasswordAsync()
        {
            if (passwordRequested) return false;
            passwordRequested = true;
            var password = await PromptPasswordAsync(
                Loc.T("password.title"), Loc.T("password.enter"), ValidateActivePassword);
            if (password is null)
            {
                passwordCancelled = true;
                return false;
            }
            secrets.Add(password);
            return true;
        }

        if (keyFileSecret is null)
        {
            if (!string.IsNullOrWhiteSpace(_settings.KeyFilePath) && hasLegacyFiles)
                ShowNotice(Loc.F("notice.keyMissingDecrypt", Path.GetFileName(_settings.KeyFilePath)), false);

            if (hasContainers && hasCustomPassword && !await EnsurePasswordAsync())
            {
                ShowNotice(Loc.T("notice.cancelled"), false);
                return;
            }
        }

        var count = entries.Count;
        var succeeded = 0;
        var failed = 0;
        var crossDeviceFailed = 0;
        var cancelled = false;
        string? lastOutput = null;

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        NoticeText.Visibility = Visibility.Collapsed;
        SetBusy(true, Loc.T("status.decrypting"));

        try
        {
            for (var index = 0; index < entries.Count; index++)
            {
                if (token.IsCancellationRequested)
                {
                    cancelled = true;
                    break;
                }

                var entry = entries[index];
                if (!CryptoEngine.IsContainerPath(entry.Path))
                {
                    entry.SetStatus("status.skipped");
                    continue;
                }

                entry.SetStatus("status.decrypting");
                var current = index;
                DecryptResult? result = null;
                var crossDevice = false;

                try
                {
                    while (true)
                    {
                        var progress = new Progress<double>(value => ReportProgress(current, count, entry.Name, value));
                        try
                        {
                            result = await CryptoEngine.DecryptAsync(
                                entry.Path, secrets, keyFileKey, progress, token, _settings.Verify);
                            break;
                        }
                        catch (CrossDeviceException)
                        {
                            crossDevice = true;
                            break;
                        }
                        catch (CryptographicException)
                        {
                            if (keyBoundPaths.Contains(entry.Path) ||
                                machineBoundPaths.Contains(entry.Path) ||
                                !hasCustomPassword ||
                                !await EnsurePasswordAsync())
                                break;
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    entry.SetStatus("status.cancelled");
                    cancelled = true;
                    break;
                }
                catch (Exception ex)
                {
                    entry.SetStatus(Loc.T("status.error") + ": " + ex.Message);
                    failed++;
                    continue;
                }

                if (result is null)
                {
                    if (crossDevice)
                    {
                        entry.SetStatus("status.otherDevice");
                        crossDeviceFailed++;
                        failed++;
                        continue;
                    }

                    if (passwordCancelled)
                    {
                        entry.SetStatus("status.cancelled");
                        cancelled = true;
                        break;
                    }

                    entry.SetStatus("status.error");
                    failed++;
                    continue;
                }

                entry.SetStatus("status.done");
                ReportProgress(current, count, entry.Name, 1);
                succeeded++;
                lastOutput = Path.GetFileName(result.OutputPath);
            }
        }
        finally
        {
            SetBusy(false, null);
            _cts.Dispose();
            _cts = null;
        }

        if (cancelled) ShowNotice(Loc.T("notice.cancelled"), false);
        else if (failed > 0 && succeeded == 0 && crossDeviceFailed == failed)
            ShowNotice(Loc.T("notice.otherDevice"), false);
        else if (failed > 0) ShowNotice(Loc.F("notice.partial", failed, succeeded), false);
        else if (succeeded == 1 && lastOutput is not null) ShowNotice(Loc.F("notice.decryptDoneOne", lastOutput), true);
        else ShowNotice(Loc.F("notice.decryptDone", succeeded), true);

        if (_requestQueue.Count > 0 && !_busy) ProcessQueue();
    }

    private void ReportProgress(int index, int count, string name, double fileProgress)
    {
        var overall = count <= 0 ? 0 : (index + Math.Clamp(fileProgress, 0, 1)) / count;
        OperationProgress.Value = Math.Clamp(overall * 100, 0, 100);
        ProgressText.Text = $"{name} · {overall:P0}";
    }

    private void SetBusy(bool busy, string? status)
    {
        _busy = busy;
        HomeView.IsEnabled = !busy;
        EncryptView.IsEnabled = !busy;
        DecryptView.IsEnabled = !busy;
        NavHome.IsEnabled = !busy;
        NavEncrypt.IsEnabled = !busy;
        NavDecrypt.IsEnabled = !busy;
        NavSettings.IsEnabled = !busy;
        NavProtection.IsEnabled = !busy;

        ProgressPanel.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        CancelButton.IsEnabled = busy;
        if (busy)
        {
            OperationProgress.Value = 0;
            ProgressText.Text = string.Empty;
            StatusText.Text = status ?? Loc.T("status.working");
        }
        else
        {
            OperationProgress.Value = 0;
            ProgressText.Text = string.Empty;
            StatusText.Text = Loc.T("status.idle");
        }
    }

    private void ShowNotice(string text, bool success)
    {
        NoticeText.Text = text;
        NoticeText.SetResourceReference(TextBlock.ForegroundProperty,
            success ? "ThemeSuccess" : "ThemeError");
        NoticeText.Visibility = Visibility.Visible;
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch (Exception)
        {
            // Cleanup is best-effort.
        }
    }

    private Task<string?> PromptPasswordAsync(string title, string prompt, Func<string, string?>? validator)
    {
        if (_passwordCompletion is not null) CompletePasswordPrompt(null);

        _passwordValidator = validator;
        PasswordTitle.Text = title;
        PasswordPromptText.Text = prompt;
        PasswordPromptBox.Password = string.Empty;
        PasswordPromptError.Visibility = Visibility.Collapsed;
        PasswordOverlay.Visibility = Visibility.Visible;
        _passwordCompletion = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
        Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(() => PasswordPromptBox.Focus()));
        return _passwordCompletion.Task;
    }

    private void PasswordPromptOk_Click(object sender, RoutedEventArgs e)
    {
        var password = PasswordPromptBox.Password;
        var error = _passwordValidator?.Invoke(password);
        if (error is not null)
        {
            PasswordPromptError.Text = error;
            PasswordPromptError.Visibility = Visibility.Visible;
            PasswordPromptBox.SelectAll();
            PasswordPromptBox.Focus();
            return;
        }

        CompletePasswordPrompt(password);
    }

    private void PasswordPromptCancel_Click(object sender, RoutedEventArgs e) =>
        CompletePasswordPrompt(null);

    private void CompletePasswordPrompt(string? result)
    {
        PasswordOverlay.Visibility = Visibility.Collapsed;
        PasswordPromptBox.Password = string.Empty;
        PasswordPromptError.Visibility = Visibility.Collapsed;
        _passwordValidator = null;

        var completion = _passwordCompletion;
        _passwordCompletion = null;
        completion?.TrySetResult(result);
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (PasswordOverlay.Visibility == Visibility.Visible)
        {
            if (e.Key == Key.Enter)
            {
                PasswordPromptOk_Click(this, new RoutedEventArgs());
                e.Handled = true;
            }
            else if (e.Key == Key.Escape)
            {
                CompletePasswordPrompt(null);
                e.Handled = true;
            }
            return;
        }

        if (e.Key != Key.Escape) return;
        if (SettingsOverlay.Visibility == Visibility.Visible)
        {
            SettingsOverlay.Visibility = Visibility.Collapsed;
            e.Handled = true;
        }
        else if (ProtectionOverlay.Visibility == Visibility.Visible)
        {
            ProtectionOverlay.Visibility = Visibility.Collapsed;
            e.Handled = true;
        }
    }

    private async void ChangePassword_Click(object sender, RoutedEventArgs e)
    {
        ProtectionMessageText.Visibility = Visibility.Collapsed;

        if (ReadMasterHash() is not null)
        {
            var current = await PromptPasswordAsync(
                Loc.T("protection.title"), Loc.T("password.current"), ValidateChangePassword);
            if (current is null) return;
        }

        var fresh = await PromptPasswordAsync(
            Loc.T("protection.title"), Loc.T("password.new"),
            value => string.IsNullOrEmpty(value) ? Loc.T("password.newEmpty") : null);
        if (fresh is null) return;

        var confirm = await PromptPasswordAsync(
            Loc.T("protection.title"), Loc.T("password.confirm"),
            value => value == fresh ? null : Loc.T("password.mismatch"));
        if (confirm is null) return;

        if (!WriteMasterHash(fresh))
        {
            ProtectionMessageText.Text = Loc.F("protection.updateFailed", Loc.T("error.registry"));
            ProtectionMessageText.SetResourceReference(TextBlock.ForegroundProperty, "ThemeError");
            ProtectionMessageText.Visibility = Visibility.Visible;
            return;
        }

        RefreshProtectionStatus();
        ProtectionMessageText.Text = Loc.T("protection.updated");
        ProtectionMessageText.SetResourceReference(TextBlock.ForegroundProperty, "ThemeSuccess");
        ProtectionMessageText.Visibility = Visibility.Visible;
    }

    private void RefreshProtectionStatus()
    {
        var hasCustom = ReadMasterHash() is not null;
        var status = Loc.T(hasCustom ? "protection.custom" : "protection.none");
        status += Environment.NewLine + Loc.F("protection.device", MachineKey.ShortId);

        if (!string.IsNullOrWhiteSpace(_settings.KeyFilePath))
        {
            var keyName = Path.GetFileName(_settings.KeyFilePath);
            status += Environment.NewLine + Loc.F("protection.keyfile", keyName);
        }

        ProtectionStatusText.Text = status;
    }

    private static string? ReadMasterHash()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\SecureFile");
            return key?.GetValue(HashName) as string;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static string HashPassword(string password) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(password + StaticSalt)));

    private static bool MatchesHash(string password, string storedHash)
    {
        byte[] stored;
        try
        {
            stored = Convert.FromBase64String(storedHash);
        }
        catch (FormatException)
        {
            return false;
        }

        var candidate = SHA256.HashData(Encoding.UTF8.GetBytes(password + StaticSalt));
        return stored.Length == candidate.Length &&
               CryptographicOperations.FixedTimeEquals(stored, candidate);
    }

    private static string? ValidateActivePassword(string password)
    {
        var stored = ReadMasterHash();
        if (stored is null) return Loc.T("password.incorrect");
        return MatchesHash(password, stored) ? null : Loc.T("password.incorrect");
    }

    private static string? ValidateChangePassword(string password)
    {
        var stored = ReadMasterHash();
        if (stored is null) return null;
        return MatchesHash(password, stored) ? null : Loc.T("password.currentWrong");
    }

    private static bool WriteMasterHash(string password)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(@"Software\SecureFile");
            if (key is null) return false;
            key.SetValue(HashName, HashPassword(password), RegistryValueKind.String);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
}

internal enum ViewKind
{
    Home,
    Encrypt,
    Decrypt,
}

public sealed class FileEntry : INotifyPropertyChanged
{
    private string _status = "status.waiting";

    public FileEntry(string path) => Path = path;

    public string Path { get; }

    public string Name => System.IO.Path.GetFileName(Path);

    public string Status => _status.StartsWith("status.", StringComparison.Ordinal)
        ? Loc.T(_status)
        : _status;

    public void SetStatus(string keyOrText)
    {
        if (_status == keyOrText) return;
        _status = keyOrText;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Status)));
    }

    public void Refresh() =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Status)));

    public event PropertyChangedEventHandler? PropertyChanged;
}
