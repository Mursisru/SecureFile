# SecureFile

Flat single-window WPF app (net8.0-windows) for AES-256 file encryption. No NuGet packages, tests, lint, or formatter scripts.

## Build and run
- `dotnet build` from the repo root is the only verification step; run `dotnet run` to launch.
- Build output is localized (Russian); still match `error CSxxxx` / `error MCxxxx`.
- Keep the flat structure: root-level files only; no folders, ViewModels, services, or extra windows.

## Files
- `MainWindow.xaml` / `MainWindow.xaml.cs` — all views, overlays, UI events, batch operations, master-password logic.
- `CryptoEngine.cs` — formats, encrypt/decrypt, verification, secure delete, legacy key store.
- `MachineKey.cs` — hardware-derived 256-bit device key and short device ID.
- `Settings.cs` — `AppSettings`, `EncryptionMethod`, registry persistence.
- `Localization.cs` — `Loc` strings for `en`, `ru`, `de`, `es`.
- `Themes.cs` — `ThemeCatalog` (40 palettes) and `BackgroundChoice` swatches.
- `ExplorerIntegration.cs` — file associations and context-menu verbs.
- `App.xaml.cs` — single instance, named pipe, `AppRequest`, startup registration.

## Architecture
- `MainWindow.xaml` holds Home, Encrypt, and Decrypt as switchable `Visibility` panels, plus `SettingsOverlay`, `ProtectionOverlay`, and `PasswordOverlay`.
- The Encrypt header has compact `.secf` / `.secf1` / `.secf1v2` radio pills. `SelectMethod` keeps them in sync with the Settings method cards in both directions and persists `Method`.
- Batch lists are `ObservableCollection<FileEntry>`; statuses are localization keys (`status.*`). The footer shows progress and Cancel. `SetBusy` disables views and navigation but leaves Cancel active. `PasswordOverlay` sits outside `RootGrid`, so password prompts still work during an operation.
- Password entry is the in-app `PasswordOverlay` (`PromptPasswordAsync` + `TaskCompletionSource`), never a second `Window` and never a `MessageBox`. Results appear in `NoticeText`.
- `App.OnStartup` loads settings, applies the language, registers shell integration, enforces a single instance, converts arguments into an `AppRequest`, and creates `MainWindow`. `--encrypt <path>` / `--decrypt <path>` and bare files/folders work; a second launch forwards `E|path`, `D|path`, or `A|` over the `SecureFile.Instance.<session-id>` pipe. `HandleExternalRequest` restores the window, cancels any password prompt, and queues the request while `_busy`.
- Themes: `ThemeCatalog` builds 40 HSL palettes — 20 light and 20 dark, each with 8 neon + 12 pastel variants, including separate light/dark coffee palettes. `SettingsOverlay` shows the 20 palettes for the chosen mode. Selection applies immediately and persists to `HKCU\Software\SecureFile\Theme`; the saved theme is applied before `InitializeComponent`.
- `Background` overrides only `ThemeBackground` from 14 swatches (including "same as theme") and is stored in `HKCU\Software\SecureFile\Background`.
- Every UI color is a `DynamicResource` (`ThemeBackground`, `ThemePanel`, `ThemeSurface`, `ThemeBorder`, `ThemeText`, `ThemeMuted`, `ThemeAccent`, `ThemeAccentSoft`, `ThemeOverlay`, `ThemeHover`, `ThemePressed`, `ThemeOnAccent`, `ThemeSuccess`, `ThemeError`). Never hardcode a color.
- WPF `Button` has no `CornerRadius`; rounding comes from the `ActionButton` ControlTemplate Border.
- `icon.ico` is both `ApplicationIcon` and a `Resource` used by `Window.Icon`.

## Encryption methods
- **Fast** — `.secf`: AES-256-CBC, PKCS7, PBKDF2-HMAC-SHA256 with 1,000 iterations, 32-byte key. No authentication.
- **Medium** — `.secf1`: the same CBC layout with 10,000 iterations. Compatible with older files.
- **Maximum** — `.secf1v2`: AES-256-CBC + HMAC-SHA256 encrypt-then-MAC, PBKDF2 with 200,000 iterations producing 64 bytes (first 32 = AES key, last 32 = HMAC key). Layout: `[SFV2][version=1][iterations BE][salt 16][IV 16][ciphertext][HMAC 32]`; the tag covers header + ciphertext.
- CBC containers are `[salt 16][IV 16][ciphertext]`, no metadata. The reader detects `SFV2` by magic; CBC decryption tries 10,000 iterations, then 1,000.
- **Machine-bound containers** — encryption without a key file writes `SFM1`: `[SFM1][version=1][method 1][machineId 16][iterations BE][salt 16][IV 16][ciphertext][HMAC 32 only for Maximum]` (58-byte header). `machineId` is the first 16 bytes of SHA-256(device key). The payload secret is the device key; Maximum's tag covers the header + ciphertext. Decryption checks the machine ID before decrypting and throws `CrossDeviceException` when it does not match, so files moved to another PC are rejected even if the old `0021` fallback is known.
- **Key-bound containers** — when a key file is active, all three methods write `SFK1` version 2: `[SFK1][version=2][method 1][keyId 16][machineId 16][wrapIterations BE][wrapSalt 16][wrapIV 16][wrappedKey 48][wrapTag 32][payloadIterations BE][payloadSalt 16][payloadIV 16][ciphertext][HMAC 32 only for Maximum]` (190-byte header). `keyId` is the first 16 bytes of SHA-256(raw 32-byte key file). The raw key is wrapped with PBKDF2(device key, 100,000) + AES-256-CBC + HMAC-SHA256; the payload uses the selected method's layout with the key file as the secret. A matching key file on another device decrypts the file (portable); without it, the machine ID must match or `CrossDeviceException` is thrown. `SFK1` v1 (174-byte header) still unwraps with `0021`; legacy `SFV2` and CBC containers remain readable.
- **Device key** — `MachineKey` derives 32 bytes with PBKDF2-HMAC-SHA256 (100,000 iterations, salt `SecureFile.DeviceKey.v1`) from `MachineGuid`, the system volume serial, BIOS registry values, and CPU registry values. It is deterministic across app deletion/reinstall on the same PC; this is best-effort hardware binding, not a secret from a local administrator. `App.OnStartup` calls `MachineKey.Initialize()`; the Protection overlay shows `MachineKey.ShortId` (first 4 bytes of SHA-256(device key) as hex). `SECUREFILE_TEST` exposes `MachineKey.TestKey` for the temporary harness only.
- Encryption never asks for a password: it uses the configured key file, otherwise the device key. A configured but unreadable key file aborts encryption.
- Decryption never prompts for `SFM1` or `SFK1` v2. For legacy CBC/`SFV2` files it prompts only when a custom `MasterHash` exists; it tries the key file (if any), the legacy per-user `FileKey`, and the entered password. If `KeyFile` is configured but missing, encryption refuses, while legacy decryption warns and may prompt.
- Key files are raw 32-byte `.sfkey` files; they are portable between machines. Losing a key file still leaves same-PC decryption possible because the container embeds a device-key-wrapped copy.
- `MasterHash` = Base64(SHA-256(password + `Sf#2026!xK9mQ`)); the `0021` fallback is no longer a master password or shown in the UI. Setting a password for the first time skips the current-password prompt. Changing the master password does not affect the device key or key files.
- `SecureDelete` overwrites the original with zeros before deleting it (best effort; SSDs may not guarantee it).
- `Verify` decrypts the produced container again to a temp file and compares SHA-256. If verification fails, the output is deleted. Cancellation during verification also deletes the produced output/temp file.
- Write to `*.tmp`, then `File.Move(..., overwrite: true)`; delete the temp file on failure or cancellation so partial output is never left behind.
- Encryption writes `<original-name><extension>` preserving the original extension. Decryption restores that path and deletes the container; legacy `<name>.secf1` files fall back to `<name>.dec`.

## File association and Explorer verbs
- On startup the app registers `HKCU\Software\Classes\.secf`, `.secf1`, `.secf1v2` → their ProgIDs, plus `OpenWithProgids` and `Applications\SecureFile.exe`, all pointing at `Environment.ProcessPath`.
- It registers `*\shell\SecureFile.Encrypt` (label `verb.encrypt`, `AppliesTo = NOT System.FileExtension:=.secf AND NOT ...`, command `--encrypt "%1"`), `*\shell\SecureFile.Decrypt` (label `verb.decrypt`, `AppliesTo` container extensions, command `--decrypt "%1"`), and `Directory\shell\SecureFile.Encrypt` (label `verb.folder`, `--encrypt "%1"`).
- Verb labels are localized with `Loc`; `App.OnStartup` applies the saved language before registering, and changing the language re-registers the verbs.
- These are legacy static verbs; Windows 11 shows them under "Show more options". A top-level Windows 11 menu needs a signed MSIX/sparse package with package identity, which is intentionally not used.
- Registration is best-effort; registry failures are swallowed so the app still starts.

## Gotchas
- Keep the window `MinHeight` at 570 or higher so the settings overlay is not clipped.
- WPF's default disabled `ListBox` template paints a white system background. File lists use `FileListStyle`; do not switch them back to a default `ListBox` style.
- Light-theme accents are auto-darkened in `BuildLightAccent` until they reach 3:1 contrast against the panel. Don't hand-pick pastel accents that bypass that check.
- Encrypting an existing container is skipped/rejected so the source cannot overwrite itself.
- `FileKey` is a legacy per-Windows-user secret kept only for decrypting old files; new files never use it. `SFM1` files are bound to the PC; `SFK1` v2 files are portable with the matching key file. Legacy password-encrypted files still need their original password.
- `SFM1`/`SFK1` v2 ignore the master password and `FileKey`. The decrypt flow pre-scans containers with `GetContainerKindAsync`; key-bound/machine-bound lists never open the password overlay. `CrossDeviceException` maps to `status.otherDevice` / `notice.otherDevice`.
- `MachineKey.Id` must be derived from the current `Key` on every call so the `SECUREFILE_TEST` override changes the ID; do not cache it.
- Hardware identifiers can change (disk replacement, BIOS update, Windows reinstall); files encrypted with the device key then require the key file or the original master password. This is inherent to hardware binding.
- The Encrypt method pills and Settings method cards are separate radio groups; use `SyncMethodRadios` so changing one does not recurse through `Checked` events.
- Completed `FileEntry` rows stay in the lists. Pressing the action again re-encrypts/attempts to decrypt them; after a successful decryption the container is gone, so a second attempt reports an error.
- `FileEntry.Status` stores a `status.*` key; call `Refresh()` after a language change.
- The password prompt handles Enter/Escape in `Window_PreviewKeyDown`; keep focus in `PasswordPromptBox` when showing it.
- The app's `--encrypt`/`--decrypt` requests use the saved method and key settings; there are no per-request method overrides.
