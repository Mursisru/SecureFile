using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace SecureFile;

/// <summary>
/// A 256-bit key derived from immutable-ish hardware identifiers.
/// The same PC produces the same key after the app is removed and reinstalled,
/// which lets the built-in device key stay bound to this PC without storing it.
/// This is best-effort binding, not a secret against a local administrator.
/// </summary>
internal static class MachineKey
{
    private const string Domain = "SecureFile.DeviceKey.v1";
    private const int KeySize = 32;
    private const int IdSize = 16;
    private const int Iterations = 100_000;

    private static readonly Lazy<byte[]> LazyKey = new(Derive, LazyThreadSafetyMode.ExecutionAndPublication);

#if SECUREFILE_TEST
    internal static byte[]? TestKey { get; set; }
#endif

    public static byte[] Key
    {
        get
        {
#if SECUREFILE_TEST
            if (TestKey is not null) return TestKey;
#endif
            return LazyKey.Value;
        }
    }

    public static string Secret => Convert.ToBase64String(Key);

    public static byte[] Id => SHA256.HashData(Key).AsSpan(0, IdSize).ToArray();

    public static string ShortId => Convert.ToHexString(Id.AsSpan(0, 4));

    /// <summary>Forces derivation on first launch so the device key exists before the first file operation.</summary>
    public static void Initialize() => _ = Key;

    private static byte[] Derive()
    {
        var material = string.Join(
            "\n",
            "domain=" + Domain,
            "machine=" + ReadMachineGuid(),
            "volume=" + ReadSystemVolumeSerial(),
            "bios=" + ReadRegistryValues(
                @"HARDWARE\DESCRIPTION\System\BIOS",
                "SystemManufacturer",
                "SystemProductName",
                "SystemVersion",
                "BaseBoardManufacturer",
                "BaseBoardProduct",
                "BIOSVendor",
                "BIOSVersion",
                "BIOSReleaseDate"),
            "cpu=" + ReadRegistryValues(
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                "ProcessorNameString",
                "Identifier",
                "VendorIdentifier"));

        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(material),
            Encoding.UTF8.GetBytes(Domain),
            Iterations,
            HashAlgorithmName.SHA256,
            KeySize);
    }

    private static string ReadMachineGuid()
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            return key?.GetValue("MachineGuid") as string ?? string.Empty;
        }
        catch (Exception)
        {
            return string.Empty;
        }
    }

    private static string ReadSystemVolumeSerial()
    {
        try
        {
            var root = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
            if (GetVolumeInformation(root, null, 0, out var serial, out _, out _, null, 0))
                return serial.ToString("X8");
        }
        catch (Exception)
        {
            // Fall through to the other identifiers.
        }

        return string.Empty;
    }

    private static string ReadRegistryValues(string path, params string[] names)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(path);
            if (key is null) return string.Empty;

            var values = new List<string>(names.Length);
            foreach (var name in names)
                values.Add(key.GetValue(name) as string ?? string.Empty);
            return string.Join("|", values);
        }
        catch (Exception)
        {
            return string.Empty;
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformation(
        string rootPathName,
        StringBuilder? volumeNameBuffer,
        int volumeNameSize,
        out uint volumeSerialNumber,
        out uint maximumComponentLength,
        out uint fileSystemFlags,
        StringBuilder? fileSystemNameBuffer,
        int fileSystemNameSize);
}
