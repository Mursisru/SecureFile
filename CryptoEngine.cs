using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureFile;

internal sealed record DecryptResult(string OutputPath, EncryptionMethod Method, bool Authenticated);

internal enum ContainerKind
{
    Unknown,
    Legacy,
    MachineBound,
    KeyBound,
}

internal sealed class CrossDeviceException : CryptographicException
{
    public CrossDeviceException() : base("This file was encrypted on another device.") { }
}

internal static class CryptoEngine
{
    public const int SaltSize = 16;
    public const int IvSize = 16;
    public const int TagSize = 32;
    private const int BufferSize = 1 << 20;

    private const byte V2Version = 1;
    private const int V2HeaderSize = 4 + 1 + 4 + SaltSize + IvSize;
    private const int CbcHeaderSize = SaltSize + IvSize;

    internal const string LegacyFallbackPassword = "0021";

    private const byte MachineVersion = 1;
    private const int MachineVersionOffset = 4;
    private const int MachineMethodOffset = 5;
    private const int MachineIdOffset = 6;
    private const int MachineIterationsOffset = 22;
    private const int MachineSaltOffset = 26;
    private const int MachineIvOffset = 42;
    private const int MachineHeaderSize = 58;

    private const byte KeyV1Version = 1;
    private const int KeyV1WrapIterationsOffset = 22;
    private const int KeyV1WrapSaltOffset = 26;
    private const int KeyV1WrapIvOffset = 42;
    private const int KeyV1WrappedKeyOffset = 58;
    private const int KeyV1WrapTagOffset = 106;
    private const int KeyV1PayloadIterationsOffset = 138;
    private const int KeyV1PayloadSaltOffset = 142;
    private const int KeyV1PayloadIvOffset = 158;
    private const int KeyV1HeaderSize = 174;

    private const byte KeyV2Version = 2;
    private const int KeyV2MachineIdOffset = 22;
    private const int KeyV2WrapIterationsOffset = 38;
    private const int KeyV2WrapSaltOffset = 42;
    private const int KeyV2WrapIvOffset = 58;
    private const int KeyV2WrappedKeyOffset = 74;
    private const int KeyV2WrapTagOffset = 122;
    private const int KeyV2PayloadIterationsOffset = 154;
    private const int KeyV2PayloadSaltOffset = 158;
    private const int KeyV2PayloadIvOffset = 174;
    private const int KeyV2HeaderSize = 190;

    private const int KeyMethodOffset = 5;
    private const int KeyIdOffset = 6;
    private const int KeyIdSize = 16;
    private const int WrappedKeySize = 48;
    private const int WrapIterations = 100_000;

    private static readonly byte[] V2Magic = { (byte)'S', (byte)'F', (byte)'V', (byte)'2' };
    private static readonly byte[] MachineMagic = { (byte)'S', (byte)'F', (byte)'M', (byte)'1' };
    private static readonly byte[] KeyMagic = { (byte)'S', (byte)'F', (byte)'K', (byte)'1' };

    public static string ExtensionFor(EncryptionMethod method) => method switch
    {
        EncryptionMethod.Fast => ".secf",
        EncryptionMethod.Maximum => ".secf1v2",
        _ => ".secf1",
    };

    public static bool IsContainerPath(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Equals(".secf", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".secf1", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".secf1v2", StringComparison.OrdinalIgnoreCase);
    }

    public static int IterationsFor(EncryptionMethod method) => method switch
    {
        EncryptionMethod.Fast => 1_000,
        EncryptionMethod.Maximum => 200_000,
        _ => 10_000,
    };

    public static async Task<string> EncryptAsync(
        string inputPath,
        EncryptionMethod method,
        byte[]? keyFileKey,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        var outputPath = inputPath + ExtensionFor(method);
        var tempPath = outputPath + ".tmp";
        var total = new FileInfo(inputPath).Length;

        try
        {
            await using (var input = OpenRead(inputPath))
            await using (var output = OpenWrite(tempPath))
            {
                if (keyFileKey is not null)
                    await EncryptKeyBoundAsync(input, output, method, keyFileKey, total, progress, cancellationToken);
                else
                    await EncryptMachineBoundAsync(input, output, method, total, progress, cancellationToken);

                await output.FlushAsync(cancellationToken);
            }

            File.Move(tempPath, outputPath, overwrite: true);
            return outputPath;
        }
        catch
        {
            TryDelete(tempPath);
            throw;
        }
    }

    private static async Task EncryptMachineBoundAsync(
        Stream input,
        Stream output,
        EncryptionMethod method,
        long total,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var iv = RandomNumberGenerator.GetBytes(IvSize);
        var iterations = IterationsFor(method);

        var header = new byte[MachineHeaderSize];
        MachineMagic.CopyTo(header, 0);
        header[MachineVersionOffset] = MachineVersion;
        header[MachineMethodOffset] = MethodToByte(method);
        MachineKey.Id.CopyTo(header, MachineIdOffset);
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(MachineIterationsOffset, 4), iterations);
        salt.CopyTo(header, MachineSaltOffset);
        iv.CopyTo(header, MachineIvOffset);

        await output.WriteAsync(header, cancellationToken);
        await EncryptPayloadAsync(
            input, output, MachineKey.Secret, salt, iv, iterations,
            method == EncryptionMethod.Maximum ? header : null, total, progress, cancellationToken);
    }

    private static async Task EncryptKeyBoundAsync(
        Stream input,
        Stream output,
        EncryptionMethod method,
        byte[] keyFileKey,
        long total,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        var secret = Convert.ToBase64String(keyFileKey);
        var keyId = ComputeKeyId(keyFileKey);
        var payloadSalt = RandomNumberGenerator.GetBytes(SaltSize);
        var payloadIv = RandomNumberGenerator.GetBytes(IvSize);
        var payloadIterations = IterationsFor(method);
        var wrapSalt = RandomNumberGenerator.GetBytes(SaltSize);
        var wrapIv = RandomNumberGenerator.GetBytes(IvSize);
        var wrapMaterial = Derive(MachineKey.Secret, wrapSalt, WrapIterations, 64);

        var header = new byte[KeyV2HeaderSize];
        KeyMagic.CopyTo(header, 0);
        header[4] = KeyV2Version;
        header[KeyMethodOffset] = MethodToByte(method);
        keyId.CopyTo(header, KeyIdOffset);
        MachineKey.Id.CopyTo(header, KeyV2MachineIdOffset);
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(KeyV2WrapIterationsOffset, 4), WrapIterations);
        wrapSalt.CopyTo(header, KeyV2WrapSaltOffset);
        wrapIv.CopyTo(header, KeyV2WrapIvOffset);

        var wrappedKey = EncryptWithAes(keyFileKey, wrapMaterial.AsSpan(0, 32).ToArray(), wrapIv);
        if (wrappedKey.Length != WrappedKeySize) throw new CryptographicException("Key wrapping failed.");
        wrappedKey.CopyTo(header, KeyV2WrappedKeyOffset);

        using (var wrapHmac = IncrementalHash.CreateHMAC(
            HashAlgorithmName.SHA256, wrapMaterial.AsSpan(32, 32).ToArray()))
        {
            wrapHmac.AppendData(header.AsSpan(0, KeyV2WrapTagOffset));
            var wrapTag = wrapHmac.GetHashAndReset();
            wrapTag.CopyTo(header, KeyV2WrapTagOffset);
        }

        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(KeyV2PayloadIterationsOffset, 4), payloadIterations);
        payloadSalt.CopyTo(header, KeyV2PayloadSaltOffset);
        payloadIv.CopyTo(header, KeyV2PayloadIvOffset);

        await output.WriteAsync(header, cancellationToken);
        await EncryptPayloadAsync(
            input, output, secret, payloadSalt, payloadIv, payloadIterations,
            method == EncryptionMethod.Maximum ? header : null, total, progress, cancellationToken);
    }

    private static async Task EncryptPayloadAsync(
        Stream input,
        Stream output,
        string secret,
        byte[] salt,
        byte[] iv,
        int iterations,
        byte[]? authenticatedHeader,
        long total,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        if (authenticatedHeader is not null)
        {
            var material = Derive(secret, salt, iterations, 64);
            using var hmac = IncrementalHash.CreateHMAC(
                HashAlgorithmName.SHA256, material.AsSpan(32, 32).ToArray());
            hmac.AppendData(authenticatedHeader);

            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = material.AsSpan(0, 32).ToArray();
            aes.IV = iv;

            await using (var crypto = new CryptoStream(
                new HmacWriteStream(output, hmac), aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
            {
                await CopyWithProgressAsync(input, crypto, total, progress, cancellationToken);
                await crypto.FlushFinalBlockAsync(cancellationToken);
            }

            var tag = hmac.GetHashAndReset();
            await output.WriteAsync(tag, cancellationToken);
            return;
        }

        var key = Derive(secret, salt, iterations, 32);
        using var cbcAes = Aes.Create();
        cbcAes.Mode = CipherMode.CBC;
        cbcAes.Padding = PaddingMode.PKCS7;
        cbcAes.Key = key;
        cbcAes.IV = iv;

        await using var cbc = new CryptoStream(output, cbcAes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true);
        await CopyWithProgressAsync(input, cbc, total, progress, cancellationToken);
        await cbc.FlushFinalBlockAsync(cancellationToken);
    }

    private static byte[] EncryptWithAes(byte[] plain, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;
        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(plain, 0, plain.Length);
    }

    private static byte[] ComputeKeyId(byte[] key) => SHA256.HashData(key).AsSpan(0, KeyIdSize).ToArray();

    private static byte MethodToByte(EncryptionMethod method) => method switch
    {
        EncryptionMethod.Fast => 0,
        EncryptionMethod.Medium => 1,
        _ => 2,
    };

    private static EncryptionMethod MethodFromByte(byte method) => method switch
    {
        0 => EncryptionMethod.Fast,
        1 => EncryptionMethod.Medium,
        2 => EncryptionMethod.Maximum,
        _ => throw new CryptographicException("Unsupported format version."),
    };

    private static byte[] Derive(string secret, byte[] salt, int iterations, int length) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(secret), salt, iterations, HashAlgorithmName.SHA256, length);

    private static async Task CopyWithProgressAsync(
        Stream source,
        Stream destination,
        long total,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[BufferSize];
        long copied = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
        {
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            copied += read;
            if (total > 0) progress?.Report(Math.Min(1.0, (double)copied / total));
        }
    }

    private sealed class HmacWriteStream : Stream
    {
        private readonly Stream _inner;
        private readonly IncrementalHash _hmac;

        public HmacWriteStream(Stream inner, IncrementalHash hmac)
        {
            _inner = inner;
            _hmac = hmac;
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _hmac.AppendData(buffer.AsSpan(offset, count));
            _inner.Write(buffer, offset, count);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            _hmac.AppendData(buffer.Span);
            return _inner.WriteAsync(buffer, cancellationToken);
        }

        public override void Flush() => _inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    public static async Task<DecryptResult> DecryptAsync(
        string inputPath,
        IReadOnlyList<string> secrets,
        byte[]? keyFileKey,
        IProgress<double>? progress,
        CancellationToken cancellationToken,
        bool verify = false)
    {
        var info = await ReadInfoAsync(inputPath, cancellationToken);
        var candidates = info.Kind switch
        {
            ContainerKind.KeyBound => ResolveKeyBoundSecrets(info, keyFileKey),
            ContainerKind.MachineBound => ResolveMachineBoundSecrets(info),
            _ => secrets,
        };

        var outputPath = GetRestoredPath(inputPath);
        var tempPath = outputPath + ".tmp";

        foreach (var secret in candidates)
        {
            foreach (var iterations in IterationsToTry(info))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    await DecryptWithInfoAsync(
                        inputPath, tempPath, secret, info, iterations, progress, cancellationToken);

                    if (verify && !await MatchesSecondPassAsync(
                            inputPath, tempPath, secret, info, iterations, cancellationToken))
                        throw new CryptographicException("Verification failed.");

                    File.Move(tempPath, outputPath, overwrite: true);
                    TryDelete(inputPath);
                    return new DecryptResult(outputPath, info.Method, info.Method == EncryptionMethod.Maximum);
                }
                catch (CryptographicException)
                {
                    TryDelete(tempPath);
                }
                catch
                {
                    TryDelete(tempPath);
                    throw;
                }
            }
        }

        throw new CryptographicException("No matching key for this file.");
    }

    public static async Task<ContainerKind> GetContainerKindAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            var info = await ReadInfoAsync(path, cancellationToken);
            return info.Kind;
        }
        catch (Exception)
        {
            return ContainerKind.Unknown;
        }
    }

    private static IReadOnlyList<string> ResolveKeyBoundSecrets(CryptoFileInfo info, byte[]? keyFileKey)
    {
        var secrets = new List<string>(2);
        var keyFileMatches = false;
        if (keyFileKey is not null && info.KeyId is not null)
        {
            var candidateId = ComputeKeyId(keyFileKey);
            if (CryptographicOperations.FixedTimeEquals(candidateId, info.KeyId))
            {
                secrets.Add(Convert.ToBase64String(keyFileKey));
                keyFileMatches = true;
            }
        }

        if (info.KeyVersion == KeyV1Version)
        {
            try
            {
                var legacySecret = Convert.ToBase64String(UnwrapKey(info));
                if (!secrets.Contains(legacySecret)) secrets.Add(legacySecret);
            }
            catch (CryptographicException)
            {
                // The wrapped key is only usable when its authentication tag is intact.
            }

            return secrets;
        }

        if (!IsCurrentMachine(info))
        {
            if (keyFileMatches) return secrets;
            throw new CrossDeviceException();
        }

        try
        {
            var machineSecret = Convert.ToBase64String(UnwrapKey(info));
            if (!secrets.Contains(machineSecret)) secrets.Add(machineSecret);
        }
        catch (CryptographicException)
        {
            // The wrapped key is only usable when its authentication tag is intact.
        }

        return secrets;
    }

    private static IReadOnlyList<string> ResolveMachineBoundSecrets(CryptoFileInfo info)
    {
        if (!IsCurrentMachine(info)) throw new CrossDeviceException();
        return new[] { MachineKey.Secret };
    }

    private static bool IsCurrentMachine(CryptoFileInfo info) =>
        info.MachineId is { Length: KeyIdSize } machineId &&
        CryptographicOperations.FixedTimeEquals(machineId, MachineKey.Id);

    private static byte[] UnwrapKey(CryptoFileInfo info)
    {
        if (info.WrapSalt is null || info.WrapIv is null || info.WrapTag is null ||
            info.WrappedKey is null || info.WrapPrefix is null)
            throw new CryptographicException("Corrupted container.");

        var secret = info.KeyVersion == KeyV1Version
            ? LegacyFallbackPassword
            : MachineKey.Secret;
        var material = Derive(secret, info.WrapSalt, info.WrapIterations, 64);
        using (var hmac = IncrementalHash.CreateHMAC(
            HashAlgorithmName.SHA256, material.AsSpan(32, 32).ToArray()))
        {
            hmac.AppendData(info.WrapPrefix);
            var actual = hmac.GetHashAndReset();
            if (!CryptographicOperations.FixedTimeEquals(actual, info.WrapTag))
                throw new CryptographicException("Key unwrap failed.");
        }

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = material.AsSpan(0, 32).ToArray();
        aes.IV = info.WrapIv;
        using var decryptor = aes.CreateDecryptor();
        var raw = decryptor.TransformFinalBlock(info.WrappedKey, 0, info.WrappedKey.Length);
        if (raw.Length != 32) throw new CryptographicException("Key unwrap failed.");
        return raw;
    }

    private static async Task<bool> MatchesSecondPassAsync(
        string inputPath,
        string firstPassPath,
        string secret,
        CryptoFileInfo info,
        int iterations,
        CancellationToken cancellationToken)
    {
        var verifyPath = Path.Combine(Path.GetTempPath(), "SecureFile-verify-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await DecryptWithInfoAsync(
                inputPath, verifyPath, secret, info, iterations, null, cancellationToken);

            var first = await HashFileAsync(firstPassPath, cancellationToken);
            var second = await HashFileAsync(verifyPath, cancellationToken);
            return CryptographicOperations.FixedTimeEquals(first, second);
        }
        finally
        {
            TryDelete(verifyPath);
        }
    }

    public static async Task<bool> VerifyRoundTripAsync(
        string originalPath,
        string encryptedPath,
        byte[]? keyFileKey,
        CancellationToken cancellationToken)
    {
        var tempPath = Path.Combine(Path.GetTempPath(), "SecureFile-verify-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var info = await ReadInfoAsync(encryptedPath, cancellationToken);
            var candidates = info.Kind switch
            {
                ContainerKind.MachineBound => ResolveMachineBoundSecrets(info),
                ContainerKind.KeyBound => ResolveKeyBoundSecrets(info, keyFileKey),
                _ => Array.Empty<string>(),
            };
            if (candidates.Count == 0) return false;

            await DecryptWithInfoAsync(
                encryptedPath, tempPath, candidates[0], info, info.Iterations, null, cancellationToken);

            var original = await HashFileAsync(originalPath, cancellationToken);
            var restored = await HashFileAsync(tempPath, cancellationToken);
            return CryptographicOperations.FixedTimeEquals(original, restored);
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    private static Task DecryptWithInfoAsync(
        string inputPath,
        string tempPath,
        string secret,
        CryptoFileInfo info,
        int iterations,
        IProgress<double>? progress,
        CancellationToken cancellationToken) =>
        info.Method == EncryptionMethod.Maximum
            ? DecryptV2Async(inputPath, tempPath, secret, info, iterations, progress, cancellationToken)
            : DecryptCbcAsync(inputPath, tempPath, secret, info, iterations, progress, cancellationToken);

    public static void SecureDelete(string path)
    {
        try
        {
            var length = new FileInfo(path).Length;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
            {
                var buffer = new byte[BufferSize];
                long written = 0;
                while (written < length)
                {
                    var count = (int)Math.Min(buffer.Length, length - written);
                    stream.Write(buffer, 0, count);
                    written += count;
                }
                stream.Flush(flushToDisk: true);
            }
            File.Delete(path);
        }
        catch (Exception)
        {
            TryDelete(path);
        }
    }

    private static async Task DecryptCbcAsync(
        string inputPath,
        string tempPath,
        string secret,
        CryptoFileInfo info,
        int iterations,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        var key = Derive(secret, info.Salt, iterations, 32);
        await using var input = OpenRead(inputPath);
        input.Seek(info.HeaderSize, SeekOrigin.Begin);

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = info.Iv;

        await using var output = OpenWrite(tempPath);
        await using var crypto = new CryptoStream(
            new LimitedReadStream(input, info.CipherLength), aes.CreateDecryptor(), CryptoStreamMode.Read, leaveOpen: true);
        await CopyWithProgressAsync(crypto, output, info.CipherLength, progress, cancellationToken);
    }

    private static async Task DecryptV2Async(
        string inputPath,
        string tempPath,
        string secret,
        CryptoFileInfo info,
        int iterations,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        var material = Derive(secret, info.Salt, iterations, 64);
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, material.AsSpan(32, 32).ToArray());

        await using (var input = OpenRead(inputPath))
        {
            var header = new byte[info.HeaderSize];
            await input.ReadExactlyAsync(header.AsMemory(), cancellationToken);
            hmac.AppendData(header);

            var buffer = new byte[BufferSize];
            long remaining = info.CipherLength;
            long processed = 0;
            while (remaining > 0)
            {
                var toRead = (int)Math.Min(buffer.Length, remaining);
                var read = await input.ReadAsync(buffer.AsMemory(0, toRead), cancellationToken);
                if (read == 0) throw new CryptographicException("Corrupted container.");
                hmac.AppendData(buffer.AsSpan(0, read));
                remaining -= read;
                processed += read;
                if (info.CipherLength > 0) progress?.Report(0.45 * processed / info.CipherLength);
            }

            var expected = new byte[TagSize];
            await input.ReadExactlyAsync(expected.AsMemory(), cancellationToken);
            var actual = hmac.GetHashAndReset();
            if (!CryptographicOperations.FixedTimeEquals(expected, actual))
                throw new CryptographicException("Authentication failed.");
        }

        await using var source = OpenRead(inputPath);
        source.Seek(info.HeaderSize, SeekOrigin.Begin);

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = material.AsSpan(0, 32).ToArray();
        aes.IV = info.Iv;

        await using var output = OpenWrite(tempPath);
        var scaled = progress is null ? null : new Progress<double>(value => progress.Report(0.45 + 0.55 * value));
        await using var crypto = new CryptoStream(
            new LimitedReadStream(source, info.CipherLength), aes.CreateDecryptor(), CryptoStreamMode.Read, leaveOpen: true);
        await CopyWithProgressAsync(crypto, output, info.CipherLength, scaled, cancellationToken);
    }

    private static async Task<CryptoFileInfo> ReadInfoAsync(string path, CancellationToken cancellationToken)
    {
        var length = new FileInfo(path).Length;
        await using var input = OpenRead(path);
        var magic = new byte[4];
        try
        {
            await input.ReadExactlyAsync(magic.AsMemory(), cancellationToken);
        }
        catch (EndOfStreamException)
        {
            throw new CryptographicException("Corrupted container.");
        }

        if (magic.AsSpan().SequenceEqual(KeyMagic))
            return await ReadKeyInfoAsync(input, magic, length, cancellationToken);

        if (magic.AsSpan().SequenceEqual(MachineMagic))
            return await ReadMachineInfoAsync(input, magic, length, cancellationToken);

        if (magic.AsSpan().SequenceEqual(V2Magic))
        {
            var header = new byte[V2HeaderSize];
            magic.CopyTo(header, 0);
            await ReadExactlyOrCorruptAsync(input, header.AsMemory(4), cancellationToken);
            if (header[4] != V2Version) throw new CryptographicException("Unsupported format version.");
            var iterations = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(5, 4));
            var salt = header.AsSpan(9, SaltSize).ToArray();
            var iv = header.AsSpan(9 + SaltSize, IvSize).ToArray();
            var tagOffset = length - TagSize;
            var cipherLength = tagOffset - V2HeaderSize;
            if (cipherLength < 0 || cipherLength % 16 != 0)
                throw new CryptographicException("Corrupted container.");

            return new CryptoFileInfo(
                Kind: ContainerKind.Legacy,
                Method: EncryptionMethod.Maximum,
                Salt: salt,
                Iv: iv,
                Iterations: iterations,
                HeaderSize: V2HeaderSize,
                CipherLength: cipherLength,
                TagOffset: tagOffset);
        }

        var method = MethodFromExtension(path);
        if (method == EncryptionMethod.Maximum)
            throw new CryptographicException("Corrupted container.");

        var cbcHeader = new byte[CbcHeaderSize];
        magic.CopyTo(cbcHeader, 0);
        await ReadExactlyOrCorruptAsync(input, cbcHeader.AsMemory(4), cancellationToken);
        var cipher = length - CbcHeaderSize;
        if (cipher <= 0 || cipher % 16 != 0)
            throw new CryptographicException("Corrupted container.");

        return new CryptoFileInfo(
            Kind: ContainerKind.Legacy,
            Method: method,
            Salt: cbcHeader.AsSpan(0, SaltSize).ToArray(),
            Iv: cbcHeader.AsSpan(SaltSize, IvSize).ToArray(),
            Iterations: IterationsFor(method),
            HeaderSize: CbcHeaderSize,
            CipherLength: cipher,
            TagOffset: length);
    }

    private static async Task<CryptoFileInfo> ReadKeyInfoAsync(
        Stream input,
        byte[] magic,
        long length,
        CancellationToken cancellationToken)
    {
        var versionBytes = new byte[1];
        await ReadExactlyOrCorruptAsync(input, versionBytes.AsMemory(), cancellationToken);
        var version = versionBytes[0];
        var headerSize = version switch
        {
            KeyV1Version => KeyV1HeaderSize,
            KeyV2Version => KeyV2HeaderSize,
            _ => throw new CryptographicException("Unsupported format version."),
        };

        var header = new byte[headerSize];
        magic.CopyTo(header, 0);
        header[4] = version;
        await ReadExactlyOrCorruptAsync(input, header.AsMemory(5), cancellationToken);

        var isV1 = version == KeyV1Version;
        var method = MethodFromByte(header[KeyMethodOffset]);
        var keyId = header.AsSpan(KeyIdOffset, KeyIdSize).ToArray();
        var wrapIterationsOffset = isV1 ? KeyV1WrapIterationsOffset : KeyV2WrapIterationsOffset;
        var wrapSaltOffset = isV1 ? KeyV1WrapSaltOffset : KeyV2WrapSaltOffset;
        var wrapIvOffset = isV1 ? KeyV1WrapIvOffset : KeyV2WrapIvOffset;
        var wrappedKeyOffset = isV1 ? KeyV1WrappedKeyOffset : KeyV2WrappedKeyOffset;
        var wrapTagOffset = isV1 ? KeyV1WrapTagOffset : KeyV2WrapTagOffset;
        var payloadIterationsOffset = isV1 ? KeyV1PayloadIterationsOffset : KeyV2PayloadIterationsOffset;
        var payloadSaltOffset = isV1 ? KeyV1PayloadSaltOffset : KeyV2PayloadSaltOffset;
        var payloadIvOffset = isV1 ? KeyV1PayloadIvOffset : KeyV2PayloadIvOffset;

        var wrapIterations = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(wrapIterationsOffset, 4));
        var payloadIterations = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(payloadIterationsOffset, 4));
        if (wrapIterations <= 0 || payloadIterations <= 0)
            throw new CryptographicException("Corrupted container.");

        var tagOffset = method == EncryptionMethod.Maximum ? length - TagSize : length;
        var cipherLength = tagOffset - headerSize;
        if (cipherLength <= 0 || cipherLength % 16 != 0)
            throw new CryptographicException("Corrupted container.");

        return new CryptoFileInfo(
            Kind: ContainerKind.KeyBound,
            Method: method,
            Salt: header.AsSpan(payloadSaltOffset, SaltSize).ToArray(),
            Iv: header.AsSpan(payloadIvOffset, IvSize).ToArray(),
            Iterations: payloadIterations,
            HeaderSize: headerSize,
            CipherLength: cipherLength,
            TagOffset: tagOffset,
            KeyId: keyId,
            WrapIterations: wrapIterations,
            WrapSalt: header.AsSpan(wrapSaltOffset, SaltSize).ToArray(),
            WrapIv: header.AsSpan(wrapIvOffset, IvSize).ToArray(),
            WrapTag: header.AsSpan(wrapTagOffset, TagSize).ToArray(),
            WrappedKey: header.AsSpan(wrappedKeyOffset, WrappedKeySize).ToArray(),
            WrapPrefix: header.AsSpan(0, wrapTagOffset).ToArray(),
            MachineId: isV1 ? null : header.AsSpan(KeyV2MachineIdOffset, KeyIdSize).ToArray(),
            KeyVersion: version);
    }

    private static async Task<CryptoFileInfo> ReadMachineInfoAsync(
        Stream input,
        byte[] magic,
        long length,
        CancellationToken cancellationToken)
    {
        var header = new byte[MachineHeaderSize];
        magic.CopyTo(header, 0);
        await ReadExactlyOrCorruptAsync(input, header.AsMemory(4), cancellationToken);

        if (header[MachineVersionOffset] != MachineVersion)
            throw new CryptographicException("Unsupported format version.");

        var method = MethodFromByte(header[MachineMethodOffset]);
        var iterations = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(MachineIterationsOffset, 4));
        if (iterations <= 0) throw new CryptographicException("Corrupted container.");

        var tagOffset = method == EncryptionMethod.Maximum ? length - TagSize : length;
        var cipherLength = tagOffset - MachineHeaderSize;
        if (cipherLength <= 0 || cipherLength % 16 != 0)
            throw new CryptographicException("Corrupted container.");

        return new CryptoFileInfo(
            Kind: ContainerKind.MachineBound,
            Method: method,
            Salt: header.AsSpan(MachineSaltOffset, SaltSize).ToArray(),
            Iv: header.AsSpan(MachineIvOffset, IvSize).ToArray(),
            Iterations: iterations,
            HeaderSize: MachineHeaderSize,
            CipherLength: cipherLength,
            TagOffset: tagOffset,
            MachineId: header.AsSpan(MachineIdOffset, KeyIdSize).ToArray());
    }

    private static async Task ReadExactlyOrCorruptAsync(
        Stream input,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        try
        {
            await input.ReadExactlyAsync(buffer, cancellationToken);
        }
        catch (EndOfStreamException)
        {
            throw new CryptographicException("Corrupted container.");
        }
    }

    private static IEnumerable<int> IterationsToTry(CryptoFileInfo info)
    {
        if (info.Kind is ContainerKind.KeyBound or ContainerKind.MachineBound)
        {
            yield return info.Iterations;
            yield break;
        }

        var seen = new HashSet<int>();
        if (info.Iterations > 0 && seen.Add(info.Iterations)) yield return info.Iterations;
        var primary = IterationsFor(info.Method);
        if (seen.Add(primary)) yield return primary;
        if (seen.Add(10_000)) yield return 10_000;
        if (seen.Add(1_000)) yield return 1_000;
    }

    private static EncryptionMethod MethodFromExtension(string path)
    {
        var extension = Path.GetExtension(path);
        if (extension.Equals(".secf", StringComparison.OrdinalIgnoreCase)) return EncryptionMethod.Fast;
        if (extension.Equals(".secf1v2", StringComparison.OrdinalIgnoreCase)) return EncryptionMethod.Maximum;
        return EncryptionMethod.Medium;
    }

    private static string GetRestoredPath(string inputPath)
    {
        var full = Path.GetFullPath(inputPath);
        string restored;
        if (full.EndsWith(".secf1v2", StringComparison.OrdinalIgnoreCase))
            restored = full[..^8];
        else if (full.EndsWith(".secf1", StringComparison.OrdinalIgnoreCase))
            restored = full[..^6];
        else if (full.EndsWith(".secf", StringComparison.OrdinalIgnoreCase))
            restored = full[..^5];
        else
            restored = full + ".dec";

        if (string.IsNullOrEmpty(Path.GetFileName(restored))) return full + ".dec";
        return Path.HasExtension(restored) ? restored : restored + ".dec";
    }

    private static async Task<byte[]> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = OpenRead(path);
        return await SHA256.HashDataAsync(stream, cancellationToken);
    }

    private static FileStream OpenRead(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static FileStream OpenWrite(string path) =>
        new(path, FileMode.Create, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous);

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private sealed record CryptoFileInfo(
        ContainerKind Kind,
        EncryptionMethod Method,
        byte[] Salt,
        byte[] Iv,
        int Iterations,
        int HeaderSize,
        long CipherLength,
        long TagOffset,
        byte[]? KeyId = null,
        int WrapIterations = 0,
        byte[]? WrapSalt = null,
        byte[]? WrapIv = null,
        byte[]? WrapTag = null,
        byte[]? WrappedKey = null,
        byte[]? WrapPrefix = null,
        byte[]? MachineId = null,
        byte KeyVersion = 0);

    private sealed class LimitedReadStream : Stream
    {
        private readonly Stream _inner;
        private long _remaining;

        public LimitedReadStream(Stream inner, long length)
        {
            _inner = inner;
            _remaining = length;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remaining <= 0) return 0;
            var read = _inner.Read(buffer, offset, (int)Math.Min(count, _remaining));
            _remaining -= read;
            return read;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_remaining <= 0) return ValueTask.FromResult(0);
            var slice = buffer[..(int)Math.Min(buffer.Length, _remaining)];
            var task = _inner.ReadAsync(slice, cancellationToken);
            return AwaitAndCount(task);
        }

        private async ValueTask<int> AwaitAndCount(ValueTask<int> task)
        {
            var read = await task;
            _remaining -= read;
            return read;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

internal static class KeyStore
{
    private const string RegPath = @"Software\SecureFile";
    private const string FileKeyName = "FileKey";

    public static byte[]? TryGetFileKey()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RegPath);
            if (key?.GetValue(FileKeyName) is not string stored) return null;
            var bytes = Convert.FromBase64String(stored);
            return bytes.Length == 32 ? bytes : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static string? TryReadKeyFileSecret(string? path) =>
        TryReadKeyFileBytes(path) is { } bytes ? Convert.ToBase64String(bytes) : null;

    public static byte[]? TryReadKeyFileBytes(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return null;
        try
        {
            var bytes = File.ReadAllBytes(path);
            return bytes.Length == 32 ? bytes : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static bool TryCreateKeyFile(string path)
    {
        try
        {
            File.WriteAllBytes(path, RandomNumberGenerator.GetBytes(32));
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
