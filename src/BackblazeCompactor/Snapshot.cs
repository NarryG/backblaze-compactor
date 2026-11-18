using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace BackblazeCompactor;

internal sealed record SnapshotFile(string RelativePath, string FullPath, long Bytes, string Sha256);

internal sealed partial class Snapshot
{
    public string Root { get; }
    public string ManifestSha256 { get; }
    public SnapshotFile Catalog { get; }
    public SnapshotFile Counter { get; }
    public IReadOnlyList<SnapshotFile> Ledgers { get; }
    public IReadOnlyList<SnapshotFile> Queues { get; }
    public IReadOnlyList<SnapshotFile> FixQueues { get; }
    public IReadOnlyList<SnapshotFile> AllFiles { get; }
    public CaptureProof Capture { get; }
    public byte[] CounterBytes { get; }
    public ulong Watermark { get; }
    public byte[] Tail { get; }

    [GeneratedRegex(@"^(bzdatacenter/bz_done_[0-9]{8}_[0-9]\.dat|bzdatacenter/bz_todo_[0-9]{8}_[0-9]+\.dat|bzdatacenter/bz_tofix/bz_tofix_[0-9]{14}\.dat)$", RegexOptions.CultureInvariant)]
    private static partial Regex LedgerName();

    public Snapshot(string directory)
    {
        Root = Paths.ExistingDirectory(directory);
        Paths.RejectLiveState(Root);
        byte[] manifestBytes = File.ReadAllBytes(Path.Combine(Root, "snapshot.json"));
        Span<byte> manifestDigest = stackalloc byte[32];
        SHA256.HashData(manifestBytes, manifestDigest);
        ManifestSha256 = Convert.ToHexStringLower(manifestDigest);
        using var manifest = JsonDocument.Parse(manifestBytes);
        if (!manifest.RootElement.GetProperty("complete").GetBoolean())
            throw new InvalidDataException("Snapshot is incomplete.");
        Capture = new CaptureProof(manifest.RootElement);
        var files = new Dictionary<string, SnapshotFile>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in manifest.RootElement.GetProperty("files").EnumerateArray())
        {
            string relative = entry.GetProperty("path").GetString() ?? throw new InvalidDataException("Missing snapshot path.");
            if (relative != "bzfileids.dat" && relative != "bzlastassignedfileid.dat" && !LedgerName().IsMatch(relative))
                throw new InvalidDataException($"Unexpected snapshot file: {relative}");
            string full = Path.GetFullPath(Path.Combine(Root, relative));
            if (!full.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Snapshot path escapes its root.");
            RejectReparsePoints(full);
            long bytes = entry.GetProperty("bytes").GetInt64();
            string sha = entry.GetProperty("sha256").GetString() ?? "";
            if (bytes < 0 || sha.Length != 64 || !sha.All(Uri.IsHexDigit))
                throw new InvalidDataException($"Invalid snapshot fingerprint: {relative}");
            if (new FileInfo(full).Length != bytes) throw new InvalidDataException($"Snapshot size changed: {relative}");
            if (!files.TryAdd(relative, new SnapshotFile(relative, full, bytes, sha.ToLowerInvariant())))
                throw new InvalidDataException($"Duplicate snapshot file: {relative}");
        }
        Catalog = files.GetValueOrDefault("bzfileids.dat") ?? throw new InvalidDataException("Snapshot has no catalog.");
        Counter = files.GetValueOrDefault("bzlastassignedfileid.dat") ?? throw new InvalidDataException("Snapshot has no allocation counter.");
        Ledgers = files.Values.Where(f => f.RelativePath.StartsWith("bzdatacenter/bz_done_", StringComparison.Ordinal))
            .OrderBy(f => f.RelativePath, StringComparer.Ordinal).ToArray();
        Queues = files.Values.Where(f => f.RelativePath.StartsWith("bzdatacenter/bz_todo_", StringComparison.Ordinal))
            .OrderBy(f => f.RelativePath, StringComparer.Ordinal).ToArray();
        FixQueues = files.Values.Where(f => f.RelativePath.StartsWith("bzdatacenter/bz_tofix/", StringComparison.Ordinal))
            .OrderBy(f => f.RelativePath, StringComparer.Ordinal).ToArray();
        AllFiles = files.Values.ToArray();
        if (Ledgers.Count == 0) throw new InvalidDataException("Snapshot has no history ledgers.");
        var actual = Directory.EnumerateFileSystemEntries(Path.Combine(Root, "bzdatacenter"))
            .Where(f => Path.GetFileName(f).Contains("bz_done", StringComparison.OrdinalIgnoreCase)
                || Path.GetFileName(f).Contains("bz_todo", StringComparison.OrdinalIgnoreCase))
            .Select(f => "bzdatacenter/" + Path.GetFileName(f));
        string fixRoot = Path.Combine(Root, "bzdatacenter", "bz_tofix");
        if (Directory.Exists(fixRoot)) actual = actual.Concat(Directory.EnumerateFileSystemEntries(fixRoot)
            .Select(f => "bzdatacenter/bz_tofix/" + Path.GetFileName(f)));
        var expected = Ledgers.Concat(Queues).Concat(FixQueues).Select(f => f.RelativePath).OrderBy(f => f, StringComparer.Ordinal).ToArray();
        if (!actual.OrderBy(f => f, StringComparer.Ordinal).SequenceEqual(expected)) throw new InvalidDataException("Snapshot manifest does not cover every ledger and queue.");
        if (Counter.Bytes is < 1 or > 18) throw new InvalidDataException("Invalid allocation counter length.");
        CounterBytes = File.ReadAllBytes(Counter.FullPath);
        Verify(Counter, CounterBytes.LongLength, Convert.ToHexStringLower(SHA256.HashData(CounterBytes)));
        int digits = CounterBytes.Length;
        while (digits > 0 && CounterBytes[digits - 1] is (byte)'\r' or (byte)'\n') digits--;
        if (digits < 2 && Ledgers.Count >= 4) throw new InvalidDataException("Short watermark would trigger native repair with this ledger count.");
        Watermark = Hex.Parse(CounterBytes.AsSpan(0, digits));
        if (Watermark == 0 || Watermark > long.MaxValue) throw new InvalidDataException("Allocation counter is outside the native range.");
        int tailLength = (int)Math.Min(10000, Catalog.Bytes);
        Tail = new byte[tailLength];
        using var stream = new FileStream(Catalog.FullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        stream.Seek(-tailLength, SeekOrigin.End);
        stream.ReadExactly(Tail);
    }

    public static void Verify(SnapshotFile file, ScanResult scan) => Verify(file, scan.Bytes, scan.Sha256);

    public static void Verify(SnapshotFile file, long bytes, string sha)
    {
        if (bytes != file.Bytes || !string.Equals(sha, file.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"Snapshot content changed: {file.RelativePath}");
    }

    public static void RejectReparsePoints(string path)
    {
        var current = new FileInfo(path) as FileSystemInfo;
        while (current is not null)
        {
            if ((File.GetAttributes(current.FullName) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException($"Reparse-point inputs are not supported: {current.FullName}");
            current = current is DirectoryInfo d ? d.Parent : ((FileInfo)current).Directory;
        }
    }
}

internal sealed class RetiredPrefix
{
    public string Value { get; }
    private readonly byte[] prefix;

    public RetiredPrefix(string value)
    {
        value = value.Replace('/', '\\').TrimEnd('\\');
        if (value.Length < 4 || !char.IsAsciiLetter(value[0]) || value[1] != ':' || value[2] != '\\'
            || value.Any(c => c > 127 || c < 32) || value.Contains('*') || value.Contains('?')
            || value.Split('\\').Any(p => p is "." or ".."))
            throw new ArgumentException("Retired prefix must be an explicit ASCII drive-absolute directory without wildcards or dot segments.");
        Value = value + "\\";
        prefix = Text.StrictUtf8.GetBytes(Value);
    }

    public bool Matches(ReadOnlySpan<byte> path) => path.Length >= prefix.Length
        && System.Text.Ascii.EqualsIgnoreCase(path[..prefix.Length], prefix);
}
