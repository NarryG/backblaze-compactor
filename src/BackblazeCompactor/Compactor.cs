using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;

namespace BackblazeCompactor;

internal enum Disposition { Outside, Chunk, Tail, Pending, Legacy, Large, Referenced, Active, Unreferenced, Deleted }

internal sealed class CompactionReport
{
    public string Format { get; set; } = "backblaze-catalog-compactor/1";
    public string Profile { get; set; } = "windows-10.0.3.1075";
    public string Mode { get; set; } = "analyze";
    public string RetiredPrefix { get; set; } = "";
    public string SnapshotManifestSha256 { get; set; } = "";
    public string CatalogSha256 { get; set; } = "";
    public long CatalogBytes { get; set; }
    public long CatalogRows { get; set; }
    public long ChunkRows { get; set; }
    public long CandidateRows { get; set; }
    public long CandidateBytes { get; set; }
    public long EligibleRows { get; set; }
    public long EligibleBytes { get; set; }
    public long UnreferencedRows { get; set; }
    public long DeletedRows { get; set; }
    public Dictionary<string, long> Kept { get; set; } = new(StringComparer.Ordinal);
    public int LedgerFiles { get; set; }
    public long LedgerRows { get; set; }
    public long QueueRows { get; set; }
    public long IgnoredLedgerTailBytes { get; set; }
    public List<string> LedgerWarnings { get; set; } = [];
    public string WatermarkHex { get; set; } = "";
    public string CatalogMaxIdHex { get; set; } = "";
    public bool PermanentExclusionRequired { get; set; } = true;
    public bool NativeKeysVerified { get; set; }
    public bool ClientMatches { get; set; }
    public bool QuiescentCapture { get; set; }
    public bool PendingCoverageVerified { get; set; }
    public bool HistoryCoverageVerified { get; set; }
    public bool ExclusionVerified { get; set; }
    public bool RepairFree { get; set; }
    public bool CanCompact { get; set; }
    public List<string> WriteBlockers { get; set; } = [];
    public string? RetainedSha256 { get; set; }
    public string? RemovedSha256 { get; set; }
}

internal sealed class Analysis
{
    public readonly Snapshot Snapshot;
    public readonly RetiredPrefix Prefix;
    public readonly HistoryState History;
    public readonly CompactionReport Report;

    public Analysis(Snapshot snapshot, RetiredPrefix prefix)
    {
        Snapshot = snapshot;
        Prefix = prefix;
        History = new HistoryState(prefix);
        Report = new CompactionReport
        {
            RetiredPrefix = prefix.Value,
            SnapshotManifestSha256 = snapshot.ManifestSha256,
            CatalogSha256 = snapshot.Catalog.Sha256,
            CatalogBytes = snapshot.Catalog.Bytes,
            WatermarkHex = snapshot.Watermark.ToString("x16"),
            LedgerFiles = snapshot.Ledgers.Count
        };
    }

    public static string FileHash(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    public Disposition Classify(CatalogRecord record)
    {
        if (record.Key.Kind == KeyKind.Chunk) return Disposition.Chunk;
        if (!Prefix.Matches(record.Path)) return Disposition.Outside;
        if (record.Offset + record.Raw.Length > Snapshot.Catalog.Bytes - 10000) return Disposition.Tail;
        if (History.Pending.Contains(record.Key.Id)) return Disposition.Pending;
        if (History.LegacyPrefixFound) return Disposition.Legacy;
        if (History.WasLarge(record.Path)) return Disposition.Large;
        if (History.Protected.Contains(record.Key.Id)) return Disposition.Referenced;
        if (!History.Seen.Contains(record.Key.Id)) return Disposition.Unreferenced;
        return History.Deleted.Contains(record.Key.Id) ? Disposition.Deleted : Disposition.Active;
    }

    public static bool Remove(Disposition decision) => decision is Disposition.Unreferenced or Disposition.Deleted;

    public static Analysis Run(Snapshot snapshot, RetiredPrefix prefix)
    {
        var analysis = new Analysis(snapshot, prefix);
        ulong previous = 0;
        var catalog = Lines.Scan(snapshot.Catalog.FullPath, (raw, offset) =>
        {
            var record = CatalogRecord.Parse(raw, offset);
            if (record.Key.Id <= previous)
                throw new InvalidDataException($"Source catalog is not native-repair-clean: non-increasing numeric ID at byte {offset}. No compaction is allowed.");
            previous = record.Key.Id;
            if (record.Key.Kind == KeyKind.Chunk)
            {
                analysis.Report.ChunkRows++;
                if (prefix.Matches(record.Path)) analysis.History.RememberLargePath(record.Path);
            }
            else if (prefix.Matches(record.Path))
            {
                analysis.Report.CandidateRows++;
                analysis.Report.CandidateBytes += raw.Length;
            }
        });
        Snapshot.Verify(snapshot.Catalog, catalog);
        if (snapshot.Watermark < previous) throw new InvalidDataException("Allocation counter is below the source catalog maximum; refusing to repair it.");
        analysis.Report.CatalogRows = catalog.Lines;
        analysis.Report.CatalogMaxIdHex = previous.ToString("x16");
        analysis.History.PrepareCandidates(analysis.Report.CandidateRows);
        Console.Error.WriteLine("Checking all native filename keys.");
        using (var keys = new NativeKeys(catalog.Lines))
        {
            Snapshot.Verify(snapshot.Catalog, Lines.Scan(snapshot.Catalog.FullPath, (raw, offset) =>
            {
                var record = CatalogRecord.Parse(raw, offset);
                var digest = keys.Add(record);
                if (record.Key.Kind == KeyKind.Name && prefix.Matches(record.Path))
                    analysis.History.AddCandidate(record, digest);
            }));
            keys.Complete();
        }
        analysis.Report.NativeKeysVerified = true;
        for (int index = 0; index < snapshot.Ledgers.Count; index++)
        {
            if (index % 50 == 0) Console.Error.WriteLine($"Reading history ledger {index + 1}/{snapshot.Ledgers.Count}.");
            var ledger = snapshot.Ledgers[index];
            try
            {
                var scan = Lines.Scan(ledger.FullPath, analysis.History.ReadLedger, analysis.History.ProtectOpaqueLedgerTail);
                Snapshot.Verify(ledger, scan);
                if (scan.IgnoredTailBytes != 0)
                {
                    analysis.Report.IgnoredLedgerTailBytes += scan.IgnoredTailBytes;
                    analysis.Report.LedgerWarnings.Add($"{ledger.RelativePath}: {scan.IgnoredTailBytes} incomplete trailing bytes are ignored by the native reader; all source bytes remain unchanged.");
                }
            }
            catch (InvalidDataException error) { throw new InvalidDataException($"{ledger.RelativePath}: {error.Message}", error); }
        }
        foreach (var queue in snapshot.Queues)
            Snapshot.Verify(queue, Lines.Scan(queue.FullPath, analysis.History.ReadQueue));
        foreach (var queue in snapshot.FixQueues)
            Snapshot.Verify(queue, Lines.Scan(queue.FullPath, analysis.History.ReadFixQueue));
        analysis.Report.LedgerRows = analysis.History.LedgerRows;
        analysis.Report.QueueRows = analysis.History.QueueRows;
        Snapshot.Verify(snapshot.Catalog, Lines.Scan(snapshot.Catalog.FullPath, (raw, offset) =>
        {
            var record = CatalogRecord.Parse(raw, offset);
            var decision = analysis.Classify(record);
            if (Remove(decision))
            {
                analysis.Report.EligibleRows++;
                analysis.Report.EligibleBytes += raw.Length;
                if (decision == Disposition.Unreferenced) analysis.Report.UnreferencedRows++;
                else analysis.Report.DeletedRows++;
            }
            else if (record.Key.Kind == KeyKind.Name && prefix.Matches(record.Path))
            {
                string reason = decision switch
                {
                    Disposition.Tail => "tail", Disposition.Pending => "pending", Disposition.Legacy => "legacy",
                    Disposition.Large => "large", Disposition.Referenced => "referenced", Disposition.Active => "active",
                    _ => throw new InvalidOperationException("Unknown retained-candidate reason.")
                };
                analysis.Report.Kept[reason] = analysis.Report.Kept.GetValueOrDefault(reason) + 1;
            }
        }));
        var report = analysis.Report;
        report.ClientMatches = snapshot.Capture.ClientMatches;
        report.QuiescentCapture = snapshot.Capture.ObservedQuiescent;
        report.PendingCoverageVerified = snapshot.Capture.PendingCovered;
        report.HistoryCoverageVerified = snapshot.Capture.HistoryCovered;
        report.RepairFree = snapshot.Capture.RepairFree;
        report.ExclusionVerified = snapshot.Capture.ExclusionCovers(prefix);
        if (!OperatingSystem.IsWindows()) report.WriteBlockers.Add("Compaction requires Windows input-handle sharing guarantees.");
        if (!report.ClientMatches) report.WriteBlockers.Add("Missing or unsupported client-binary fingerprint.");
        if (!report.QuiescentCapture) report.WriteBlockers.Add("Capture did not prove an observed quiescent writer interval.");
        if (!report.PendingCoverageVerified) report.WriteBlockers.Add("Pending-work coverage is missing, unsupported, or nonempty.");
        if (!report.HistoryCoverageVerified) report.WriteBlockers.Add("History coverage is missing or contains unsupported native-consumable ledger names.");
        if (!report.RepairFree) report.WriteBlockers.Add("Repair-marker/transaction-sidecar absence is not established.");
        if (!report.ExclusionVerified) report.WriteBlockers.Add("Retired prefix is not covered by an unambiguous exclusion in the captured configuration.");
        if (report.EligibleRows == 0) report.WriteBlockers.Add("No records meet the removal contract.");
        report.CanCompact = report.WriteBlockers.Count == 0;
        return analysis;
    }
}

internal static class Compactor
{
    internal static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    private static readonly string[] OutputFiles = ["bzfileids.dat", "bzfileids.removed.dat", "bzlastassignedfileid.dat", "compaction.json"];

    private static void RequireSafeCapture(Analysis analysis)
    {
        if (!analysis.Report.CanCompact)
            throw new InvalidOperationException("No output permitted: " + string.Join(" ", analysis.Report.WriteBlockers));
    }

    public static CompactionReport Write(Analysis analysis, string directory)
    {
        RequireSafeCapture(analysis);
        string output = Paths.NewOutput(directory, analysis.Snapshot.Root);
        string stage = output + ".partial-" + Guid.NewGuid().ToString("N");
        if (Directory.Exists(stage) || File.Exists(stage)) throw new IOException("Temporary output already exists.");
        Directory.CreateDirectory(stage);
        try
        {
            using (var kept = new HashedWriter(Path.Combine(stage, "bzfileids.dat")))
            using (var removed = new HashedWriter(Path.Combine(stage, "bzfileids.removed.dat")))
            {
                var scan = Lines.Scan(analysis.Snapshot.Catalog.FullPath, (raw, offset) =>
                {
                    var record = CatalogRecord.Parse(raw, offset);
                    if (Analysis.Remove(analysis.Classify(record))) removed.Write(raw);
                    else kept.Write(raw);
                });
                Snapshot.Verify(analysis.Snapshot.Catalog, scan);
                analysis.Report.RetainedSha256 = kept.Complete();
                analysis.Report.RemovedSha256 = removed.Complete();
            }
            using (var counter = new FileStream(Path.Combine(stage, "bzlastassignedfileid.dat"), FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                counter.Write(analysis.Snapshot.CounterBytes);
                counter.Flush(true);
            }
            analysis.Report.Mode = "compact";
            using (var manifest = new FileStream(Path.Combine(stage, "compaction.json"), FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(manifest, analysis.Report, Json);
                manifest.Flush(true);
            }
            Verify(analysis, stage);
            Directory.Move(stage, output);
            return analysis.Report;
        }
        finally { if (Directory.Exists(stage)) Directory.Delete(stage, true); }
    }

    public static void Verify(Analysis analysis, string directory)
    {
        RequireSafeCapture(analysis);
        string output = Path.GetFullPath(directory);
        Paths.RejectLiveState(output);
        Snapshot.RejectReparsePoints(output);
        var names = Directory.EnumerateFileSystemEntries(output).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray();
        if (!names.SequenceEqual(OutputFiles.Order(StringComparer.Ordinal)))
            throw new InvalidDataException("Candidate must contain only the compacted catalog, removed records, unchanged counter, and compaction manifest. Ledgers are forbidden.");
        foreach (string name in OutputFiles) Snapshot.RejectReparsePoints(Path.Combine(output, name));
        var saved = JsonSerializer.Deserialize<CompactionReport>(File.ReadAllBytes(Path.Combine(output, "compaction.json")), Json)
            ?? throw new InvalidDataException("Invalid compaction manifest.");
        if (saved.Format != analysis.Report.Format || saved.Profile != analysis.Report.Profile || saved.Mode != "compact"
            || saved.RetiredPrefix != analysis.Prefix.Value || saved.SnapshotManifestSha256 != analysis.Report.SnapshotManifestSha256
            || saved.CatalogSha256 != analysis.Snapshot.Catalog.Sha256 || saved.EligibleRows != analysis.Report.EligibleRows
            || saved.EligibleBytes != analysis.Report.EligibleBytes)
            throw new InvalidDataException("Candidate does not match this snapshot, prefix, and removal contract.");
        var counter = File.ReadAllBytes(Path.Combine(output, "bzlastassignedfileid.dat"));
        if (!counter.AsSpan().SequenceEqual(analysis.Snapshot.CounterBytes)) throw new InvalidDataException("Candidate changed the allocation counter.");
        using var kept = new FileStream(Path.Combine(output, "bzfileids.dat"), FileMode.Open, FileAccess.Read, FileShare.Read, 4 * 1024 * 1024);
        using var removed = new FileStream(Path.Combine(output, "bzfileids.removed.dat"), FileMode.Open, FileAccess.Read, FileShare.Read, 4 * 1024 * 1024);
        byte[] scratch = ArrayPool<byte>.Shared.Rent(65536);
        try
        {
            Snapshot.Verify(analysis.Snapshot.Catalog, Lines.Scan(analysis.Snapshot.Catalog.FullPath, (raw, offset) =>
            {
                var record = CatalogRecord.Parse(raw, offset);
                Compare(raw, Analysis.Remove(analysis.Classify(record)) ? removed : kept, scratch);
            }));
            if (kept.ReadByte() != -1 || removed.ReadByte() != -1) throw new InvalidDataException("Candidate contains extra records or trailing bytes.");
            if (kept.Length < analysis.Snapshot.Tail.Length) throw new InvalidDataException("Candidate shortened the protected tail.");
            kept.Seek(-analysis.Snapshot.Tail.Length, SeekOrigin.End);
            byte[] tail = new byte[analysis.Snapshot.Tail.Length];
            kept.ReadExactly(tail);
            if (!tail.AsSpan().SequenceEqual(analysis.Snapshot.Tail)) throw new InvalidDataException("Candidate changed the native tail-recovery window.");
        }
        finally { ArrayPool<byte>.Shared.Return(scratch); }
        if (Analysis.FileHash(Path.Combine(output, "bzfileids.dat")) != saved.RetainedSha256
            || Analysis.FileHash(Path.Combine(output, "bzfileids.removed.dat")) != saved.RemovedSha256)
            throw new InvalidDataException("Candidate output hashes do not match its manifest.");
    }

    private static void Compare(ReadOnlySpan<byte> expected, Stream stream, byte[] scratch)
    {
        while (!expected.IsEmpty)
        {
            int count = Math.Min(expected.Length, scratch.Length);
            stream.ReadExactly(scratch.AsSpan(0, count));
            if (!expected[..count].SequenceEqual(scratch.AsSpan(0, count)))
                throw new InvalidDataException("Candidate is not the exact policy-selected subsequence of the source catalog.");
            expected = expected[count..];
        }
    }
}

internal sealed class HashedWriter : IDisposable
{
    private readonly FileStream stream;
    private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly byte[] buffer = ArrayPool<byte>.Shared.Rent(4 * 1024 * 1024);
    private int used;
    private bool completed;

    public HashedWriter(string path) => stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.SequentialScan);

    public void Write(ReadOnlySpan<byte> bytes)
    {
        while (!bytes.IsEmpty)
        {
            int count = Math.Min(bytes.Length, buffer.Length - used);
            bytes[..count].CopyTo(buffer.AsSpan(used));
            used += count;
            bytes = bytes[count..];
            if (used == buffer.Length) Flush();
        }
    }

    private void Flush()
    {
        if (used == 0) return;
        stream.Write(buffer.AsSpan(0, used));
        hash.AppendData(buffer.AsSpan(0, used));
        used = 0;
    }

    public string Complete()
    {
        if (completed) throw new InvalidOperationException("Writer already completed.");
        Flush();
        stream.Flush(true);
        completed = true;
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    public void Dispose()
    {
        stream.Dispose();
        hash.Dispose();
        ArrayPool<byte>.Shared.Return(buffer);
    }
}
