using System.Buffers;
using System.Text;

namespace BackblazeCompactor;

internal readonly ref struct LedgerRecord
{
    public readonly byte Action;
    public readonly ulong? NameId;
    public readonly ushort NameCaseMask;
    public readonly ulong? ObjectId;
    public readonly ushort ObjectCaseMask;
    public readonly ulong? ChunkId;
    public readonly byte ChunkType;
    public readonly ReadOnlySpan<byte> Path;

    private LedgerRecord(byte action, ulong? name, ushort nameCaseMask, ulong? obj, ushort objectCaseMask, ulong? chunk, byte chunkType, ReadOnlySpan<byte> path)
    {
        Action = action;
        NameId = name;
        NameCaseMask = nameCaseMask;
        ObjectId = obj;
        ObjectCaseMask = objectCaseMask;
        ChunkId = chunk;
        ChunkType = chunkType;
        Path = path;
    }

    public static LedgerRecord Parse(ReadOnlySpan<byte> raw, long offset)
    {
        var content = raw[..^1];
        if (!content.IsEmpty && content[^1] == (byte)'\r') content = content[..^1];
        Span<Range> fields = stackalloc Range[16];
        int count = ByteFields.Split(content, fields);
        if (count != 14 || content[fields[0]].Length != 1
            || content[fields[0]][0] != (byte)'5' || content[fields[1]].Length != 1)
            throw new InvalidDataException($"Unknown ledger format at byte {offset}.");
        if (content.Contains((byte)0) || content.Contains((byte)'\r')
            || content[fields[2]].Length != 3 || content[fields[3]].Length != 14
            || content[fields[5]].Length != 3 || content[fields[8]].Length != 40
            || content[fields[9]].Length != 16 || content[fields[10]].Length != 16
            || content[fields[count - 1]].IsEmpty)
            throw new InvalidDataException($"Malformed fixed ledger columns at byte {offset}.");
        byte action = content[fields[1]][0];
        if (action is not ((byte)'+' or (byte)'=' or (byte)'-' or (byte)'x' or (byte)'!' or (byte)'g' or (byte)'z'))
            throw new InvalidDataException($"Unknown ledger action at byte {offset}.");
        ulong? name = OptionalId(content[fields[6]], offset, out ushort nameCaseMask);
        var objectField = content[fields[4]];
        ulong? obj = null;
        ushort objectCaseMask;
        if (objectField.Length == 83 && objectField[27] == (byte)'_' && objectField[28] == (byte)'f')
            obj = OptionalId(objectField.Slice(29, 16), offset, out objectCaseMask);
        else
            throw new InvalidDataException($"Unknown object identity field at byte {offset}.");
        var chunks = content[fields[7]];
        if (chunks.Length != 9 || chunks[0] != (byte)'k' || chunks[2] != (byte)'_' || chunks[3] != (byte)'n')
            throw new InvalidDataException($"Unknown chunk descriptor at byte {offset}.");
        byte type = chunks[1];
        if (type is not ((byte)'0' or (byte)'1' or (byte)'5' or (byte)'-'))
            throw new InvalidDataException($"Unknown chunk type at byte {offset}.");
        ulong? chunk = null;
        var field = content[fields[11]];
        if (field.Length == 18 && field.StartsWith("cf"u8)) chunk = Hex.Parse(field[2..], offset);
        else if (!field.SequenceEqual("-"u8)) throw new InvalidDataException($"Unknown chunk ID at byte {offset}.");
        return new LedgerRecord(action, name, nameCaseMask, obj, objectCaseMask, chunk, type, content[fields[count - 1]]);
    }

    private static ulong? OptionalId(ReadOnlySpan<byte> field, long offset, out ushort caseMask)
    {
        if (field.Length != 16) throw new InvalidDataException($"Unknown ID width at byte {offset}.");
        caseMask = 0;
        if (field.SequenceEqual("----------------"u8)) return null;
        return Hex.Parse(field, offset, out caseMask);
    }
}

internal sealed class HistoryState
{
    public readonly IdSet Candidates = new();
    public readonly IdSet Seen = new();
    public readonly IdSet Deleted = new();
    public readonly IdSet Pending = new();
    public readonly IdSet Protected = new();
    private readonly Dictionary<PathDigest, ulong> candidatePaths = [];
    private readonly Dictionary<ulong, ushort> uppercaseIds = [];
    public readonly HashSet<string> LargePaths = new(StringComparer.OrdinalIgnoreCase);
    public bool LegacyPrefixFound { get; private set; }
    public long LedgerRows { get; private set; }
    public long QueueRows { get; private set; }
    private readonly RetiredPrefix prefix;

    public HistoryState(RetiredPrefix prefix) => this.prefix = prefix;

    public void PrepareCandidates(long count) => candidatePaths.EnsureCapacity(checked((int)count));

    public void AddCandidate(CatalogRecord record, PathDigest digest)
    {
        if (!candidatePaths.TryAdd(digest, record.Key.Id))
            throw new InvalidDataException("Duplicate candidate path or digest collision; refusing to choose an identity.");
        Candidates.Add(record.Key.Id);
        if (record.Key.CaseMask != 0) uppercaseIds.Add(record.Key.Id, record.Key.CaseMask);
    }

    public void RememberLargePath(ReadOnlySpan<byte> path)
    {
        if (!WasLarge(path)) LargePaths.Add(Text.StrictUtf8.GetString(path));
    }

    public void ProtectOpaqueLedgerTail(ReadOnlySpan<byte> tail, long offset)
    {
        // Opaque committed legacy rows and uncommitted EOF fragments cannot
        // authorize lifecycle changes; retain any recognizable identities.
        ulong value = 0;
        int run = 0;
        foreach (byte b in tail)
        {
            int digit = b is >= (byte)'0' and <= (byte)'9' ? b - '0'
                : b is >= (byte)'a' and <= (byte)'f' ? b - 'a' + 10
                : b is >= (byte)'A' and <= (byte)'F' ? b - 'A' + 10 : -1;
            if (digit < 0) { value = 0; run = 0; continue; }
            value = unchecked((value << 4) | (uint)digit);
            if (++run >= 16 && Candidates.Contains(value)) Protected.Add(value);
        }
        int tab = tail.LastIndexOf((byte)'\t');
        if (tab >= 0)
        {
            var path = tail[(tab + 1)..];
            if (!path.IsEmpty && path[^1] == (byte)'\n') path = path[..^1];
            if (!path.IsEmpty && path[^1] == (byte)'\r') path = path[..^1];
            if (prefix.Matches(path) && candidatePaths.TryGetValue(PathDigest.Compute(path), out ulong id)) Protected.Add(id);
        }
    }

    public void ReadLedger(ReadOnlySpan<byte> raw, long offset)
    {
        LedgerRows++;
        if (raw[0] == (byte)'#' || raw.SequenceEqual("\n"u8) || raw.SequenceEqual("\r\n"u8)) return;
        if (raw[0] == (byte)'4')
        {
            ReadLegacyLedger(raw, offset);
            return;
        }
        var record = LedgerRecord.Parse(raw, offset);
        bool inPrefix = prefix.Matches(record.Path);
        if (inPrefix && (record.ChunkType is (byte)'1' or (byte)'5' || record.Action == (byte)'!'))
            RememberLargePath(record.Path);
        ulong? mappedForPath = null;
        if (inPrefix)
        {
            var digest = PathDigest.Compute(record.Path);
            if (candidatePaths.TryGetValue(digest, out ulong mapped))
            {
                mappedForPath = mapped;
                if (record.NameId != mapped || record.NameCaseMask != uppercaseIds.GetValueOrDefault(mapped)) Protected.Add(mapped);
            }
        }
        if (record.NameId is ulong name && Candidates.Contains(name))
        {
            Seen.Add(name);
            if (!inPrefix || mappedForPath != name || record.NameCaseMask != uppercaseIds.GetValueOrDefault(name)
                || record.ChunkType is (byte)'1' or (byte)'5'
                || record.Action == (byte)'!') Protected.Add(name);
            if ((record.Action is (byte)'+' or (byte)'=' && record.ChunkType != (byte)'0')
                || (record.Action == (byte)'-' && record.ChunkType != (byte)'-'))
                Protected.Add(name);
            switch (record.Action)
            {
                case (byte)'+':
                case (byte)'=': Deleted.Remove(name); break;
                case (byte)'-': Deleted.Add(name); break;
            }
        }
        // Cross-name object references and numeric chunk coincidences only
        // retain candidates; numeric equality never authorizes removal.
        if (record.ObjectId is ulong obj && Candidates.Contains(obj)
            && (record.NameId != obj || record.NameCaseMask != record.ObjectCaseMask))
            Protected.Add(obj);
        if (record.ChunkId is ulong chunk && Candidates.Contains(chunk)) Protected.Add(chunk);
    }

    private void ReadLegacyLedger(ReadOnlySpan<byte> raw, long offset)
    {
        ProtectOpaqueLedgerTail(raw, offset);
        var content = raw[..^1];
        if (!content.IsEmpty && content[^1] == (byte)'\r') content = content[..^1];
        int tab = content.LastIndexOf((byte)'\t');
        // Only the native fixed positions are understood. If the identity or
        // final path cannot be located confidently, retain every candidate.
        if (content.Length <= 82 || content[1] != (byte)'\t'
            || content[3] != (byte)'\t' || content[7] != (byte)'\t'
            || content[2] is not ((byte)'+' or (byte)'=' or (byte)'-' or (byte)'x' or (byte)'!' or (byte)'g' or (byte)'z')
            || content[81] is not ((byte)'0' or (byte)'1' or (byte)'5' or (byte)'-')
            || content[24] != (byte)'\t' || content[39] != (byte)'\t'
            || tab <= 81 || content.Contains((byte)0) || content.Contains((byte)'\r'))
        {
            LegacyPrefixFound = true;
            return;
        }
        var identity = content.Slice(8, 16);
        if (identity.SequenceEqual("----------------"u8))
        {
            LegacyPrefixFound = true;
            return;
        }
        foreach (byte b in identity)
            if (!(b is >= (byte)'0' and <= (byte)'9'
                or >= (byte)'a' and <= (byte)'f' or >= (byte)'A' and <= (byte)'F'))
            {
                LegacyPrefixFound = true;
                return;
            }
        foreach (byte b in content.Slice(25, 14))
            if (b is < (byte)'0' or > (byte)'9')
            {
                LegacyPrefixFound = true;
                return;
            }
        var path = content[(tab + 1)..];
        if (path.Length < 3 || !(((path[0] is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z')
            && path[1] == (byte)':' && (path[2] == (byte)'\\' || path[2] == (byte)'/'))
            || (path[0] == (byte)'\\' && path[1] == (byte)'\\')))
        {
            LegacyPrefixFound = true;
            return;
        }
        try { _ = Text.StrictUtf8.GetCharCount(path); }
        catch (DecoderFallbackException) { LegacyPrefixFound = true; return; }
        if (prefix.Matches(path)) LegacyPrefixFound = true;
    }

    public void ReadFixQueue(ReadOnlySpan<byte> raw, long offset)
    {
        var path = raw[..^1];
        if (!path.IsEmpty && path[^1] == (byte)'\r') path = path[..^1];
        if (path.Length < 3 || path[1] != (byte)':' || path[2] != (byte)'\\'
            || path.IndexOfAny((byte)0, (byte)'\t', (byte)'\r') >= 0)
            throw new InvalidDataException($"Unknown path-only correction queue format at byte {offset}.");
        _ = Text.StrictUtf8.GetCharCount(path);
        ProtectQueuedPath(path);
        QueueRows++;
    }

    private void ProtectQueuedPath(ReadOnlySpan<byte> path)
    {
        if (prefix.Matches(path) && candidatePaths.TryGetValue(PathDigest.Compute(path), out ulong id)) Pending.Add(id);
    }

    public void ReadQueue(ReadOnlySpan<byte> raw, long offset)
    {
        var content = raw[..^1];
        if (!content.IsEmpty && content[^1] == (byte)'\r') content = content[..^1];
        Span<Range> fields = stackalloc Range[7];
        int count = ByteFields.Split(content, fields);
        if (count != 6 || !content[fields[0]].SequenceEqual("1"u8) || content[fields[1]].Length != 1
            || content[fields[2]].Length != 16 || content.Contains((byte)0) || content.Contains((byte)'\r'))
            throw new InvalidDataException($"Unknown pending-queue format at byte {offset}.");
        ulong id = Hex.Parse(content[fields[2]], offset);
        if (Candidates.Contains(id)) Pending.Add(id);
        ProtectQueuedPath(content[fields[5]]);
        QueueRows++;
    }

    public bool WasLarge(ReadOnlySpan<byte> path)
    {
        if (LargePaths.Count == 0) return false;
        int count = Text.StrictUtf8.GetCharCount(path);
        char[]? rented = null;
        Span<char> chars = count <= 2048 ? stackalloc char[count] : (rented = ArrayPool<char>.Shared.Rent(count)).AsSpan(0, count);
        try
        {
            Text.StrictUtf8.GetChars(path, chars);
            return LargePaths.GetAlternateLookup<ReadOnlySpan<char>>().Contains(chars);
        }
        finally { if (rented is not null) ArrayPool<char>.Shared.Return(rented); }
    }
}
