using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace BackblazeCompactor;

internal enum KeyKind { Name, Chunk }

internal readonly record struct CatalogKey(KeyKind Kind, ushort CaseMask, ulong Id);

internal readonly ref struct CatalogRecord
{
    public readonly CatalogKey Key;
    public readonly ReadOnlySpan<byte> Path;
    public readonly ReadOnlySpan<byte> Raw;
    public readonly long Offset;

    private CatalogRecord(CatalogKey key, ReadOnlySpan<byte> path, ReadOnlySpan<byte> raw, long offset)
    {
        Key = key;
        Path = path;
        Raw = raw;
        Offset = offset;
    }

    public static CatalogRecord Parse(ReadOnlySpan<byte> raw, long offset)
    {
        if (raw.IsEmpty || raw[^1] != (byte)'\n')
            throw new InvalidDataException($"Unterminated catalog record at byte {offset}.");
        var content = raw[..^1];
        if (!content.IsEmpty && content[^1] == (byte)'\r') content = content[..^1];
        int tab = content.IndexOf((byte)'\t');
        if (tab < 0) throw new InvalidDataException($"Missing catalog separator at byte {offset}.");
        var key = content[..tab];
        var path = content[(tab + 1)..];
        bool chunk = !key.IsEmpty && key[0] == (byte)'x';
        int start = chunk ? 1 : 0;
        if ((!chunk && key.Length != 16) || (chunk && (key.Length != 25
            || key[17] != (byte)'_' || key[19] != (byte)'_' || key[18] != (byte)'5')))
            throw new InvalidDataException($"Unknown catalog key format at byte {offset}.");
        ulong id = Hex.Parse(key.Slice(start, 16), offset, out ushort caseMask);
        if (id == 0 || id > long.MaxValue)
            throw new InvalidDataException($"Catalog ID is outside the native signed-positive range at byte {offset}.");
        if (chunk) _ = Hex.Parse(key[20..], offset);
        if (path.IsEmpty || path.IndexOfAny((byte)0, (byte)'\r', (byte)'\n') >= 0 || path.Contains((byte)'\t'))
            throw new InvalidDataException($"Invalid catalog path at byte {offset}.");
        _ = Text.StrictUtf8.GetCharCount(path);
        return new CatalogRecord(new CatalogKey(chunk ? KeyKind.Chunk : KeyKind.Name, caseMask, id), path, raw, offset);
    }
}

internal static class Text
{
    internal static readonly UTF8Encoding StrictUtf8 = new(false, true);
}

internal static class Hex
{
    public static ulong Parse(ReadOnlySpan<byte> bytes, long offset = -1) => Parse(bytes, offset, out _);

    public static ulong Parse(ReadOnlySpan<byte> bytes, long offset, out ushort caseMask)
    {
        if (bytes.IsEmpty || bytes.Length > 16) throw new InvalidDataException($"Invalid hexadecimal ID near byte {offset}.");
        ulong result = 0;
        caseMask = 0;
        int index = 0;
        foreach (byte b in bytes)
        {
            uint digit = b is >= (byte)'0' and <= (byte)'9' ? (uint)(b - '0')
                : b is >= (byte)'a' and <= (byte)'f' ? (uint)(b - 'a' + 10)
                : b is >= (byte)'A' and <= (byte)'F' ? (uint)(b - 'A' + 10) : 16;
            if (digit > 15) throw new InvalidDataException($"Invalid hexadecimal ID near byte {offset}.");
            if (b is >= (byte)'A' and <= (byte)'F') caseMask |= (ushort)(1 << index);
            index++;
            result = (result << 4) | digit;
        }
        return result;
    }
}

internal delegate void LineVisitor(ReadOnlySpan<byte> raw, long offset);
internal readonly record struct ScanResult(long Bytes, long Lines, string Sha256, long IgnoredTailBytes = 0);

internal static class Lines
{
    private const int BufferSize = 4 * 1024 * 1024;
    private const int MaxRecordSize = 1024 * 1024;

    public static ScanResult Scan(string path, LineVisitor visitor, LineVisitor? ignoredTail = null)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            BufferSize, FileOptions.SequentialScan);
        return Scan(stream, visitor, ignoredTail);
    }

    public static ScanResult Scan(Stream stream, LineVisitor visitor, LineVisitor? ignoredTail = null)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize + MaxRecordSize);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        int carry = 0;
        long consumed = 0;
        long lines = 0;
        try
        {
            while (true)
            {
                int read = stream.Read(buffer.AsSpan(carry, BufferSize));
                if (read == 0) break;
                hash.AppendData(buffer.AsSpan(carry, read));
                int count = carry + read;
                int start = 0;
                while (start < count)
                {
                    int newline = buffer.AsSpan(start, count - start).IndexOf((byte)'\n');
                    if (newline < 0) break;
                    int length = newline + 1;
                    if (length > MaxRecordSize) throw new InvalidDataException($"Record exceeds 1 MiB at byte {consumed}.");
                    visitor(buffer.AsSpan(start, length), consumed);
                    start += length;
                    consumed += length;
                    lines++;
                }
                carry = count - start;
                if (carry > MaxRecordSize) throw new InvalidDataException($"Record exceeds 1 MiB at byte {consumed}.");
                buffer.AsSpan(start, carry).CopyTo(buffer);
            }
            if (carry != 0)
            {
                if (ignoredTail is null) throw new InvalidDataException($"Unterminated final record at byte {consumed}.");
                ignoredTail(buffer.AsSpan(0, carry), consumed);
            }
            return new ScanResult(consumed + carry, lines, Convert.ToHexStringLower(hash.GetHashAndReset()), carry);
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }
    }
}

// A dense local ordinal range costs one bit per ID. Sparse pages avoid allocations
// proportional to an untrusted maximum ID; the cached page removes repeated lookups.
internal sealed class IdSet
{
    private const int PageBits = 16;
    private readonly Dictionary<ulong, ulong[]> pages = [];
    private ulong cachedPage = ulong.MaxValue;
    private ulong[]? cachedWords;
    public long Count { get; private set; }

    public bool Contains(ulong id)
    {
        ulong number = id >> PageBits;
        if (cachedPage != number)
        {
            pages.TryGetValue(number, out cachedWords);
            cachedPage = number;
        }
        return cachedWords is not null && (cachedWords[(id & 65535) >> 6] & (1UL << (int)(id & 63))) != 0;
    }

    public bool Add(ulong id)
    {
        ulong number = id >> PageBits;
        if (cachedPage != number || cachedWords is null)
        {
            if (!pages.TryGetValue(number, out cachedWords))
            {
                cachedWords = new ulong[1024];
                pages.Add(number, cachedWords);
            }
            cachedPage = number;
        }
        int word = (int)((id & 65535) >> 6);
        ulong mask = 1UL << (int)(id & 63);
        if ((cachedWords[word] & mask) != 0) return false;
        cachedWords[word] |= mask;
        Count++;
        return true;
    }

    public void Remove(ulong id)
    {
        if (!Contains(id)) return;
        cachedWords![(id & 65535) >> 6] &= ~(1UL << (int)(id & 63));
        Count--;
    }
}
