using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace BackblazeCompactor;

internal readonly record struct PathDigest(ulong A, ulong B, ulong C, ulong D)
{
    public static PathDigest Compute(ReadOnlySpan<byte> value)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(value, hash);
        return new PathDigest(BinaryPrimitives.ReadUInt64LittleEndian(hash), BinaryPrimitives.ReadUInt64LittleEndian(hash[8..]),
            BinaryPrimitives.ReadUInt64LittleEndian(hash[16..]), BinaryPrimitives.ReadUInt64LittleEndian(hash[24..]));
    }
}

internal readonly record struct NativeDigest(ulong A, ulong B) : IComparable<NativeDigest>
{
    public int CompareTo(NativeDigest other)
    {
        int first = A.CompareTo(other.A);
        return first != 0 ? first : B.CompareTo(other.B);
    }
}

// Exact duplicate keys necessarily share a digest. A digest collision refuses
// compaction rather than permitting deletion. External sorted runs cap working
// memory regardless of the number of source rows.
internal sealed class NativeKeys : IDisposable
{
    private readonly NativeDigest[] buffer;
    private readonly List<string> runs = [];
    private readonly string work = Path.Combine(Path.GetTempPath(), "backblaze-compactor-" + Guid.NewGuid().ToString("N"));
    private readonly byte[] chunkKey = new byte[1024 * 1024];
    private int count;
    public NativeKeys(long rows) => buffer = new NativeDigest[(int)Math.Clamp(rows, 1, 4 * 1024 * 1024)];

    public PathDigest Add(CatalogRecord record)
    {
        if (count == buffer.Length) SaveRun();
        PathDigest digest;
        if (record.Key.Kind == KeyKind.Name) digest = PathDigest.Compute(record.Path);
        else
        {
            // Native duplicate scanner hashes row+18, replacing the TAB at its
            // byte 7 with '_': type + '_' + five-digit index + '_' + path.
            record.Raw.Slice(18, 7).CopyTo(chunkKey);
            chunkKey[7] = (byte)'_';
            record.Path.CopyTo(chunkKey.AsSpan(8));
            digest = PathDigest.Compute(chunkKey.AsSpan(0, 8 + record.Path.Length));
        }
        buffer[count++] = new NativeDigest(digest.A, digest.B);
        return digest;
    }

    private void SortAndCheck()
    {
        Array.Sort(buffer, 0, count);
        for (int i = 1; i < count; i++)
            if (buffer[i] == buffer[i - 1]) throw Duplicate();
    }

    private static InvalidDataException Duplicate() => new("Source has duplicate native filename keys or a digest collision; no compaction is allowed.");

    private void SaveRun()
    {
        SortAndCheck();
        Directory.CreateDirectory(work);
        string path = Path.Combine(work, runs.Count.ToString("D6") + ".bin");
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            file.Write(MemoryMarshal.AsBytes(buffer.AsSpan(0, count)));
        runs.Add(path);
        count = 0;
    }

    public void Complete()
    {
        if (runs.Count == 0) { SortAndCheck(); return; }
        if (count > 0) SaveRun();
        var readers = new List<RunReader>();
        try
        {
            var queue = new PriorityQueue<RunReader, NativeDigest>();
            foreach (string path in runs)
            {
                var reader = new RunReader(path);
                readers.Add(reader);
                if (reader.MoveNext()) queue.Enqueue(reader, reader.Current);
            }
            NativeDigest? previous = null;
            while (queue.TryDequeue(out var reader, out var digest))
            {
                if (previous == digest) throw Duplicate();
                previous = digest;
                if (reader.MoveNext()) queue.Enqueue(reader, reader.Current);
            }
        }
        finally { foreach (var reader in readers) reader.Dispose(); }
    }

    public void Dispose()
    {
        if (Directory.Exists(work)) Directory.Delete(work, true);
    }

    private sealed class RunReader : IDisposable
    {
        private readonly FileStream stream;
        public NativeDigest Current { get; private set; }
        public RunReader(string path) => stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);
        public bool MoveNext()
        {
            Span<byte> bytes = stackalloc byte[16];
            int read = stream.Read(bytes);
            if (read == 0) return false;
            stream.ReadExactly(bytes[read..]);
            Current = new NativeDigest(BinaryPrimitives.ReadUInt64LittleEndian(bytes), BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]));
            return true;
        }
        public void Dispose() => stream.Dispose();
    }
}
