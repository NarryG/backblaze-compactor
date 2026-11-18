using System.Buffers;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace BackblazeCompactor;

internal static class Paths
{
    public static string ExistingDirectory(string directory)
    {
        string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        Snapshot.RejectReparsePoints(full);
        if (!OperatingSystem.IsWindows()) return full;
        using var handle = CreateFileW(full, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (handle.IsInvalid) throw DirectoryError();
        Span<char> buffer = stackalloc char[512];
        uint length = GetFinalPathNameByHandleW(handle, ref MemoryMarshal.GetReference(buffer), (uint)buffer.Length, 0);
        if (length == 0) throw DirectoryError();
        if (length < buffer.Length) return LocalPath(buffer[..(int)length]);
        char[] rented = ArrayPool<char>.Shared.Rent(checked((int)length + 1));
        try
        {
            length = GetFinalPathNameByHandleW(handle, ref rented[0], (uint)rented.Length, 0);
            if (length == 0) throw DirectoryError();
            if (length >= rented.Length) throw new IOException("Directory identity changed during path resolution.");
            return LocalPath(rented.AsSpan(0, (int)length));
        }
        finally { ArrayPool<char>.Shared.Return(rented); }
    }

    private static string LocalPath(ReadOnlySpan<char> path)
    {
        if (path.StartsWith(@"\\?\")) path = path[4..];
        if (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\')
            throw new IOException("Only resolved local drive paths are supported.");
        return Path.TrimEndingDirectorySeparator(path.ToString());
    }

    private static IOException DirectoryError()
        => new("Cannot resolve the existing directory identity.", new Win32Exception(Marshal.GetLastWin32Error()));

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, ref char path, uint length, uint flags);

    public static void RejectLiveState(string directory)
    {
        if (!OperatingSystem.IsWindows()) return;
        string full = Directory.Exists(directory) ? ExistingDirectory(directory)
            : Path.Combine(ExistingDirectory(Path.GetDirectoryName(directory) ?? throw new IOException("Directory has no parent.")), Path.GetFileName(directory));
        foreach (string root in new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Backblaze"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Backblaze")
        })
        {
            string resolvedRoot = Directory.Exists(root) ? ExistingDirectory(root) : root;
            if (full.Equals(resolvedRoot, StringComparison.OrdinalIgnoreCase)
                || full.StartsWith(resolvedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Only offline snapshots and separate output directories are accepted; live Backblaze paths are forbidden.");
        }
    }

    public static string NewOutput(string directory, string snapshotRoot)
    {
        string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        string parent = ExistingDirectory(Path.GetDirectoryName(full) ?? throw new IOException("Output has no parent directory."));
        full = Path.Combine(parent, Path.GetFileName(full));
        RejectLiveState(full);
        if (full.Equals(snapshotRoot, StringComparison.OrdinalIgnoreCase)
            || full.StartsWith(snapshotRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Output must be outside the input snapshot.");
        if (File.Exists(full) || Directory.Exists(full)) throw new IOException("Output already exists; nothing will be overwritten.");
        return full;
    }
}

internal sealed class SnapshotLease : IDisposable
{
    private readonly List<FileStream> handles = [];

    public SnapshotLease(Snapshot snapshot)
    {
        try
        {
            var manifest = new FileStream(Path.Combine(snapshot.Root, "snapshot.json"), FileMode.Open, FileAccess.Read, FileShare.Read);
            handles.Add(manifest);
            Span<byte> digest = stackalloc byte[32];
            SHA256.HashData(manifest, digest);
            if (Convert.ToHexStringLower(digest) != snapshot.ManifestSha256)
                throw new InvalidDataException("Snapshot manifest changed during admission.");
            foreach (var file in snapshot.AllFiles)
            {
                var handle = new FileStream(file.FullPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1);
                handles.Add(handle);
                if (file == snapshot.Counter)
                {
                    SHA256.HashData(handle, digest);
                    Snapshot.Verify(file, handle.Length, Convert.ToHexStringLower(digest));
                }
            }
        }
        catch { Dispose(); throw; }
    }

    public void Dispose()
    {
        foreach (var handle in handles) handle.Dispose();
        handles.Clear();
    }
}
