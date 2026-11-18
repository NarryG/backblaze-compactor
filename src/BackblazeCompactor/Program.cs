using System.Text.Json;
using BackblazeCompactor;

return Run(args);

static int Run(string[] args)
{
    try
    {
        if (args.Length == 0 || args is ["--help"] or ["-h"])
        {
            Console.WriteLine("""
                Offline Backblaze catalog compactor — Windows 10.0.3.1075 profile

                analyze SNAPSHOT --retired-prefix DRIVE:\directory\
                compact SNAPSHOT OUTPUT --retired-prefix DRIVE:\directory\
                verify  SNAPSHOT CANDIDATE --retired-prefix DRIVE:\directory\

                Reads a complete snapshot.json plus its catalog/ledgers/queues.
                SNAPSHOT must be a real, non-reparse offline directory.
                Retired prefix must remain excluded from this backup permanently.
                Compact requires a matching client, observed quiescent capture,
                complete/empty pending-work evidence, and no repair markers.
                Unknown formats, stale fingerprints, unsafe records, and existing
                output paths fail closed. No command installs or edits live state.
                """);
            return 0;
        }
        if (args[0] is not ("analyze" or "compact" or "verify")) throw new ArgumentException("Expected analyze, compact, or verify.");
        string mode = args[0];
        string snapshotPath;
        string prefixValue;
        string? output = null;
        if (mode == "analyze" && args.Length == 4 && args[2] == "--retired-prefix")
        {
            snapshotPath = args[1];
            prefixValue = args[3];
        }
        else if (mode == "compact" && args.Length == 5 && args[3] == "--retired-prefix")
        {
            snapshotPath = args[1];
            output = args[2];
            prefixValue = args[4];
        }
        else if (mode == "verify" && args.Length == 5 && args[3] == "--retired-prefix")
        {
            snapshotPath = args[1];
            output = Path.GetFullPath(args[2]);
            Paths.RejectLiveState(output);
            Snapshot.RejectReparsePoints(output);
            prefixValue = args[4];
        }
        else throw new ArgumentException("Invalid arguments; use --help.");
        Paths.RejectLiveState(snapshotPath);
        var snapshot = new Snapshot(snapshotPath);
        using var lease = new SnapshotLease(snapshot);
        var prefix = new RetiredPrefix(prefixValue);
        if (mode == "compact") _ = Paths.NewOutput(output!, snapshot.Root);
        var analysis = Analysis.Run(snapshot, prefix);
        if (mode == "compact") Compactor.Write(analysis, output!);
        if (mode == "verify")
        {
            Compactor.Verify(analysis, output!);
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                verified = true,
                retiredPrefix = analysis.Prefix.Value,
                eligibleRows = analysis.Report.EligibleRows,
                eligibleBytes = analysis.Report.EligibleBytes,
                ledgerFilesVerified = snapshot.Ledgers.Count,
                catalogSha256 = snapshot.Catalog.Sha256
            }, Compactor.Json));
        }
        else Console.WriteLine(JsonSerializer.Serialize(analysis.Report, Compactor.Json));
        return 0;
    }
    catch (Exception error) when (error is IOException or InvalidDataException or ArgumentException or InvalidOperationException
        or UnauthorizedAccessException or JsonException or OverflowException or System.Text.DecoderFallbackException)
    {
        Console.Error.WriteLine(JsonSerializer.Serialize(new { error = error.Message }));
        return 2;
    }
}
