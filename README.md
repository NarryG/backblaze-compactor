# Backblaze Catalog Compactor

An offline Windows tool for investigating catalog-driven RAM usage in Backblaze Transmitter and building a smaller catalog.

## Why this exists

Backblaze Computer Backup’s Windows client stores a path-to-file-ID catalog in `bzfileids.dat`. Worktrees, build outputs, and test artifacts can generate millions of distinct paths. Deleting those files from disk does not immediately remove their catalog entries.

During some backup operations, `bztransmit.exe` loads the catalog and builds an in-memory filename lookup table. A multi-gigabyte catalog can therefore drive high RAM usage even when many of the files it names are gone. **That is memory pressure from a large index, not proof of a memory leak.** A smaller catalog reduces the amount of data the client has to load and index; it does not guarantee a particular RAM saving.

## What it does

- **`analyze`** reports how many catalog rows and bytes belong to a retired directory, how much qualifies for removal, and what blocks compaction.
- **`compact`** writes a separate candidate `bzfileids.dat` from an offline snapshot. It removes only eligible ordinary mappings and preserves retained rows byte-for-byte and in order, along with chunk mappings and the catalog’s recovery tail.
- **`verify`** independently checks the candidate against the snapshot and the retirement prefix you supply, including the exact retained and removed rows and the unchanged allocation counter.

“The file is gone” is not enough. Backblaze can still need its mapping to record the deletion. Compaction is limited to permanently excluded, retired directories and fails closed when the history or pending-work evidence is incomplete.

## What it doesn’t do

- **No live install or modification.** It does not replace Backblaze’s catalog, change exclusions, or stop or restart the client.
- **No deletion of backed-up files or history.** It does not delete your files, write or shrink `bz_done` history ledgers, or contact Backblaze.
- **No memory patch or restore guarantee.** It does not cap RAM, fix leaks, certify cloud restores, or bypass [Safety Freeze](https://www.backblaze.com/computer-backup/docs/safety-freeze). Verification checks the offline output only.

**Experimental and unsupported.** Candidate generation is pinned to Windows Backblaze **10.0.3.1075**, checked against the captured `bztransmit.exe` SHA-256.

## Run

Requires Windows, the .NET 10 SDK, and Python 3.11+ for capture or tests. The capture helper requires elevated PowerShell/WMI, assumes the standard Backblaze installation on `C:`, and makes a temporary VSS snapshot. It neither stops nor starts the client. Use a private destination outside your backup selection; the copied catalog and ledgers contain filenames and backup metadata. A full capture can be large.

```powershell
dotnet build src/BackblazeCompactor/BackblazeCompactor.csproj -c Release
$dll = 'src/BackblazeCompactor/bin/Release/net10.0/BackblazeCompactor.dll'
$snapshot = 'C:/OfflineBackblaze/snapshot'
$candidate = 'C:/OfflineBackblaze/candidate'
$prefix = 'D:/RetiredScratch/'
python -B analysis/snapshot.py $snapshot
dotnet $dll analyze $snapshot --retired-prefix $prefix
```

Use a new snapshot directory and a new candidate directory outside it, with an existing parent. Use real local paths, not junctions. A capture made while Backblaze is running is diagnostic only. If the snapshot passes all write checks, run:

```powershell
dotnet $dll compact $snapshot $candidate --retired-prefix $prefix
dotnet $dll verify $snapshot $candidate --retired-prefix $prefix
```

The candidate directory contains the retained catalog, the removed rows for inspection, an unchanged copy of the allocation counter, and a JSON receipt. Keep these outputs private too.

## What can be removed?

Only unreferenced ordinary mappings or mappings with a completed deletion in supported version-5 history can qualify. Treat an exclusion as a backup policy change, not a cleanup toggle; see [Backblaze’s exclusion guidance](https://www.backblaze.com/computer-backup/docs/configure-exclusions-windows).

The tool keeps pending work, large-file associations, and ambiguous or referenced identities. It preserves the final 10,000 bytes of the catalog, including the entire row crossing that boundary. It checks ledger fingerprints, requires observed client quiescence and complete supported history and pending-work evidence, and refuses to write if repair markers exist.

## Tests

After the Release build, run `python -B -m unittest discover -s tests -v`. The suite uses synthetic snapshots; it does not need Backblaze installed or administrator access.

The repository contains source and synthetic tests only. It is not affiliated with Backblaze.
