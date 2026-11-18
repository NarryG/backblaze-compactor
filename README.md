# Backblaze Catalog Compactor

An unofficial Windows tool for analyzing and compacting an **offline copy** of Backblaze Computer Backup’s `bzfileids.dat` path-to-ID catalog. It does not apply changes to a live installation, edit `bz_done` history, or contact Backblaze.

**Experimental and unsupported.** The writer is pinned to Windows Backblaze **10.0.3.1075** and checks the `bztransmit.exe` SHA-256. A verified output establishes the offline transformation, not cloud restore compatibility or immunity from [Safety Freeze](https://www.backblaze.com/computer-backup/docs/safety-freeze).

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

Use a new snapshot directory and a new candidate directory outside it, with an existing parent. Use real local paths, not junctions. `analyze` reports the measured footprint, potentially eligible rows and write blockers. A capture made while Backblaze is running is diagnostic only. For a snapshot that passes **all** gates, `compact` writes a separate candidate and verifies it before publishing; `verify` independently checks the result against the source and the explicitly supplied prefix:

```powershell
dotnet $dll compact $snapshot $candidate --retired-prefix $prefix
dotnet $dll verify $snapshot $candidate --retired-prefix $prefix
```

The candidate contains the retained catalog, the removed raw rows for inspection, an unchanged copy of the allocation counter, and a JSON receipt. **No live apply command is provided.** Keep these outputs private too.

## What can be removed?

Only ordinary mappings under an explicitly retired and permanently excluded directory, either unreferenced or with a completed deletion in supported version-5 history. A missing file alone is not sufficient: the client can still need its catalog mapping to generate the deletion record. Treat an exclusion as a backup policy change, not a cleanup toggle; see [Backblaze’s exclusion guidance](https://www.backblaze.com/computer-backup/docs/configure-exclusions-windows).

The tool keeps chunk mappings, pending work, large-file associations and ambiguous or referenced identities. It preserves raw retained bytes and order, the allocation counter, and the final 10,000-byte recovery window including any row crossing its start. Ledger fingerprints are checked and no ledger is written. The writer also requires observed client quiescence, supported complete history and pending-work evidence, and no repair markers. Unknown evidence blocks output. Do not use native rebuild, repair or inheritance as validation of a candidate.

## Tests

After the Release build, run `python -B -m unittest discover -s tests -v`. The suite uses synthetic snapshots; it does not need Backblaze installed or administrator access.

The repository contains source and synthetic tests only. It is not affiliated with Backblaze.
