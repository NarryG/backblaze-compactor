"""Deterministic synthetic Backblaze catalog/ledger snapshots for CLI tests.

Every fixture is built from literal bytes in memory. Nothing is copied from a
live installation, no filesystem timestamp is consulted, and the resulting tree
contains only the snapshot manifest and the files that manifest names.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

PINNED_CLIENT_SHA256 = "9522d21b72fd25896c9e5b857acb3b5b022fb14618d863b7294ea40ab65c3b70"
KIND = "VSS point-in-time catalog/ledger snapshot"
PREFIX = "D:\\Scratch\\"
OUTSIDE = "C:\\Keep\\"
DEFAULT_LEDGER = "bz_done_20260101_0.dat"
TOFIX_NAME = "bz_tofix_20260101000000.dat"

OMIT = object()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ordinary_row(identifier: int, path: str, eol: str = "\n", *, uppercase: bool = False) -> bytes:
    key = f"{identifier:016X}" if uppercase else f"{identifier:016x}"
    return f"{key}\t{path}{eol}".encode("utf-8")


def chunk_row(identifier: int, index: int, path: str, eol: str = "\n", *, uppercase: bool = False) -> bytes:
    key = f"{identifier:016X}" if uppercase else f"{identifier:016x}"
    return f"x{key}_5_{index:05x}\t{path}{eol}".encode("utf-8")


def resource_field(object_id: int) -> str:
    value = f"4_h{'a' * 24}_f{object_id:016x}_d20260101_m000000_c000_v0000000_t0000"
    if len(value) != 83 or value[27:29] != "_f":
        raise AssertionError(f"fixture resource field is not 83 bytes: {value!r}")
    return value


CHUNK_DESCRIPTORS = {
    "0": "k0_n00000",
    "1": "k1_n00000",
    "5": "k5_n00000",
    "-": "k-_n-----",
}


def _name_field(name_id: int | None, uppercase: bool = False) -> str:
    if name_id is None:
        return "----------------"
    return f"{name_id:016X}" if uppercase else f"{name_id:016x}"


def ledger_v5(
    action: str,
    path: str,
    name_id: int | None,
    *,
    chunk_type: str = "0",
    chunk_id: int | str = "-",
    object_id: int = 0,
    datetime: str = "20260101000000",
    hash_char: str = "a",
    created: str = "0000000000000000",
    modified: str = "0000000000000000",
    size: str = "123",
    name_upper: bool = False,
) -> bytes:
    if len(action) != 1:
        raise ValueError("ledger action must be one byte")
    if any(ch in path for ch in "\t\r\n\0"):
        raise ValueError("fixture ledger path contains a forbidden byte")
    if chunk_id == "-":
        chunk_field = "-"
    elif isinstance(chunk_id, int):
        chunk_field = f"cf{chunk_id:016x}"
    else:
        chunk_field = chunk_id
    fields = [
        "5",
        action,
        "---",
        datetime,
        resource_field(object_id),
        "u--",
        _name_field(name_id, name_upper),
        CHUNK_DESCRIPTORS[chunk_type],
        hash_char * 40,
        created,
        modified,
        chunk_field,
        size,
        path,
    ]
    return ("\t".join(fields) + "\n").encode("utf-8")


def ledger_v4(
    action: str,
    path: str,
    name_id: int | None,
    *,
    chunk_type: str = "0",
    object_id: int = 0,
    datetime: str = "20260101000000",
    hash_char: str = "a",
    created: str = "0000000000000000",
    modified: str = "0000000000000000",
    size: str = "123",
    name_upper: bool = False,
) -> bytes:
    """Opaque legacy sample: only native-proven ID/date/kind offsets are modeled.

    The resource field is deliberately synthetic; this is not a complete
    reconstruction of the vendor's version-4 writer grammar.
    """
    if len(action) != 1 or any(ch in path for ch in "\t\r\n\0"):
        raise ValueError("invalid fixture ledger action or path")
    opaque_resource = f"{hash_char * 20}_f{object_id:016x}_"
    fields = [
        "4", action, "---", _name_field(name_id, name_upper), datetime,
        opaque_resource, CHUNK_DESCRIPTORS[chunk_type], created, modified, size, path,
    ]
    row = ("\t".join(fields) + "\n").encode("utf-8")
    if (row[8:24] != _name_field(name_id, name_upper).encode("ascii")
            or row[25:39] != datetime.encode("ascii")
            or row[81:82] != chunk_type.encode("ascii")):
        raise ValueError("invalid legacy fixture fixed columns")
    return row


def queue_row(identifier: int, path: str) -> bytes:
    if any(ch in path for ch in "\t\r\n\0"):
        raise ValueError("fixture queue path contains a forbidden byte")
    return f"1\t+\t{identifier:016x}\t0\t0\t{path}\n".encode("utf-8")


def fix_row(path: str) -> bytes:
    if any(ch in path for ch in "\t\r\n\0"):
        raise ValueError("fixture correction path contains a forbidden byte")
    return (path + "\n").encode("utf-8")


def default_capture(
    *,
    excluded: object = None,
    writers_before: object = (),
    writers_after: object = (),
    writers_started: object = (),
    writer_observation_complete: bool = True,
    pending_thread: object = (),
    pending_main_large: object = (),
    pending_external_before: object = (),
    pending_external_after: object = (),
    repair_markers: object = (),
    catalog_sidecars: object = (),
    pending_coverage_complete: bool = True,
    client_sha256: str = PINNED_CLIENT_SHA256,
) -> dict:
    return {
        "clientSha256": client_sha256,
        "writersBefore": list(writers_before),
        "writersAfter": list(writers_after),
        "writersStarted": list(writers_started),
        "writerObservationComplete": writer_observation_complete,
        "writerDrainComplete": True,
        "historyCoverageComplete": True,
        "unsupportedLedgerNames": [],
        "externalScratchVolumeBefore": {
            "available": True,
            "volumeId": "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\:12345678",
        },
        "externalScratchVolumeAfter": {
            "available": True,
            "volumeId": "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\:12345678",
        },
        "pendingDirectories": {
            "thread": list(pending_thread),
            "mainLarge": list(pending_main_large),
            "externalLargeBefore": list(pending_external_before),
            "externalLargeAfter": list(pending_external_after),
        },
        "repairMarkers": list(repair_markers),
        "catalogSidecars": list(catalog_sidecars),
        "pendingCoverageComplete": pending_coverage_complete,
        "excludedDirectories": [PREFIX] if excluded is None else list(excluded),
        "includedDirectories": [],
    }


def counter_for(max_id: int, gap: int = 0x100) -> bytes:
    return f"{max_id + gap:x}\n".encode("ascii")


class Catalog:
    """Append-only catalog builder with explicit, strictly increasing IDs."""

    def __init__(self) -> None:
        self.rows: list[bytes] = []
        self.meta: list[dict] = []
        self.next_id = 1
        self._size = 0
        self._fillers = 0

    @property
    def data(self) -> bytes:
        return b"".join(self.rows)

    @property
    def size(self) -> int:
        return self._size

    @property
    def max_id(self) -> int:
        return self.meta[-1]["id"] if self.meta else 0

    def add(
        self,
        path: str,
        *,
        identifier: int | None = None,
        chunk: bool = False,
        index: int = 0,
        eol: str = "\n",
        uppercase: bool = False,
    ) -> dict:
        if identifier is None:
            identifier = self.next_id
        if identifier <= 0 or (self.meta and identifier <= self.meta[-1]["id"]):
            raise ValueError("fixture catalog IDs must be positive and strictly increasing")
        raw = (
            chunk_row(identifier, index, path, eol, uppercase=uppercase)
            if chunk
            else ordinary_row(identifier, path, eol, uppercase=uppercase)
        )
        meta = {
            "id": identifier,
            "path": path,
            "raw": raw,
            "offset": self._size,
            "index": len(self.rows),
            "chunk": chunk,
        }
        self.rows.append(raw)
        self.meta.append(meta)
        self._size += len(raw)
        self.next_id = identifier + 1
        return meta

    def add_filler(self, count: int = 1, *, width: int | None = None) -> None:
        for _ in range(count):
            number = self._fillers
            self._fillers += 1
            if width is None:
                self.add(f"{OUTSIDE}filler-{number:06d}.dat")
            else:
                self.add(f"{OUTSIDE}{'f' * width}_{number:05d}.dat")

    def add_pad(self, total_length: int) -> dict:
        path_length = total_length - 18
        if path_length < 1:
            raise ValueError("pad row is too short for a catalog path")
        if path_length >= len(OUTSIDE):
            path = OUTSIDE + "p" * (path_length - len(OUTSIDE))
        else:
            path = "C" * path_length
        row = self.add(path)
        if len(row["raw"]) != total_length:
            raise AssertionError("pad row length was not exact")
        return row

    def pop(self) -> dict:
        if not self.rows:
            raise IndexError("fixture catalog is empty")
        row = self.meta.pop()
        self.rows.pop()
        self._size -= len(row["raw"])
        self.next_id = row["id"]
        return row


def finish_tail(catalog: Catalog, rows: int = 40, width: int = 300) -> None:
    """Append outside-prefix rows that make the protected 10,000-byte tail real."""
    catalog.add_filler(rows, width=width)
    if catalog.size < 10000:
        raise AssertionError("fixture tail is shorter than the native recovery window")


class Fixture:
    def __init__(self, root: Path, files: dict[str, bytes], manifest: dict) -> None:
        self.root = root
        self.files = files
        self.manifest = manifest

    @property
    def counter(self) -> bytes:
        return self.files["bzlastassignedfileid.dat"]

    @property
    def catalog(self) -> bytes:
        return self.files["bzfileids.dat"]


def write_snapshot(
    root: Path,
    catalog: bytes | bytearray,
    *,
    counter: bytes,
    ledgers: dict[str, bytes] | None = None,
    queues: dict[str, bytes] | None = None,
    tofix: dict[str, bytes] | None = None,
    capture: object = OMIT,
    complete: bool = True,
) -> Fixture:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    files: dict[str, bytes] = {
        "bzfileids.dat": bytes(catalog),
        "bzlastassignedfileid.dat": bytes(counter),
    }
    for name, data in sorted((ledgers if ledgers is not None else {DEFAULT_LEDGER: b""}).items()):
        files[f"bzdatacenter/{name}"] = bytes(data)
    for name, data in sorted((queues or {}).items()):
        files[f"bzdatacenter/{name}"] = bytes(data)
    for name, data in sorted((tofix or {}).items()):
        files[f"bzdatacenter/bz_tofix/{name}"] = bytes(data)
    for relative, data in files.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    manifest = {
        "kind": KIND,
        "complete": complete,
        "files": [
            {
                "path": relative.replace("\\", "/"),
                "bytes": len(data),
                "sha256": sha256_hex(data),
            }
            for relative, data in files.items()
        ],
    }
    if capture is not OMIT:
        manifest["capture"] = capture
    (root / "snapshot.json").write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))
    return Fixture(root, files, manifest)


def fingerprints(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha256_hex(path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def is_candidate_path(path: str) -> bool:
    return path[: len(PREFIX)].lower() == PREFIX.lower()


def candidate_metas(catalog: Catalog) -> list[dict]:
    return [row for row in catalog.meta if not row["chunk"] and is_candidate_path(row["path"])]
