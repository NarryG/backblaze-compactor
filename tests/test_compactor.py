"""Black-box contract tests for the offline Backblaze catalog compactor CLI.

The tests build complete, deterministic synthetic snapshots in isolated
temporary directories and invoke the already-built Release DLL. They never
read or write live Backblaze state, never start a native Backblaze executable,
and never inspect original backed-up paths or timestamps.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fixtures import (
    DEFAULT_LEDGER,
    OMIT,
    OUTSIDE,
    PREFIX,
    TOFIX_NAME,
    Catalog,
    candidate_metas,
    counter_for,
    default_capture,
    finish_tail,
    fingerprints,
    fix_row,
    ledger_v4,
    ledger_v5,
    ordinary_row,
    queue_row,
    write_snapshot,
)

ROOT = Path(__file__).resolve().parents[1]
DLL = ROOT / "src" / "BackblazeCompactor" / "bin" / "Release" / "net10.0" / "BackblazeCompactor.dll"
DOTNET = shutil.which("dotnet")
OUTPUT_FILES = ["bzfileids.dat", "bzfileids.removed.dat", "bzlastassignedfileid.dat", "compaction.json"]


def nonzero_kept(report: dict) -> dict[str, int]:
    return {key: value for key, value in report.get("kept", {}).items() if value}


class CompactorCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if DOTNET is None:
            raise unittest.SkipTest("dotnet is not on PATH")
        if not DLL.is_file():
            raise unittest.SkipTest(f"Release DLL not built yet: {DLL}")

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="bzc-tests-")
        self.addCleanup(self._temporary.cleanup)
        self.tmp = Path(self._temporary.name).resolve()

    # ------------------------------------------------------------------ CLI
    def _run(self, *arguments: object, timeout: int = 300) -> subprocess.CompletedProcess:
        environment = dict(os.environ)
        environment["DOTNET_NOLOGO"] = "1"
        environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
        return subprocess.run(
            [DOTNET, str(DLL), *(str(argument) for argument in arguments)],
            cwd=str(ROOT),
            capture_output=True,
            timeout=timeout,
            env=environment,
        )

    @staticmethod
    def _diagnostic(process: subprocess.CompletedProcess) -> str:
        stdout = process.stdout[-2000:].decode("utf-8", "replace")
        stderr = process.stderr[-4000:].decode("utf-8", "replace")
        return f"exit={process.returncode}\nstdout={stdout!r}\nstderr={stderr!r}"

    def _json_stdout(self, process: subprocess.CompletedProcess) -> dict:
        try:
            value = json.loads(process.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            self.fail(f"stdout was not one JSON document ({error}): {self._diagnostic(process)}")
        if not isinstance(value, dict):
            self.fail(f"stdout JSON was not an object: {value!r}")
        return value

    def _snapshot(self, name: str, catalog: Catalog, *, capture: object = None,
                  ledgers: dict[str, bytes] | None = None, queues: dict[str, bytes] | None = None,
                  tofix: dict[str, bytes] | None = None, counter: bytes | None = None):
        if capture is None:
            capture = default_capture()
        if counter is None:
            counter = counter_for(catalog.max_id)
        return write_snapshot(
            self.tmp / name,
            catalog.data,
            counter=counter,
            ledgers=ledgers,
            queues=queues,
            tofix=tofix,
            capture=capture,
        )

    def _candidate_fixture(self, name: str, *, path: str | None = None,
                           ledgers: dict[str, bytes] | None = None,
                           anchor: bool = False,
                           queues: dict[str, bytes] | None = None,
                           tofix: dict[str, bytes] | None = None,
                           capture: object = None,
                           materialize: bool = True):
        catalog = Catalog()
        catalog.add_filler(10)
        candidate = catalog.add(path if path is not None else f"{PREFIX}{name}.txt")
        anchor_row = catalog.add(f"{PREFIX}anchor-{name}.txt") if anchor else None
        finish_tail(catalog)
        fixture = (
            self._snapshot(name, catalog, capture=capture, ledgers=ledgers, queues=queues, tofix=tofix)
            if materialize else None
        )
        return catalog, candidate, anchor_row, fixture

    # ------------------------------------------------------------- assertions
    def assert_bytes(self, actual: bytes, expected: bytes, message: str) -> None:
        if actual == expected:
            return
        limit = min(len(actual), len(expected))
        difference = next((index for index in range(limit) if actual[index] != expected[index]), limit)
        start = max(0, difference - 40)
        self.fail(
            f"{message}: lengths {len(actual)} != {len(expected)}, first difference at byte {difference}; "
            f"actual={actual[start:start + 120]!r} expected={expected[start:start + 120]!r}"
        )

    def assert_before_tail(self, catalog: Catalog, indices: list[int]) -> None:
        boundary = len(catalog.data) - 10000
        for index in indices:
            row = catalog.meta[index]
            self.assertLessEqual(
                row["offset"] + len(row["raw"]), boundary,
                f"fixture row {index} is not before the protected 10,000-byte tail",
            )

    def check_report(self, report: dict, catalog: Catalog, removed_indices: list[int], *,
                     kept: dict[str, int] | None, unreferenced: int, deleted: int,
                     can_compact: bool) -> None:
        candidates = candidate_metas(catalog)
        removed = sorted(set(removed_indices))
        eligible_bytes = sum(len(catalog.meta[index]["raw"]) for index in removed)
        self.assertEqual(report["candidateRows"], len(candidates))
        self.assertEqual(report["candidateBytes"], sum(len(row["raw"]) for row in candidates))
        self.assertEqual(report["eligibleRows"], len(removed))
        self.assertEqual(report["eligibleBytes"], eligible_bytes)
        self.assertEqual(report["unreferencedRows"], unreferenced)
        self.assertEqual(report["deletedRows"], deleted)
        self.assertEqual(report["catalogBytes"], len(catalog.data))
        self.assertEqual(report["catalogRows"], len(catalog.rows))
        if kept is None:
            self.assertEqual(sum(nonzero_kept(report).values()), len(candidates) - len(removed))
        else:
            self.assertEqual(nonzero_kept(report), kept)
        self.assertEqual(report["canCompact"], can_compact)
        if can_compact:
            self.assertEqual(report["writeBlockers"], [])
        else:
            self.assertIsInstance(report["writeBlockers"], list)
            self.assertTrue(report["writeBlockers"], "a blocked analysis must explain why")

    def analyze(self, fixture) -> dict:
        process = self._run("analyze", fixture.root, "--retired-prefix", PREFIX)
        self.assertEqual(process.returncode, 0, self._diagnostic(process))
        report = self._json_stdout(process)
        self.assertEqual(report.get("mode"), "analyze")
        self.assertEqual(report.get("retiredPrefix"), PREFIX)
        return report

    def compact_ok(self, fixture, catalog: Catalog, name: str, removed_indices: list[int], *,
                   kept: dict[str, int] | None, unreferenced: int, deleted: int,
                   counter: bytes | None = None, ignored_tail: int | None = None) -> dict:
        removed = sorted(set(removed_indices))
        output = self.tmp / name
        self.assert_before_tail(catalog, removed)
        before = fingerprints(fixture.root)
        process = self._run("compact", fixture.root, output, "--retired-prefix", PREFIX)
        self.assertEqual(process.returncode, 0, self._diagnostic(process))
        self.assertEqual(fingerprints(fixture.root), before, "compact changed a source snapshot byte")
        self.assertEqual(sorted(path.name for path in output.iterdir()), sorted(OUTPUT_FILES))
        files = {name: (output / name).read_bytes() for name in OUTPUT_FILES}
        expected_kept = b"".join(
            row["raw"] for index, row in enumerate(catalog.meta) if index not in removed
        )
        expected_removed = b"".join(catalog.meta[index]["raw"] for index in removed)
        self.assert_bytes(files["bzfileids.dat"], expected_kept, "retained catalog")
        self.assert_bytes(files["bzfileids.removed.dat"], expected_removed, "removed records")
        self.assert_bytes(
            files["bzlastassignedfileid.dat"],
            fixture.counter if counter is None else counter,
            "allocation counter",
        )
        manifest = json.loads(files["compaction.json"])
        self.check_report(manifest, catalog, removed, kept=kept, unreferenced=unreferenced,
                          deleted=deleted, can_compact=True)
        self.assertEqual(manifest["mode"], "compact")
        if ignored_tail is not None:
            self.assertEqual(manifest.get("ignoredLedgerTailBytes"), ignored_tail)
        return manifest

    def compact_fails(self, fixture, name: str) -> subprocess.CompletedProcess:
        output = self.tmp / name
        process = self._run("compact", fixture.root, output, "--retired-prefix", PREFIX)
        self.assertNotEqual(process.returncode, 0, self._diagnostic(process))
        self.assertFalse(output.exists(), "a failed compact must not publish an output directory")
        return process

    def verify_ok(self, fixture, output: Path) -> dict:
        process = self._run("verify", fixture.root, output, "--retired-prefix", PREFIX)
        self.assertEqual(process.returncode, 0, self._diagnostic(process))
        result = self._json_stdout(process)
        self.assertIs(result.get("verified"), True)
        return result

    def verify_fails(self, fixture, output: Path) -> subprocess.CompletedProcess:
        process = self._run("verify", fixture.root, output, "--retired-prefix", PREFIX)
        self.assertNotEqual(process.returncode, 0, self._diagnostic(process))
        return process

    # --------------------------------------------------------------- behavior
    def test_unreferenced_candidate_is_removed(self) -> None:
        catalog, candidate, _, fixture = self._candidate_fixture("unreferenced")
        report = self.analyze(fixture)
        self.check_report(report, catalog, [candidate["index"]], kept={}, unreferenced=1,
                          deleted=0, can_compact=True)
        self.compact_ok(fixture, catalog, "unreferenced-out", [candidate["index"]],
                        kept={}, unreferenced=1, deleted=0)

    def test_completed_minus_candidate_is_removed(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        candidate = catalog.add(f"{PREFIX}completed-minus.txt")
        finish_tail(catalog)
        ledger = (
            ledger_v5("+", candidate["path"], candidate["id"])
            + ledger_v5("-", candidate["path"], candidate["id"], chunk_type="-")
        )
        fixture = self._snapshot("completed-minus", catalog, ledgers={DEFAULT_LEDGER: ledger})
        report = self.analyze(fixture)
        self.check_report(report, catalog, [candidate["index"]], kept={}, unreferenced=0,
                          deleted=1, can_compact=True)
        self.compact_ok(fixture, catalog, "completed-minus-out", [candidate["index"]],
                        kept={}, unreferenced=0, deleted=1)

    def test_x_expiration_does_not_qualify_without_minus(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        active = catalog.add(f"{PREFIX}x-active.txt")
        deleted = catalog.add(f"{PREFIX}x-deleted.txt")
        finish_tail(catalog)
        ledger = (
            ledger_v5("+", active["path"], active["id"])
            + ledger_v5("x", active["path"], active["id"])
            + ledger_v5("+", deleted["path"], deleted["id"])
            + ledger_v5("-", deleted["path"], deleted["id"], chunk_type="-")
            + ledger_v5("x", deleted["path"], deleted["id"])
        )
        fixture = self._snapshot("x-expiry", catalog, ledgers={DEFAULT_LEDGER: ledger})
        report = self.analyze(fixture)
        self.check_report(report, catalog, [deleted["index"]], kept={"active": 1},
                          unreferenced=0, deleted=1, can_compact=True)
        self.compact_ok(fixture, catalog, "x-expiry-out", [deleted["index"]],
                        kept={"active": 1}, unreferenced=0, deleted=1)

    def test_plus_after_minus_keeps_candidate(self) -> None:
        catalog, candidate, anchor, _ = self._candidate_fixture(
            "plus-after-minus", anchor=True, materialize=False,
        )
        ledger = (
            ledger_v5("+", candidate["path"], candidate["id"])
            + ledger_v5("-", candidate["path"], candidate["id"], chunk_type="-")
            + ledger_v5("+", candidate["path"], candidate["id"])
        )
        fixture = self._snapshot("plus-after-minus", catalog, ledgers={DEFAULT_LEDGER: ledger})
        report = self.analyze(fixture)
        self.check_report(report, catalog, [anchor["index"]], kept={"active": 1},
                          unreferenced=1, deleted=0, can_compact=True)
        manifest = self.compact_ok(fixture, catalog, "plus-after-minus-out", [anchor["index"]],
                                   kept={"active": 1}, unreferenced=1, deleted=0)
        self.assert_bytes(
            (self.tmp / "plus-after-minus-out" / "bzfileids.dat").read_bytes(),
            b"".join(row["raw"] for row in catalog.meta if row["index"] != anchor["index"]),
            "candidate with a reopening plus",
        )
        self.assertEqual(manifest["deletedRows"], 0)

    def test_ledger_file_and_physical_order_beat_datetime(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        physically_reopened = catalog.add(f"{PREFIX}physical-order.txt")
        file_order_deleted = catalog.add(f"{PREFIX}file-order.txt")
        finish_tail(catalog)
        first = (
            ledger_v5("-", physically_reopened["path"], physically_reopened["id"],
                      chunk_type="-", datetime="20260103000000")
            + ledger_v5("+", physically_reopened["path"], physically_reopened["id"],
                        datetime="20260101000000")
            + ledger_v5("+", file_order_deleted["path"], file_order_deleted["id"],
                        datetime="20260102000000")
        )
        second = ledger_v5("-", file_order_deleted["path"], file_order_deleted["id"],
                           chunk_type="-", datetime="20260101000000")
        fixture = self._snapshot("order", catalog, ledgers={
            "bz_done_20260101_0.dat": first,
            "bz_done_20260102_0.dat": second,
        })
        report = self.analyze(fixture)
        self.check_report(report, catalog, [file_order_deleted["index"]], kept={"active": 1},
                          unreferenced=0, deleted=1, can_compact=True)
        self.assertEqual(report.get("ledgerFiles"), 2)
        manifest = self.compact_ok(fixture, catalog, "order-out", [file_order_deleted["index"]],
                                   kept={"active": 1}, unreferenced=0, deleted=1)
        self.assertEqual(manifest["ledgerRows"], 4)

    def test_never_large_parent_kept_including_chunk_catalog_association(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        chunk_parent = catalog.add(f"{PREFIX}large-chunk-parent.txt")
        ledger_parent = catalog.add(f"{PREFIX}large-ledger-parent.txt")
        anchor = catalog.add(f"{PREFIX}large-anchor.txt")
        chunk = catalog.add(chunk_parent["path"], chunk=True, index=1)
        finish_tail(catalog)
        ledger = (
            ledger_v5("+", chunk_parent["path"], chunk_parent["id"])
            + ledger_v5("-", chunk_parent["path"], chunk_parent["id"], chunk_type="-")
            + ledger_v5("+", ledger_parent["path"], ledger_parent["id"], chunk_type="5")
            + ledger_v5("-", ledger_parent["path"], ledger_parent["id"], chunk_type="-")
        )
        fixture = self._snapshot("never-large", catalog, ledgers={DEFAULT_LEDGER: ledger})
        report = self.analyze(fixture)
        self.assertEqual(report["chunkRows"], 1)
        self.check_report(report, catalog, [anchor["index"]], kept={"large": 2},
                          unreferenced=1, deleted=0, can_compact=True)
        manifest = self.compact_ok(fixture, catalog, "never-large-out", [anchor["index"]],
                                   kept={"large": 2}, unreferenced=1, deleted=0)
        self.assertEqual(manifest["chunkRows"], 1)
        self.assertIn(chunk["raw"], (self.tmp / "never-large-out" / "bzfileids.dat").read_bytes())

    def test_foreign_dedupe_object_reference_keeps_candidate(self) -> None:
        catalog, candidate, anchor, _ = self._candidate_fixture(
            "foreign-object", anchor=True, materialize=False,
        )
        ledger = ledger_v5(
            "+", "C:\\Elsewhere\\unrelated.txt", 0x500,
            object_id=candidate["id"],
        )
        fixture = self._snapshot("foreign-object", catalog, ledgers={DEFAULT_LEDGER: ledger})
        report = self.analyze(fixture)
        self.check_report(report, catalog, [anchor["index"]], kept={"referenced": 1},
                          unreferenced=1, deleted=0, can_compact=True)
        self.compact_ok(fixture, catalog, "foreign-object-out", [anchor["index"]],
                        kept={"referenced": 1}, unreferenced=1, deleted=0)

    def test_pending_todo_id_keeps_candidate(self) -> None:
        catalog, candidate, anchor, _ = self._candidate_fixture(
            "pending-todo", anchor=True, materialize=False,
        )
        queue = queue_row(candidate["id"], candidate["path"])
        fixture = self._snapshot("pending-todo", catalog, queues={"bz_todo_20260101_0.dat": queue})
        report = self.analyze(fixture)
        self.check_report(report, catalog, [anchor["index"]], kept={"pending": 1},
                          unreferenced=1, deleted=0, can_compact=True)
        self.assertEqual(report.get("queueRows"), 1)
        self.compact_ok(fixture, catalog, "pending-todo-out", [anchor["index"]],
                        kept={"pending": 1}, unreferenced=1, deleted=0)

    def test_path_only_tofix_keeps_candidate(self) -> None:
        catalog, candidate, anchor, _ = self._candidate_fixture(
            "pending-fix", anchor=True, materialize=False,
        )
        fixture = self._snapshot(
            "pending-fix", catalog,
            tofix={TOFIX_NAME: fix_row(candidate["path"])},
        )
        report = self.analyze(fixture)
        self.check_report(report, catalog, [anchor["index"]], kept={"pending": 1},
                          unreferenced=1, deleted=0, can_compact=True)
        self.compact_ok(fixture, catalog, "pending-fix-out", [anchor["index"]],
                        kept={"pending": 1}, unreferenced=1, deleted=0)

    def test_ledger_aliases_keep_candidate(self) -> None:
        cases = {
            "same-id-different-path": lambda candidate: ledger_v5(
                "-", f"{PREFIX}alias-other.txt", candidate["id"], chunk_type="-",
            ),
            "same-path-different-id": lambda candidate: ledger_v5(
                "-", candidate["path"], 0x500, chunk_type="-",
            ),
        }
        for name, make_record in cases.items():
            with self.subTest(alias=name):
                catalog, candidate, anchor, _ = self._candidate_fixture(
                    f"alias-{name}", anchor=True, materialize=False,
                )
                fixture = self._snapshot(
                    f"alias-{name}", catalog,
                    ledgers={DEFAULT_LEDGER: make_record(candidate)},
                )
                report = self.analyze(fixture)
                self.check_report(report, catalog, [anchor["index"]], kept={"referenced": 1},
                                  unreferenced=1, deleted=0, can_compact=True)
                self.compact_ok(fixture, catalog, f"alias-{name}-out", [anchor["index"]],
                                kept={"referenced": 1}, unreferenced=1, deleted=0)

    def test_uppercase_catalog_and_ledger_name_id_is_eligible(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        candidate = catalog.add(f"{PREFIX}UpperCaseEligible.txt", uppercase=True)
        finish_tail(catalog)
        counter = b"ABCD\n"
        ledger = (
            ledger_v5("+", candidate["path"], candidate["id"], name_upper=True)
            + ledger_v5("-", candidate["path"], candidate["id"], chunk_type="-", name_upper=True)
        )
        fixture = self._snapshot("uppercase-eligible", catalog,
                                 ledgers={DEFAULT_LEDGER: ledger}, counter=counter)
        report = self.analyze(fixture)
        self.assertEqual(report.get("watermarkHex"), f"{0xABCD:016x}")
        self.check_report(report, catalog, [candidate["index"]], kept={}, unreferenced=0,
                          deleted=1, can_compact=True)
        manifest = self.compact_ok(fixture, catalog, "uppercase-eligible-out",
                                   [candidate["index"]], kept={}, unreferenced=0,
                                   deleted=1, counter=counter)
        self.assertEqual(manifest.get("watermarkHex"), f"{0xABCD:016x}")
        self.assert_bytes(
            (self.tmp / "uppercase-eligible-out" / "bzlastassignedfileid.dat").read_bytes(),
            b"ABCD\n",
            "source counter hex case",
        )

    def test_lowercase_minus_does_not_complete_uppercase_plus(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        candidate = catalog.add(f"{PREFIX}CaseSensitive.txt", uppercase=True)
        anchor = catalog.add(f"{PREFIX}case-anchor.txt")
        finish_tail(catalog)
        ledger = (
            ledger_v5("+", candidate["path"], candidate["id"], name_upper=True)
            + ledger_v5("-", candidate["path"], candidate["id"], chunk_type="-")
        )
        fixture = self._snapshot("case-sensitive", catalog,
                                 ledgers={DEFAULT_LEDGER: ledger})
        report = self.analyze(fixture)
        self.check_report(report, catalog, [anchor["index"]], kept=None,
                          unreferenced=1, deleted=0, can_compact=True)
        self.assertEqual(sum(nonzero_kept(report).values()), 1)
        self.compact_ok(fixture, catalog, "case-sensitive-out", [anchor["index"]],
                        kept=None, unreferenced=1, deleted=0)
        kept = (self.tmp / "case-sensitive-out" / "bzfileids.dat").read_bytes()
        self.assertIn(candidate["raw"], kept)
        self.assertNotIn(anchor["raw"], kept)

    def test_prefix_boundary_and_case_policy(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        upper = catalog.add(f"{PREFIX}upper.txt")
        lower = catalog.add("d:\\scratch\\lower.txt")
        adjacent = catalog.add("D:\\Scratch2\\adjacent.txt")
        exact = catalog.add("D:\\Scratch")
        finish_tail(catalog)
        fixture = self._snapshot("prefix-boundary", catalog)
        report = self.analyze(fixture)
        self.check_report(report, catalog, [upper["index"], lower["index"]], kept={},
                          unreferenced=2, deleted=0, can_compact=True)
        manifest = self.compact_ok(fixture, catalog, "prefix-boundary-out",
                                   [upper["index"], lower["index"]], kept={},
                                   unreferenced=2, deleted=0)
        self.assertEqual(manifest["candidateRows"], 2)
        kept = (self.tmp / "prefix-boundary-out" / "bzfileids.dat").read_bytes()
        self.assertIn(adjacent["raw"], kept)
        self.assertIn(exact["raw"], kept)
        self.assertNotIn(upper["raw"], kept)
        self.assertNotIn(lower["raw"], kept)

    def test_tail_includes_crossing_row_and_whole_rows(self) -> None:
        catalog = Catalog()
        catalog.add_filler(20)
        early = catalog.add(f"{PREFIX}tail-early.txt")
        crossing = catalog.add(f"{PREFIX}cross-" + "x" * 7800 + ".dat")
        tail_row = catalog.add(f"{PREFIX}tail-row.txt")
        catalog.add_filler(24, width=300)
        boundary = len(catalog.data) - 10000
        self.assertLessEqual(early["offset"] + len(early["raw"]), boundary)
        self.assertLess(crossing["offset"], boundary)
        self.assertLess(boundary, crossing["offset"] + len(crossing["raw"]))
        self.assertGreaterEqual(tail_row["offset"], boundary)
        fixture = self._snapshot("tail", catalog)
        report = self.analyze(fixture)
        self.check_report(report, catalog, [early["index"]], kept={"tail": 2},
                          unreferenced=1, deleted=0, can_compact=True)
        self.compact_ok(fixture, catalog, "tail-out", [early["index"]], kept={"tail": 2},
                        unreferenced=1, deleted=0)
        kept = (self.tmp / "tail-out" / "bzfileids.dat").read_bytes()
        self.assertEqual(kept[-10000:], catalog.data[-10000:], "protected tail bytes changed")
        self.assertIn(crossing["raw"], kept)
        self.assertIn(tail_row["raw"], kept)
        self.assertNotIn(early["raw"], kept)

    def test_counter_gaps_and_unpadded_bytes_unchanged(self) -> None:
        catalog = Catalog()
        catalog.add("C:\\Keep\\one.dat", identifier=1)
        catalog.add("C:\\Keep\\five.dat", identifier=5)
        candidate = catalog.add(f"{PREFIX}gap.txt", identifier=9)
        finish_tail(catalog, rows=40, width=300)
        counter = b"abcd\n"
        fixture = self._snapshot("counter-gap", catalog, counter=counter)
        report = self.analyze(fixture)
        self.assertEqual(report.get("watermarkHex"), f"{0xABCD:016x}")
        self.check_report(report, catalog, [candidate["index"]], kept={}, unreferenced=1,
                          deleted=0, can_compact=True)
        manifest = self.compact_ok(fixture, catalog, "counter-gap-out", [candidate["index"]],
                                   kept={}, unreferenced=1, deleted=0, counter=counter)
        self.assertEqual(manifest.get("watermarkHex"), f"{0xABCD:016x}")

    def test_preserves_lf_crlf_and_utf8_bytes(self) -> None:
        catalog = Catalog()
        plain = catalog.add("C:\\Keep\\plain.txt", eol="\n")
        unicode_row = catalog.add("C:\\Keep\\Grüße-日本.txt", eol="\n")
        crlf = catalog.add("C:\\Keep\\crlf.txt", eol="\r\n")
        candidate = catalog.add(f"{PREFIX}utf8-remove.txt")
        finish_tail(catalog)
        fixture = self._snapshot("bytes", catalog)
        report = self.analyze(fixture)
        self.check_report(report, catalog, [candidate["index"]], kept={}, unreferenced=1,
                          deleted=0, can_compact=True)
        self.compact_ok(fixture, catalog, "bytes-out", [candidate["index"]], kept={},
                        unreferenced=1, deleted=0)
        kept = (self.tmp / "bytes-out" / "bzfileids.dat").read_bytes()
        self.assertIn(plain["raw"], kept)
        self.assertIn(unicode_row["raw"], kept)
        self.assertIn(crlf["raw"], kept)
        self.assertTrue(crlf["raw"].endswith(b"\r\n"))
        self.assertIn("Grüße-日本".encode("utf-8"), kept)
        self.assertEqual(kept, b"".join(
            row["raw"] for row in catalog.meta if row["index"] != candidate["index"]
        ))

    def test_malformed_inputs_fail_without_publishing(self) -> None:
        cases = {
            "catalog-key": b"not-a-hex-key\tC:\\bad.txt\n",
            "catalog-nonhex": b"00000000000000zz\tC:\\bad.txt\n",
            "catalog-nul": b"0000000000000001\tC:\\bad\x00path.txt\n",
            "catalog-unterminated": b"0000000000000001\tC:\\bad.txt",
            "catalog-comment": b"# " + b"a" * 40 + b"\tC:\\bad.txt\n",
        }
        for name, catalog_bytes in cases.items():
            with self.subTest(case=name):
                fixture = write_snapshot(
                    self.tmp / name,
                    catalog_bytes,
                    counter=b"100\n",
                    capture=default_capture(),
                )
                self._assert_analyze_fails(fixture)
                self.compact_fails(fixture, f"{name}-out")

        valid_catalog = ordinary_row(1, f"{OUTSIDE}ok.txt") + ordinary_row(2, f"{OUTSIDE}two.txt")
        bad_ledger = ledger_v5("q", f"{OUTSIDE}ok.txt", 1)
        ledger_fixture = write_snapshot(
            self.tmp / "ledger-action",
            valid_catalog,
            counter=b"100\n",
            ledgers={DEFAULT_LEDGER: bad_ledger},
            capture=default_capture(),
        )
        self._assert_analyze_fails(ledger_fixture)
        self.compact_fails(ledger_fixture, "ledger-action-out")

        unterminated_queue = queue_row(1, f"{OUTSIDE}ok.txt")[:-1]
        queue_fixture = write_snapshot(
            self.tmp / "queue-unterminated",
            valid_catalog,
            counter=b"100\n",
            queues={"bz_todo_20260101_0.dat": unterminated_queue},
            capture=default_capture(),
        )
        self._assert_analyze_fails(queue_fixture)
        self.compact_fails(queue_fixture, "queue-unterminated-out")

    def _assert_analyze_fails(self, fixture) -> None:
        process = self._run("analyze", fixture.root, "--retired-prefix", PREFIX)
        self.assertNotEqual(process.returncode, 0, self._diagnostic(process))

    def test_source_fingerprint_mismatch_fails(self) -> None:
        catalog, _, _, fixture = self._candidate_fixture("fingerprint")
        catalog_path = fixture.root / "bzfileids.dat"
        data = bytearray(catalog_path.read_bytes())
        tab = data.index(b"\t")
        data[tab + 1] = ord("Z") if data[tab + 1] != ord("Z") else ord("Y")
        catalog_path.write_bytes(bytes(data))
        self._assert_analyze_fails(fixture)
        self.compact_fails(fixture, "fingerprint-out")

    def test_global_duplicate_name_outside_prefix_fails(self) -> None:
        catalog = Catalog()
        catalog.add(f"{OUTSIDE}duplicate.txt")
        catalog.add(f"{OUTSIDE}duplicate.txt")
        catalog.add_filler(5)
        fixture = self._snapshot("duplicate", catalog)
        self._assert_analyze_fails(fixture)
        self.compact_fails(fixture, "duplicate-out")

    def test_analyze_is_read_only(self) -> None:
        catalog, candidate, _, fixture = self._candidate_fixture("readonly")
        before = fingerprints(fixture.root)
        report = self.analyze(fixture)
        self.check_report(report, catalog, [candidate["index"]], kept={}, unreferenced=1,
                          deleted=0, can_compact=True)
        self.assertEqual(fingerprints(fixture.root), before, "analyze modified the snapshot")

    def test_compact_rejects_existing_output(self) -> None:
        _, _, _, fixture = self._candidate_fixture("existing-output")
        directory = self.tmp / "existing-directory"
        directory.mkdir()
        sentinel = directory / "keep.txt"
        sentinel.write_bytes(b"do not replace")
        process = self._run("compact", fixture.root, directory, "--retired-prefix", PREFIX)
        self.assertNotEqual(process.returncode, 0, self._diagnostic(process))
        self.assertEqual([path.name for path in directory.iterdir()], ["keep.txt"])
        self.assertEqual(sentinel.read_bytes(), b"do not replace")

        existing_file = self.tmp / "existing-file"
        existing_file.write_bytes(b"do not replace")
        process = self._run("compact", fixture.root, existing_file, "--retired-prefix", PREFIX)
        self.assertNotEqual(process.returncode, 0, self._diagnostic(process))
        self.assertEqual(existing_file.read_bytes(), b"do not replace")

        inside = fixture.root / "inside"
        process = self._run("compact", fixture.root, inside, "--retired-prefix", PREFIX)
        self.assertNotEqual(process.returncode, 0, self._diagnostic(process))
        self.assertFalse(inside.exists())

    def test_verify_detects_output_tampering(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        upper = catalog.add(f"{PREFIX}verify-upper.txt")
        lower = catalog.add("d:\\scratch\\verify-lower.txt")
        finish_tail(catalog)
        fixture = self._snapshot("verify-base", catalog)
        self.compact_ok(fixture, catalog, "verify-base-out", [upper["index"], lower["index"]],
                        kept={}, unreferenced=2, deleted=0)
        base = self.tmp / "verify-base-out"
        self.verify_ok(fixture, base)

        def copy_output(name: str) -> Path:
            destination = self.tmp / name
            shutil.copytree(base, destination)
            return destination

        with self.subTest(tamper="same-length-catalog"):
            tampered = copy_output("tamper-catalog")
            path = tampered / "bzfileids.dat"
            data = bytearray(path.read_bytes())
            tab = data.index(b"\t")
            data[tab + 1] = ord("Z") if data[tab + 1] != ord("Z") else ord("Y")
            path.write_bytes(bytes(data))
            self.verify_fails(fixture, tampered)

        with self.subTest(tamper="removed-records"):
            tampered = copy_output("tamper-removed")
            path = tampered / "bzfileids.removed.dat"
            lines = path.read_bytes().splitlines(keepends=True)
            path.write_bytes(b"".join(lines[:-1]))
            self.verify_fails(fixture, tampered)

        with self.subTest(tamper="counter"):
            tampered = copy_output("tamper-counter")
            path = tampered / "bzlastassignedfileid.dat"
            data = bytearray(path.read_bytes())
            data[0] = ord("1") if data[0] != ord("1") else ord("2")
            path.write_bytes(bytes(data))
            self.verify_fails(fixture, tampered)

        with self.subTest(tamper="ledger-addition"):
            tampered = copy_output("tamper-ledger")
            (tampered / DEFAULT_LEDGER).write_bytes(b"5\t+\t---\n")
            self.verify_fails(fixture, tampered)

    def test_verify_detects_input_ledger_alteration(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        candidate = catalog.add(f"{PREFIX}ledger-altered.txt")
        finish_tail(catalog)
        ledger = (
            ledger_v5("+", candidate["path"], candidate["id"])
            + ledger_v5("-", candidate["path"], candidate["id"], chunk_type="-")
        )
        fixture = self._snapshot("ledger-altered", catalog, ledgers={DEFAULT_LEDGER: ledger})
        self.compact_ok(fixture, catalog, "ledger-altered-out", [candidate["index"]],
                        kept={}, unreferenced=0, deleted=1)
        output = self.tmp / "ledger-altered-out"
        self.verify_ok(fixture, output)
        ledger_path = fixture.root / "bzdatacenter" / DEFAULT_LEDGER
        data = ledger_path.read_bytes()
        self.assertIn(b"a" * 40, data)
        ledger_path.write_bytes(data.replace(b"a" * 40, b"a" * 39 + b"b", 1))
        self.verify_fails(fixture, output)

    def test_write_blocked_when_capture_not_clean(self) -> None:
        cases = {
            "writers-before": default_capture(writers_before=["bztransmit.exe:1234"]),
            "writers-started": default_capture(writers_started=["bztransmit.exe:5678"]),
            "observation-incomplete": default_capture(writer_observation_complete=False),
            "nonempty-thread": default_capture(pending_thread=["bzt_1_instru_1_bzt.xml"]),
            "repair-marker": default_capture(repair_markers=["VSS:bzstat_ibsModifiedBzDoneFile.dat"]),
            "missing-exclusion": default_capture(excluded=["D:\\Other\\"]),
        }
        for name, capture in cases.items():
            with self.subTest(case=name):
                catalog, candidate, _, fixture = self._candidate_fixture(
                    f"blocked-{name}", capture=capture,
                )
                report = self.analyze(fixture)
                self.assertIs(report.get("canCompact"), False)
                self.assertIsInstance(report.get("writeBlockers"), list)
                self.assertTrue(report["writeBlockers"], "blocked analysis must name a write blocker")
                self.assertEqual(report.get("eligibleRows"), 1)
                self.compact_fails(fixture, f"blocked-{name}-out")

        catalog, candidate, _, fixture = self._candidate_fixture(
            "blocked-missing-capture", capture=OMIT,
        )
        report = self.analyze(fixture)
        self.assertIs(report.get("canCompact"), False)
        self.assertTrue(report.get("writeBlockers"))
        self.compact_fails(fixture, "blocked-missing-capture-out")

    def test_legacy_v4_prefix_keeps_all_candidates(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        candidate = catalog.add(f"{PREFIX}legacy-candidate.txt")
        finish_tail(catalog)
        ledger = ledger_v4("+", f"{PREFIX}legacy-other.txt", 0x500)
        fixture = self._snapshot("legacy", catalog, ledgers={DEFAULT_LEDGER: ledger})
        report = self.analyze(fixture)
        self.check_report(report, catalog, [], kept={"legacy": 1}, unreferenced=0,
                          deleted=0, can_compact=False)
        self.assertTrue(report["writeBlockers"])

    def test_ledger_comments_do_not_reactivate_candidate(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        candidate = catalog.add(f"{PREFIX}commented.txt")
        finish_tail(catalog)
        plus = ledger_v5("+", candidate["path"], candidate["id"])
        minus = ledger_v5("-", candidate["path"], candidate["id"], chunk_type="-")
        ledger = (
            plus
            + minus
            + b"# opaque ledger comment that is not a record\n"
            + b"#" + plus
        )
        fixture = self._snapshot("commented", catalog, ledgers={DEFAULT_LEDGER: ledger})
        report = self.analyze(fixture)
        self.check_report(report, catalog, [candidate["index"]], kept={}, unreferenced=0,
                          deleted=1, can_compact=True)
        self.compact_ok(fixture, catalog, "commented-out", [candidate["index"]],
                        kept={}, unreferenced=0, deleted=1)

    def test_ledger_partial_minus_after_active_plus_keeps(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        candidate = catalog.add(f"{PREFIX}partial-minus.txt")
        anchor = catalog.add(f"{PREFIX}partial-minus-anchor.txt")
        finish_tail(catalog)
        plus = ledger_v5("+", candidate["path"], candidate["id"])
        partial = ledger_v5("-", candidate["path"], candidate["id"], chunk_type="-")[:63]
        self.assertNotIn(b"\n", partial)
        fixture = self._snapshot("partial-minus", catalog,
                                 ledgers={DEFAULT_LEDGER: plus + partial})
        before = fingerprints(fixture.root)
        report = self.analyze(fixture)
        self.assertEqual(report.get("ignoredLedgerTailBytes"), len(partial))
        self.assertTrue(report.get("ledgerWarnings"))
        self.check_report(report, catalog, [anchor["index"]], kept={"active": 1},
                          unreferenced=1, deleted=0, can_compact=True)
        self.compact_ok(fixture, catalog, "partial-minus-out", [anchor["index"]],
                        kept={"active": 1}, unreferenced=1, deleted=0,
                        ignored_tail=len(partial))
        self.assertEqual(fingerprints(fixture.root), before)

    def test_ledger_partial_plus_protects_otherwise_eligible_id(self) -> None:
        catalog = Catalog()
        catalog.add_filler(10)
        candidate = catalog.add(f"{PREFIX}partial-plus.txt")
        anchor = catalog.add(f"{PREFIX}partial-plus-anchor.txt")
        finish_tail(catalog)
        partial = ledger_v5("+", candidate["path"], candidate["id"])[:-1]
        self.assertNotIn(b"\n", partial)
        fixture = self._snapshot("partial-plus", catalog,
                                 ledgers={DEFAULT_LEDGER: partial})
        report = self.analyze(fixture)
        self.assertEqual(report.get("ignoredLedgerTailBytes"), len(partial))
        self.assertTrue(report.get("ledgerWarnings"))
        self.check_report(report, catalog, [anchor["index"]], kept=None,
                          unreferenced=1, deleted=0, can_compact=True)
        self.assertEqual(sum(nonzero_kept(report).values()), 1)
        self.compact_ok(fixture, catalog, "partial-plus-out", [anchor["index"]],
                        kept=None, unreferenced=1, deleted=0,
                        ignored_tail=len(partial))
        kept = (self.tmp / "partial-plus-out" / "bzfileids.dat").read_bytes()
        self.assertIn(candidate["raw"], kept)
        self.assertNotIn(anchor["raw"], kept)

    def test_catalog_row_crossing_reader_buffer_boundary(self) -> None:
        catalog = Catalog()
        target = 4 * 1024 * 1024 - 100
        while target - catalog.size >= 4055:
            catalog.add_filler(1, width=4000)
        gap = target - catalog.size
        if gap:
            if gap < 19:
                catalog.pop()
                gap = target - catalog.size
            self.assertGreaterEqual(gap, 19)
            catalog.add_pad(gap)
        self.assertEqual(catalog.size, target)
        crossing = catalog.add(f"{PREFIX}buffer-" + "b" * 370 + ".dat")
        self.assertEqual(crossing["offset"], target)
        self.assertLess(4 * 1024 * 1024, crossing["offset"] + len(crossing["raw"]))
        catalog.add_filler(50, width=300)
        finish_tail(catalog, rows=40, width=300)
        fixture = self._snapshot("buffer-boundary", catalog)
        report = self.analyze(fixture)
        self.assertGreater(report.get("catalogBytes"), 4 * 1024 * 1024)
        self.check_report(report, catalog, [crossing["index"]], kept={}, unreferenced=1,
                          deleted=0, can_compact=True)
        self.compact_ok(fixture, catalog, "buffer-boundary-out", [crossing["index"]],
                        kept={}, unreferenced=1, deleted=0)

    def test_write_requires_complete_capture_evidence(self) -> None:
        changes = {
            "missing-inclusions": ("includedDirectories", OMIT),
            "malformed-inclusions": ("includedDirectories", "D:\\Scratch\\"),
            "partial-inclusions": ("includedDirectories", ["D:\\Other\\", None]),
            "empty-inclusion-selector": ("includedDirectories", [""]),
            "included-descendant": ("includedDirectories", ["D:\\Scratch\\returned\\"]),
            "missing-exclusions": ("excludedDirectories", OMIT),
            "missing-history-proof": ("historyCoverageComplete", OMIT),
            "partial-history": ("historyCoverageComplete", False),
            "unknown-ledger": ("unsupportedLedgerNames", ["prefix_bz_done_20260101_0.dat"]),
            "missing-drain-proof": ("writerDrainComplete", OMIT),
            "incomplete-drain": ("writerDrainComplete", False),
            "missing-scratch-before": ("externalScratchVolumeBefore", OMIT),
            "unavailable-scratch": ("externalScratchVolumeAfter", {"available": False, "volumeId": ""}),
            "changed-scratch": ("externalScratchVolumeAfter", {
                "available": True, "volumeId": "\\\\?\\Volume{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}\\:12345678",
            }),
            "malformed-scratch": ("externalScratchVolumeAfter", {"available": True, "volumeId": "D:\\"}),
        }
        for name, (field, value) in changes.items():
            with self.subTest(case=name):
                capture = default_capture()
                if value is OMIT:
                    capture.pop(field)
                else:
                    capture[field] = value
                _, _, _, fixture = self._candidate_fixture(f"proof-{name}", capture=capture)
                report = self.analyze(fixture)
                self.assertEqual(report["eligibleRows"], 1)
                self.assertIs(report["canCompact"], False)
                self.compact_fails(fixture, f"proof-{name}-out")

    def test_unsupported_ledgers_cannot_authorize_or_hide_lifecycle(self) -> None:
        for indexed in (True, False):
            with self.subTest(indexed=indexed):
                catalog = Catalog()
                candidate = catalog.add(f"{PREFIX}unsupported-ledger.txt")
                finish_tail(catalog)
                if indexed:
                    # A multi-digit suffix moves bz_done_ outside the native
                    # last-22-byte search window: its minus must not be replayed.
                    ledger = ledger_v5("+", candidate["path"], candidate["id"])
                    unknown = ledger_v5("-", candidate["path"], candidate["id"], chunk_type="-")
                    fixture = self._snapshot("ignored-indexed", catalog, ledgers={
                        DEFAULT_LEDGER: ledger, "bz_done_20260102_10.dat": unknown,
                    })
                else:
                    # A prefixed basename IS consumed by the native suffix
                    # window, but cannot be silently omitted from coverage.
                    fixture = self._snapshot("hidden-prefixed", catalog)
                    (fixture.root / "bzdatacenter" / "prefix_bz_done_20260102_0.dat").write_bytes(
                        ledger_v5("+", candidate["path"], candidate["id"]),
                    )
                result = self._run("analyze", fixture.root, "--retired-prefix", PREFIX)
                self.assertNotEqual(result.returncode, 0, self._diagnostic(result))
                self.compact_fails(fixture, f"unsupported-ledger-{indexed}-out")

    def test_in_prefix_dedupe_reference_keeps_completed_mapping(self) -> None:
        catalog = Catalog()
        target = catalog.add(f"{PREFIX}shared-object.txt")
        user = catalog.add(f"{PREFIX}deduplicated-user.txt")
        orphan = catalog.add(f"{PREFIX}unrelated-orphan.txt")
        finish_tail(catalog)
        ledger = (
            ledger_v5("+", target["path"], target["id"], object_id=target["id"])
            + ledger_v5("-", target["path"], target["id"], object_id=target["id"], chunk_type="-")
            + ledger_v5("=", user["path"], user["id"], object_id=target["id"])
        )
        fixture = self._snapshot("inside-dedupe", catalog, ledgers={DEFAULT_LEDGER: ledger})
        report = self.analyze(fixture)
        self.check_report(report, catalog, [orphan["index"]], kept={"referenced": 1, "active": 1},
                          unreferenced=1, deleted=0, can_compact=True)
        self.compact_ok(fixture, catalog, "inside-dedupe-out", [orphan["index"]],
                        kept={"referenced": 1, "active": 1}, unreferenced=1, deleted=0)

    def test_opaque_legacy_reference_outside_prefix_keeps_candidate(self) -> None:
        catalog = Catalog()
        target = catalog.add(f"{PREFIX}legacy-referenced.txt")
        orphan = catalog.add(f"{PREFIX}legacy-unrelated.txt")
        finish_tail(catalog)
        legacy = ledger_v4("+", f"{OUTSIDE}legacy-name.txt", target["id"])
        fixture = self._snapshot("legacy-outside", catalog, ledgers={DEFAULT_LEDGER: legacy})
        report = self.analyze(fixture)
        self.check_report(report, catalog, [orphan["index"]], kept={"referenced": 1},
                          unreferenced=1, deleted=0, can_compact=True)
        self.compact_ok(fixture, catalog, "legacy-outside-out", [orphan["index"]],
                        kept={"referenced": 1}, unreferenced=1, deleted=0)

    def test_normalized_drive_root_is_not_a_retired_directory(self) -> None:
        _, _, _, fixture = self._candidate_fixture("drive-root", capture=default_capture(excluded=["D:\\"]))
        output = self.tmp / "drive-root-out"
        for mode in ("analyze", "compact"):
            arguments = [mode, fixture.root]
            if mode == "compact":
                arguments.append(output)
            process = self._run(*arguments, "--retired-prefix", "D://")
            self.assertNotEqual(process.returncode, 0, self._diagnostic(process))
        self.assertFalse(output.exists())

    def test_verify_requires_operator_retirement_prefix(self) -> None:
        other = "D:\\Other\\"
        catalog = Catalog()
        catalog.add(f"{PREFIX}untouched.txt")
        catalog.add(f"{other}retired.txt")
        finish_tail(catalog)
        fixture = self._snapshot("verify-scope", catalog, capture=default_capture(excluded=[PREFIX, other]))
        output = self.tmp / "verify-scope-out"
        compact = self._run("compact", fixture.root, output, "--retired-prefix", other)
        self.assertEqual(compact.returncode, 0, self._diagnostic(compact))
        no_prefix = self._run("verify", fixture.root, output)
        self.assertNotEqual(no_prefix.returncode, 0, self._diagnostic(no_prefix))
        wrong = self._run("verify", fixture.root, output, "--retired-prefix", PREFIX)
        self.assertNotEqual(wrong.returncode, 0, self._diagnostic(wrong))
        correct = self._run("verify", fixture.root, output, "--retired-prefix", other)
        self.assertEqual(correct.returncode, 0, self._diagnostic(correct))
        self.assertEqual(self._json_stdout(correct)["retiredPrefix"], other)

    def test_explicit_child_exclusion_and_include_ambiguity(self) -> None:
        target = "D:\\Projects\\Work\\Retired\\"
        cases = {
            "selected-drive": ([target], ["D:\\"], True),
            "nearer-include": (["D:\\Projects\\"], ["D:\\Projects\\Work\\"], False),
            "nearer-exclusion": ([target], ["D:\\Projects\\Work\\"], True),
            "included-child": ([target], [target + "returned\\"], False),
            "same-node-conflict": ([target], [target], False),
            "unknown-selector": ([target], ["D:\\Projects\\..\\Other\\"], False),
        }
        for name, (excluded, included, allowed) in cases.items():
            with self.subTest(case=name):
                catalog = Catalog()
                candidate = catalog.add(target + "retired.txt")
                finish_tail(catalog)
                capture = default_capture(excluded=excluded)
                capture["includedDirectories"] = included
                fixture = self._snapshot(f"selectors-{name}", catalog, capture=capture)
                analysis = self._run("analyze", fixture.root, "--retired-prefix", target)
                self.assertEqual(analysis.returncode, 0, self._diagnostic(analysis))
                report = self._json_stdout(analysis)
                self.assertIs(report["exclusionVerified"], allowed)
                self.assertIs(report["canCompact"], allowed)
                output = self.tmp / f"selectors-{name}-out"
                compact = self._run("compact", fixture.root, output, "--retired-prefix", target)
                if allowed:
                    self.assertEqual(compact.returncode, 0, self._diagnostic(compact))
                    self.assertNotIn(candidate["raw"], (output / "bzfileids.dat").read_bytes())
                    verified = self._run("verify", fixture.root, output, "--retired-prefix", target)
                    self.assertEqual(verified.returncode, 0, self._diagnostic(verified))
                else:
                    self.assertNotEqual(compact.returncode, 0, self._diagnostic(compact))
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
