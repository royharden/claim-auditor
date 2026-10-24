"""Future bounded-process/source probes; no worker or Git fixture is created now."""

import io
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from claim_auditor.audit.policy import decide_finding
from claim_auditor.contracts import AuditError, canonical_json
from claim_auditor.index import StaticIndex, build_index, resolve
from claim_auditor.inventory import extract_inventory
from claim_auditor.snapshot import create_fixture_snapshot, create_git_snapshot, read_source, unread_entry_digest
from claim_auditor.snapshot.safeio import MAX_FILE_BYTES, read_ordinary

from .git_fixture import GitFixture
from .support import claim, frozen_source, predicate, span_for


class RepeatedOutput:
    """Bounded in-memory stream fixture; repeated references avoid a 32-MiB allocation."""
    def __init__(self, size):
        self.remaining = size
        self.chunk = b"x" * (64 * 1024)

    def read(self, size):
        count = min(size, self.remaining, len(self.chunk))
        self.remaining -= count
        return self.chunk if count == len(self.chunk) else self.chunk[:count]

    def close(self):
        pass


class WorkerReply:
    """Injected process handshake; never starts a process or imports target code."""
    def __init__(self, raw=b"", *, timeout=False, stdout=None):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(raw) if stdout is None else stdout
        self.stderr = io.BytesIO()
        self.returncode = 0
        self.timeout = timeout
        self.kills = 0

    def wait(self, timeout=None):
        if not self.kills and (timeout is None or not 0 < timeout <= 30):
            raise AssertionError("Live parser wait must have the declared finite deadline")
        if self.timeout and not self.kills:
            raise subprocess.TimeoutExpired("trusted-parser-fixture", timeout)
        return self.returncode

    def kill(self):
        self.kills += 1
        self.returncode = -9


class ResourceBoundaryTests(unittest.TestCase):
    def test_lone_cr_ingress_is_unavailable_scope_never_clean_absence(self):
        """what_bug_this_catches: unsupported lone-CR acquisition being normalized/admitted or accused as absent."""
        with TemporaryDirectory() as directory:
            snapshot, root = frozen_source(Path(directory), readme=b"first\rsecond\r")
            self.assertFalse(snapshot.complete)
            self.assertEqual(next(entry.status for entry in snapshot.entries if entry.path == "README.md"), "excluded")
            self.assertIn("unsupported_lone_cr_line_endings", {gap.reason for gap in snapshot.exclusions})
            with self.assertRaises(AuditError) as caught:
                read_source(snapshot, root, "README.md")
            self.assertEqual(caught.exception.reason, "source_integrity")
            inventory = extract_inventory(snapshot, root, "README.md")
            self.assertFalse(inventory.complete)
            self.assertEqual([(error.reason, error.detail) for error in inventory.errors],
                             [("readme_excluded", "unsupported_lone_cr_line_endings")])
            self.assertEqual((inventory.claims, inventory.blocks), ([], []))
            query = predicate(kind="path_exists", subject="README.md", path="README.md", module=None)
            result = resolve(StaticIndex(snapshot=snapshot, root=root), query)
            self.assertEqual(result.state, "unknown")
            self.assertFalse(any(item.kind == "negative" for item in result.evidence))

    def test_readme_absent_from_snapshot_is_input_error_not_integrity(self):
        """what_bug_this_catches: a README path with no snapshot entry reported as integrity failure (4) instead of input (2)."""
        with TemporaryDirectory() as directory:
            snapshot, root = frozen_source(Path(directory))
            with self.assertRaises(AuditError) as caught:
                extract_inventory(snapshot, root, "docs/MISSING.md")
            self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("readme_not_in_snapshot", 2))

    def test_source_file_byte_cap_excludes_entry_without_reading_or_completing(self):
        """what_bug_this_catches: an oversized source file being read, admitted, or published inside a complete snapshot."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir()
            size = MAX_FILE_BYTES + 1
            (source / "big.py").write_bytes(b"x" * size)
            (source / "tiny.py").write_bytes(b"def work():\n    pass\n")
            out = base / "snapshot"
            with patch("claim_auditor.snapshot.read_ordinary", wraps=read_ordinary) as read:
                snapshot = create_fixture_snapshot(source, out)
            self.assertNotIn("big.py", {str(call.args[1]) for call in read.call_args_list})
            self.assertFalse(snapshot.complete)
            entry = next(entry for entry in snapshot.entries if entry.path == "big.py")
            self.assertEqual((entry.status, entry.size), ("excluded", size))
            self.assertEqual(entry.sha256, unread_entry_digest("file_byte_limit", size))
            self.assertIn(("big.py", "file_byte_limit"), {(gap.path, gap.reason) for gap in snapshot.exclusions})
            self.assertEqual(next(entry.status for entry in snapshot.entries if entry.path == "tiny.py"), "included")
            self.assertFalse((out / "files" / "big.py").exists())
            with self.assertRaises(AuditError) as caught:
                read_source(snapshot, out, "big.py")
            self.assertEqual(caught.exception.exit_code, 4)

    def test_total_text_cap_is_shared_across_files(self):
        """what_bug_this_catches: enforcing each file cap while ignoring the combined snapshot text liability."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir()
            for name in ("first.py", "second.py"):
                (source / name).write_bytes(b"x\n" * 300)
            out = base / "snapshot"
            # Same production guard with a smaller test ceiling, not a large allocation.
            with patch("claim_auditor.snapshot.MAX_TEXT_BYTES", 1024):
                with self.assertRaises(AuditError) as caught:
                    create_fixture_snapshot(source, out)
            self.assertEqual(caught.exception.reason, "snapshot_input")
            self.assertIn("total_text_byte_limit", caught.exception.detail)
            self.assertFalse((out / "manifest.json").exists())

    def test_compressed_object_copy_has_a_shared_byte_cap(self):
        """what_bug_this_catches: copying a local object store without honoring its compressed-byte allowance."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = GitFixture(base)
            out = base / "snapshot"
            with patch("claim_auditor.snapshot.git.MAX_OBJECT_BYTES", 1):
                with self.assertRaises(AuditError) as caught:
                    create_git_snapshot(fixture.root, fixture.head, out)
            self.assertEqual(caught.exception.reason, "git_snapshot_input")
            # The aggregate compressed-copy cap still aborts (only per-file blob caps became excluded scope).
            # The remaining allowance is passed to read_ordinary, so the copy may stop with its own cap reason.
            self.assertTrue(any(reason in caught.exception.detail for reason in
                                ("file_byte_limit", "compressed_object_byte_limit")))
            self.assertFalse((out / "manifest.json").exists())

    def test_small_compressed_object_cannot_bypass_decompressed_blob_cap(self):
        """what_bug_this_catches: treating compressed-object size as a bound on expanded source bytes, or reading an over-cap blob."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            raw = b"x\n" * (MAX_FILE_BYTES // 2 + 1)
            fixture = GitFixture(base, {"README.md": b"Owned oversized blob control.\n", "big.py": raw})
            objects = fixture.root / ".git" / "objects"
            compressed = sum(path.stat().st_size for path in objects.rglob("*") if path.is_file())
            self.assertLess(compressed, MAX_FILE_BYTES)  # Positive compressed-vs-expanded control.
            oid = fixture.git("rev-parse", "HEAD:big.py").decode("ascii").strip()
            out = base / "snapshot"
            snapshot = create_git_snapshot(fixture.root, fixture.head, out)
            self.assertFalse(snapshot.complete)
            entry = next(entry for entry in snapshot.entries if entry.path == "big.py")
            self.assertEqual((entry.status, entry.size), ("excluded", len(raw)))
            # Expanded size comes from batch-check; the marker binds the object ID, never unread content.
            self.assertEqual(entry.sha256, unread_entry_digest("file_byte_limit", len(raw), oid))
            self.assertIn(("big.py", "file_byte_limit"), {(gap.path, gap.reason) for gap in snapshot.exclusions})
            self.assertFalse((out / "files" / "big.py").exists())

    def test_missing_memory_enforcement_refuses_without_inprocess_fallback(self):
        """what_bug_this_catches: unavailable OS memory enforcement falling back to an unbounded parser."""
        with TemporaryDirectory() as directory:
            snapshot, root = frozen_source(Path(directory))
            process = WorkerReply(canonical_json({"enforced": False, "error": "fixture-memory-enforcement-unavailable", "files": []}))
            with patch("claim_auditor.index.subprocess.Popen", return_value=process) as spawn, patch("ast.parse") as fallback:
                with self.assertRaises(AuditError) as caught:
                    build_index(snapshot, root)
                fallback.assert_not_called()
            self.assertEqual(caught.exception.reason, "parser_enforcement_unavailable")
            self.assertEqual(caught.exception.exit_code, 2)
            self.assertIn("-I", spawn.call_args.args[0])
            self.assertFalse(spawn.call_args.kwargs["shell"])

    def test_parser_timeout_kills_worker_and_scope_cannot_accuse_absence(self):
        """what_bug_this_catches: a timed-out parser yielding an empty supposedly exhaustive declaration index."""
        with TemporaryDirectory() as directory:
            snapshot, root = frozen_source(Path(directory))
            process = WorkerReply(timeout=True)
            with patch("claim_auditor.index.subprocess.Popen", return_value=process), patch("ast.parse") as fallback:
                index = build_index(snapshot, root)
                fallback.assert_not_called()
            self.assertGreaterEqual(process.kills, 1)
            self.assertEqual(index.errors[0].reason, "parser_timeout")
            self.assertTrue(index.parse_failures)
            self.assertEqual(index.facts, [])
            query = predicate(subject="invented")
            atom = claim(span_for(snapshot, read_source(snapshot, root, "README.md")), query)
            result = resolve(index, query)
            finding = decide_finding(atom, [result], citation_valid=True)
            self.assertEqual(finding.verdict, "unknown")
            self.assertEqual(finding.accused_predicate_ids, [])

    def test_worker_output_overflow_is_killed_and_retained_as_parser_failure(self):
        """what_bug_this_catches: parser output growth bypassing its streaming byte cap or becoming a clean empty scope."""
        with TemporaryDirectory() as directory:
            snapshot, root = frozen_source(Path(directory))
            process = WorkerReply(stdout=RepeatedOutput(32 * 1024 * 1024 + 1))
            with patch("claim_auditor.index.subprocess.Popen", return_value=process):
                index = build_index(snapshot, root)
            self.assertGreaterEqual(process.kills, 1)
            self.assertEqual(index.errors[0].reason, "parser_output_limit")
            self.assertEqual(index.facts, [])
            self.assertTrue(index.parse_failures)

    def test_trusted_isolated_parser_does_not_import_target_shadow_modules(self):
        """what_bug_this_catches: target PYTHONPATH/sitecustomize/module shadows executing while indexing source text."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            marker = base / "IMPORTED-TARGET.txt"
            sentinel = ("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('unexpected target import')\n").encode()
            snapshot, root = frozen_source(base, extra={"sitecustomize.py": sentinel, "json.py": sentinel,
                                                       "subprocess.py": sentinel})
            real_spawn = subprocess.Popen
            with patch.dict(os.environ, {"PYTHONPATH": str(root / "files")}), patch("claim_auditor.index.subprocess.Popen", wraps=real_spawn) as spawn:
                index = build_index(snapshot, root)
            self.assertFalse(index.errors)
            self.assertIn("tiny.py", index.parsed_paths)
            self.assertIn("json.py", index.parsed_paths)
            self.assertFalse(marker.exists())
            self.assertIn("-I", spawn.call_args.args[0])
            self.assertNotEqual(Path(spawn.call_args.kwargs["cwd"]), root / "files")
            self.assertFalse(spawn.call_args.kwargs["shell"])
