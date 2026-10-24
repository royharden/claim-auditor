"""Integrity regressions authored as source; execution requires later activation."""

from contextlib import redirect_stderr
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from claim_auditor import cli
from claim_auditor.audit.service import audit_snapshot
from claim_auditor.citations import validate_coverage, validate_evidence, validate_span, verify_report
from claim_auditor.contracts import AuditError, canonical_json, sha256
from claim_auditor.index import StaticIndex, resolve
from claim_auditor.snapshot import load_snapshot, read_source

from .support import frozen_source, predicate, span_for


class IntegrityTests(unittest.TestCase):
    def test_changed_frozen_byte_is_not_read_from_checkout(self):
        """what_bug_this_catches: tampered evidence silently reopening mutable source."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            snapshot, root = frozen_source(base)
            (root / "files" / "tiny.py").write_bytes(b"def evil():\n    pass\n")
            for operation in (lambda: read_source(snapshot, root, "tiny.py"),
                              lambda: load_snapshot(root)):
                with self.subTest(operation=operation), self.assertRaises(AuditError) as caught:
                    operation()
                self.assertEqual(caught.exception.exit_code, 4)
            self.assertIn(b"work", (base / "source" / "tiny.py").read_bytes())

    def test_missing_supplied_roots_are_input_errors_not_integrity(self):
        """what_bug_this_catches: a nonexistent user-supplied snapshot/run path reported as integrity failure (4) instead of input (2)."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            out = base / "run"
            with self.assertRaises(AuditError) as caught:
                audit_snapshot(base / "no-such-snapshot", "README.md", "rules", out)
            self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("snapshot_not_found", 2))
            self.assertFalse(out.exists())
            with self.assertRaises(AuditError) as caught:
                verify_report(base / "no-such-run")
            self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("run_not_found", 2))
            # An existing run root missing an inner artifact remains integrity, not input.
            _, root = frozen_source(base)
            manifest = audit_snapshot(root, "README.md", "rules", out)
            self.assertEqual(manifest.state, "complete")
            (out / "report.json").unlink()
            with self.assertRaises(AuditError) as caught:
                verify_report(out)
            self.assertEqual(caught.exception.exit_code, 4)

    def test_cli_maps_missing_run_to_2_and_uncaught_failure_to_3(self):
        """what_bug_this_catches: an uncaught exception escaping as an uncontracted exit 1/traceback, or a missing run root exiting 4."""
        with TemporaryDirectory() as directory:
            missing = Path(directory) / "no-such-run"
            with redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["verify-report", str(missing)]), 2)
            stderr = io.StringIO()
            with patch("claim_auditor.citations.verify_report", side_effect=RuntimeError("synthetic fault")), \
                    redirect_stderr(stderr):
                self.assertEqual(cli.main(["verify-report", str(missing)]), 3)
            self.assertEqual(json.loads(stderr.getvalue())["error"], "unexpected_failure")

    def test_wrong_snapshot_rejects_even_identical_quote_bytes(self):
        """what_bug_this_catches: quote equality substituting for snapshot identity."""
        with TemporaryDirectory() as directory:
            snapshot, root = frozen_source(Path(directory))
            raw = read_source(snapshot, root, "README.md")
            span = span_for(snapshot, raw).model_copy(update={"snapshot_id": "foreign"})
            with self.assertRaises(AuditError) as caught:
                validate_span(snapshot, root, span)
            self.assertEqual(caught.exception.reason, "citation_snapshot_mismatch")

    def test_self_consistent_forged_coverage_still_needs_query_replay(self):
        """what_bug_this_catches: a recomputed digest blessing fabricated absence scope."""
        with TemporaryDirectory() as directory:
            snapshot, root = frozen_source(Path(directory))
            # Deliberate unit seam: no parser worker is being tested here.
            index = StaticIndex(snapshot=snapshot, root=root)
            result = resolve(index, predicate(subject="invented"))
            self.assertEqual(result.state, "absent")  # positive refusal control
            validate_coverage(snapshot, result.coverage[0], index)
            forged = result.coverage[0].model_copy(update={"examined_files": []})
            payload = forged.model_dump(mode="json", exclude={"artifact_digest"})
            forged = forged.model_copy(update={"artifact_digest": sha256(canonical_json(payload))})
            with self.assertRaises(AuditError) as caught:
                validate_coverage(snapshot, forged, index)
            self.assertEqual(caught.exception.reason, "coverage_replay_mismatch")

    def test_negative_evidence_requires_one_exhaustive_coverage_certificate(self):
        """what_bug_this_catches: absent/duplicate certificates authorizing accusations."""
        with TemporaryDirectory() as directory:
            snapshot, root = frozen_source(Path(directory))
            index = StaticIndex(snapshot=snapshot, root=root)
            result = resolve(index, predicate(subject="invented"))
            evidence = result.evidence[0]
            for certificates in ([], result.coverage * 2):
                with self.subTest(count=len(certificates)), self.assertRaises(AuditError) as caught:
                    validate_evidence(snapshot, root, evidence, certificates, index)
                self.assertEqual(caught.exception.reason, "negative_coverage_missing_or_duplicate")
