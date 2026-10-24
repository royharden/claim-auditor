"""Future CLI exit-contract controls for supplied roots and unexpected failures; synthetic inputs only."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pydantic import BaseModel

from claim_auditor.audit import audit_snapshot
from claim_auditor.citations import verify_report
from claim_auditor.cli import main
from claim_auditor.contracts import AuditError


class _CompleteManifest(BaseModel):
    """Stand-in for a completed RunManifest; only `state` is read by the CLI exit mapping."""

    state: str = "complete"


class ExitContractRootTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def cli(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(argv)
        return status, stderr.getvalue()

    def present_snapshot_root(self):
        # require_snapshot_root only checks that a top manifest exists; contents are never read here.
        root = self.base / "snapshot-present"
        root.mkdir()
        (root / "manifest.json").write_bytes(b"{}")
        return root

    def test_missing_snapshot_root_is_input_error_for_every_snapshot_command(self):
        """what_bug_this_catches: a mistyped --snapshot path reported as integrity failure (4) instead of input (2)."""
        missing = self.base / "no-such-snapshot"
        for argv in (["audit", "--snapshot", str(missing), "--out", str(self.base / "audit-out")],
                     ["dev-packet", "--snapshot", str(missing), "--out", str(self.base / "packet-out")]):
            with self.subTest(command=argv[0]):
                status, stderr = self.cli(argv)
                self.assertEqual(status, 2)
                self.assertEqual(json.loads(stderr)["error"], "snapshot_not_found")
        self.assertFalse((self.base / "audit-out").exists())
        self.assertFalse((self.base / "packet-out").exists())

    def test_audit_service_classifies_missing_snapshot_root_as_input(self):
        """what_bug_this_catches: the audit service bypassing the CLI guard and calling an absent root integrity."""
        with self.assertRaises(AuditError) as caught:
            audit_snapshot(self.base / "no-such-snapshot", "README.md", "rules", self.base / "run")
        self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("snapshot_not_found", 2))
        self.assertFalse((self.base / "run").exists())

    def test_missing_run_root_is_input_error_for_verify_report(self):
        """what_bug_this_catches: verify-report on a nonexistent run directory exiting as report integrity (4)."""
        missing = self.base / "no-such-run"
        status, stderr = self.cli(["verify-report", str(missing)])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(stderr)["error"], "run_not_found")
        with self.assertRaises(AuditError) as caught:
            verify_report(missing)
        self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("run_not_found", 2))

    def test_unexpected_exception_is_structured_incomplete_not_traceback(self):
        """what_bug_this_catches: an uncaught KeyError escaping main as a traceback with uncontracted exit 1."""
        with patch("claim_auditor.citations.verify_report", side_effect=KeyError("synthetic-internal")):
            status, stderr = self.cli(["verify-report", str(self.base / "any-run")])
        self.assertEqual(status, 3)
        error = json.loads(stderr)
        self.assertEqual(error["error"], "unexpected_failure")
        self.assertTrue(error["detail"].startswith("KeyError"))
        self.assertNotIn("Traceback", stderr)

    def test_fail_on_missing_with_unreadable_report_is_integrity_failure(self):
        """what_bug_this_catches: an unreadable just-written report.json under --fail-on reported as input (2)."""
        snapshot = self.present_snapshot_root()
        cases = {"absent-report": None, "corrupt-report": b"not a report"}
        for name, raw in cases.items():
            out = self.base / name
            out.mkdir()
            if raw is not None:
                (out / "report.json").write_bytes(raw)
            with self.subTest(case=name), \
                    patch("claim_auditor.audit.audit_snapshot", return_value=_CompleteManifest()) as audit:
                status, stderr = self.cli(["audit", "--snapshot", str(snapshot), "--out", str(out),
                                           "--fail-on", "missing"])
            audit.assert_called_once()
            self.assertEqual(status, 4)
            self.assertEqual(json.loads(stderr)["error"], "report_integrity")
