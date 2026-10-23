"""Future integration source: produce real artifacts at activation, then tamper them."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.audit.service import audit_snapshot
from claim_auditor.citations import verify_report
from claim_auditor.contracts import AuditError

from .support import frozen_source


class ClosedReportTests(unittest.TestCase):
    def test_prediction_artifact_change_fails_closed_report_integrity(self):
        """what_bug_this_catches: an altered predictions sidecar scoring as a verified closed run."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            _, snapshot_root = frozen_source(base)
            out = base / "run"
            manifest = audit_snapshot(snapshot_root, "README.md", "rules", out)
            self.assertEqual(manifest.state, "complete")
            self.assertEqual(verify_report(out).run_id, manifest.run_id)
            artifact = out / "predictions.jsonl"
            artifact.write_bytes(artifact.read_bytes() + b"{}\n")
            with self.assertRaises(AuditError) as caught:
                verify_report(out)
            self.assertEqual(caught.exception.reason, "report_artifact_digest")
            self.assertEqual(caught.exception.exit_code, 4)

    def test_changed_embedded_source_invalidates_previously_complete_report(self):
        """what_bug_this_catches: completed manifest bypassing evidence reopening after tamper."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            _, snapshot_root = frozen_source(base)
            out = base / "run"
            manifest = audit_snapshot(snapshot_root, "README.md", "rules", out)
            self.assertEqual(manifest.state, "complete")
            verify_report(out)
            (out / "snapshot" / "files" / "tiny.py").write_bytes(b"def fake():\n    pass\n")
            with self.assertRaises(AuditError) as caught:
                verify_report(out)
            self.assertEqual(caught.exception.exit_code, 4)
