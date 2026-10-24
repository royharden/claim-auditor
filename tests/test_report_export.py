"""Future selected local export controls; no report/export is produced now."""

import json
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from claim_auditor.audit.service import audit_snapshot
from claim_auditor.citations import verify_report
from claim_auditor.contracts import RUN_STATE_EXIT, AuditError, canonical_json, sha256
from claim_auditor.report.export import export_report
from claim_auditor.report import export as export_module

from .support import frozen_source


class ReportExportTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def closed_run(self, *, extra=None):
        # Same actual future audit factory/verifier used by closed-report and
        # context controls. No handwritten completed manifest or new verifier.
        _, source = frozen_source(self.base, extra=extra)
        run = self.base / "original-run"
        manifest = audit_snapshot(source, "README.md", "rules", run)
        self.assertEqual(manifest.state, "complete")
        self.assertEqual(verify_report(run), manifest)
        return run, manifest, sha256((run / "RUN.json").read_bytes())

    def test_copy_reopens_with_canonical_verifier_before_export_record_is_written_last(self):
        """what_bug_this_catches: closing export bookkeeping before a full bound report/source copy verifies."""
        run, manifest, pin = self.closed_run()
        out = self.base / "export"
        writes = []
        write = export_module._write_new

        def observe_write(root, relative, raw):
            if relative == "EXPORT.json":
                self.assertFalse((out / "EXPORT.json").exists())
                self.assertEqual(verify_report(out / "run"), manifest)
            writes.append((root, relative))
            return write(root, relative, raw)

        with patch.object(export_module, "_write_new", side_effect=observe_write):
            record = export_report(run, out, manifest_digest=pin)
        self.assertEqual(writes[-1], (out, "EXPORT.json"))
        self.assertEqual(record["input_run_manifest_digest"], pin)
        self.assertEqual(record["state"], "closed_local_copy_unpublished")
        self.assertEqual(json.loads((out / "EXPORT.json").read_bytes()), record)
        self.assertEqual((out / "run" / "RUN.json").read_bytes(), (run / "RUN.json").read_bytes())
        self.assertEqual(verify_report(out / "run"), manifest)
        for key in ("origin_verified", "custody_verified", "publication_authorized", "workflow_execution_observed"):
            self.assertFalse(record[key])
        for item in record["inventory"]:
            self.assertEqual(sha256((out / item["path"]).read_bytes()), item["sha256"])

    def test_wrong_pin_and_equivalent_json_with_changed_raw_run_bytes_refuse_before_output(self):
        """what_bug_this_catches: self-computed or semantic-only manifest identity replacing an external raw-byte pin."""
        run, _, pin = self.closed_run()
        out = self.base / "wrong-pin"
        with self.assertRaises(AuditError) as caught:
            export_report(run, out, manifest_digest="0" * 64)
        self.assertEqual(caught.exception.reason, "export_manifest_pin_mismatch")
        self.assertFalse(out.exists())
        path = run / "RUN.json"
        path.write_bytes(path.read_bytes() + b" ")  # Same JSON object, different frozen bytes.
        out = self.base / "changed-raw-pin"
        with self.assertRaises(AuditError) as caught:
            export_report(run, out, manifest_digest=pin)
        self.assertEqual(caught.exception.reason, "export_manifest_pin_mismatch")
        self.assertFalse(out.exists())

    def test_incomplete_run_propagates_canonical_failure_without_copying(self):
        """what_bug_this_catches: matching a manifest pin being mistaken for a complete report closure, or a
        non-complete run state escaping the shared RUN_STATE_EXIT table (failed_input is 2, not 3)."""
        run, manifest, _ = self.closed_run()
        for state, exit_code in (("incomplete", 3), ("failed_input", 2), ("failed_integrity", 4)):
            raw = canonical_json(manifest.model_copy(update={"state": state})) + b"\n"
            (run / "RUN.json").write_bytes(raw)
            out = self.base / f"export-{state}"
            with self.subTest(state=state), self.assertRaises(AuditError) as caught:
                export_report(run, out, manifest_digest=sha256(raw))
            self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("run_not_complete", exit_code))
            self.assertEqual(exit_code, RUN_STATE_EXIT[state])
            self.assertFalse(out.exists())

    def test_unlisted_control_file_is_neither_opened_nor_silently_omitted(self):
        """what_bug_this_catches: broad directory copying or dropping private extras while advertising a closed export."""
        run, _, pin = self.closed_run()
        extra = run / "unlisted-control.json"
        extra.write_bytes(b'{"synthetic_inert_control":true}\n')
        read = export_module.read_ordinary

        def refuse_extra(root, relative, *args, **kwargs):
            if relative == extra.name:
                raise AssertionError("Unlisted control bytes must never be opened")
            return read(root, relative, *args, **kwargs)

        out = self.base / "export"
        with patch.object(export_module, "read_ordinary", side_effect=refuse_extra):
            with self.assertRaises(AuditError) as caught:
                export_report(run, out, manifest_digest=pin)
        self.assertEqual(caught.exception.reason, "export_inventory_mismatch")
        self.assertFalse(out.exists())
        self.assertTrue(extra.exists())

    def test_selected_reparse_object_refuses_before_copying(self):
        """what_bug_this_catches: an inventory-selected ordinary name bypassing reparse-point refusal."""
        run, _, pin = self.closed_run()
        selected = run / "context.json"
        lstat = Path.lstat

        def reparse(path, *args, **kwargs):
            if path == selected:
                return SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
            return lstat(path, *args, **kwargs)

        out = self.base / "export"
        with patch.object(Path, "lstat", new=reparse):
            with self.assertRaises(AuditError) as caught:
                export_report(run, out, manifest_digest=pin)
        # Run-tree link/entry refusals keep unsafe_export_path (integrity, 4); argument paths use invalid_export_path (2).
        self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("unsafe_export_path", 4))
        self.assertFalse(out.exists())

    def test_traversing_or_unc_argument_path_is_input_error_before_reading(self):
        """what_bug_this_catches: a bad source/destination argument reported as run integrity (4) or opening the run first."""
        run, _, pin = self.closed_run()
        for source, out in ((run / ".." / run.name, self.base / "export"),
                            (run, self.base / "nested" / ".." / "export"),
                            (Path("//server/share/run"), self.base / "export")):
            with self.subTest(source=str(source), out=str(out)), \
                    patch.object(export_module, "read_ordinary", side_effect=AssertionError("must refuse before reading")), \
                    self.assertRaises(AuditError) as caught:
                export_report(source, out, manifest_digest=pin)
            self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("invalid_export_path", 2))
            self.assertFalse((self.base / "export").exists())

    def test_required_agent_control_source_refuses_whole_export_without_reading_or_omission(self):
        """what_bug_this_catches: removing a required unsafe source file while claiming a complete evidence copy."""
        # Entirely owned inert future fixture, never a real agent/control file.
        run, _, pin = self.closed_run(extra={"agentops/inert_notes.py": b"# synthetic inert fixture\n"})
        read = export_module.read_ordinary

        def refuse_control(root, relative, *args, **kwargs):
            if relative == "snapshot/files/agentops/inert_notes.py":
                raise AssertionError("Export selection must refuse this required path before opening bytes")
            return read(root, relative, *args, **kwargs)

        out = self.base / "export"
        with patch.object(export_module, "read_ordinary", side_effect=refuse_control):
            with self.assertRaises(AuditError) as caught:
                export_report(run, out, manifest_digest=pin)
        self.assertEqual(caught.exception.reason, "nonexportable_required_source")
        self.assertFalse(out.exists())

    def test_overlap_and_existing_destination_refuse_without_touching_source(self):
        """what_bug_this_catches: an export overwriting an original run or an unrelated existing destination."""
        run, _, pin = self.closed_run()
        original = (run / "RUN.json").read_bytes()
        for out in (run, run / "nested-export", self.base):
            with self.subTest(out=out), self.assertRaises(AuditError) as caught:
                export_report(run, out, manifest_digest=pin)
            self.assertEqual(caught.exception.reason, "export_source_destination_overlap")
        existing = self.base / "existing"
        existing.mkdir()
        marker = existing / "owned-marker.txt"
        marker.write_bytes(b"synthetic preservation marker")
        with self.assertRaises(AuditError) as caught:
            export_report(run, existing, manifest_digest=pin)
        self.assertEqual(caught.exception.reason, "output_exists")
        self.assertEqual(marker.read_bytes(), b"synthetic preservation marker")
        self.assertEqual((run / "RUN.json").read_bytes(), original)

    def test_interrupted_copy_keeps_partial_files_and_failure_but_never_closed_export(self):
        """what_bug_this_catches: erasing interrupted evidence or allowing its output path to be silently reused."""
        run, manifest, pin = self.closed_run()
        out = self.base / "export"
        write = export_module._write_new

        def interrupted(root, relative, raw):
            if relative == "report.html":
                raise OSError("synthetic copy interruption")
            return write(root, relative, raw)

        with patch.object(export_module, "_write_new", side_effect=interrupted):
            with self.assertRaises(OSError):
                export_report(run, out, manifest_digest=pin)
        self.assertFalse((out / "EXPORT.json").exists())
        failure = json.loads((out / "FAILED.json").read_bytes())
        self.assertEqual(failure["state"], "incomplete_preserved_not_publishable")
        self.assertIn("run/RUN.json", failure["copied_paths"])
        preserved = {item: (out / item).read_bytes() for item in failure["copied_paths"]}
        self.assertEqual(verify_report(run), manifest)
        with self.assertRaises(AuditError) as caught:
            export_report(run, out, manifest_digest=pin)
        self.assertEqual(caught.exception.reason, "output_exists")
        self.assertEqual({item: (out / item).read_bytes() for item in preserved}, preserved)

    def test_input_mutation_after_its_copy_prevents_last_written_closure(self):
        """what_bug_this_catches: an early copied file changing while another artifact copies without a final recheck."""
        run, _, pin = self.closed_run()
        out = self.base / "export"
        write = export_module._write_new
        changed = []

        def mutate_after_copy(root, relative, raw):
            result = write(root, relative, raw)
            if relative == "report.md" and not changed:
                path = run / "context.json"  # Already copied in the sorted inventory.
                path.write_bytes(path.read_bytes() + b" ")
                changed.append(path)
            return result

        with patch.object(export_module, "_write_new", side_effect=mutate_after_copy):
            with self.assertRaises(AuditError) as caught:
                export_report(run, out, manifest_digest=pin)
        self.assertEqual(caught.exception.reason, "export_input_changed")
        self.assertEqual(len(changed), 1)
        self.assertFalse((out / "EXPORT.json").exists())
        self.assertTrue((out / "run" / "context.json").exists())
        failure = json.loads((out / "FAILED.json").read_bytes())
        self.assertEqual(failure["reason"], "export_input_changed")
