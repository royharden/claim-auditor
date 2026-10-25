"""Future tool/target separation probes; no tool hashes or audits observed now."""

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from claim_auditor.audit.service import audit_snapshot
from claim_auditor.citations import verify_report
from claim_auditor.contracts import AuditError
from claim_auditor.provenance import guard_tool_paths
from claim_auditor.report.export import export_report

from .support import frozen_source


class TrustedToolPathTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        # Relocate only the guard's module-location input for this unit seam.
        # Never write to, copy, or hash the real installed package here.
        self.tool = self.base / "installed" / "claim_auditor"
        self.module_path = str(self.tool / "provenance.py")

    def test_audit_refuses_tool_source_or_output_before_target_reads_observation_and_writes(self):
        """what_bug_this_catches: target/output Python entering the package that defines trusted tool identity."""
        cases = [(self.tool, self.base / "ordinary-run"),
                 (self.base / "ordinary-snapshot", self.tool / "generated-run")]
        with patch("claim_auditor.provenance.__file__", self.module_path), \
                patch("claim_auditor.snapshot.load_snapshot") as load, \
                patch("claim_auditor.audit.service.capture_run_context") as observe, \
                patch.object(Path, "mkdir") as mkdir:
            for source, out in cases:
                with self.subTest(source=source, out=out), self.assertRaises(AuditError) as caught:
                    audit_snapshot(source, "README.md", "rules", out)
                self.assertEqual(caught.exception.reason, "audit_path_inside_tool_source")
            load.assert_not_called()
            observe.assert_not_called()
            mkdir.assert_not_called()

    def test_export_refuses_output_in_tool_scope_before_manifest_reads_or_fresh_directory(self):
        """what_bug_this_catches: copied evidence source contaminating the trusted tool package during export."""
        with patch("claim_auditor.provenance.__file__", self.module_path), \
                patch("claim_auditor.report.export.read_ordinary") as read, \
                patch("claim_auditor.report.export.fresh_directory") as create, \
                patch("claim_auditor.report.export.verify_report") as verify:
            with self.assertRaises(AuditError) as caught:
                export_report(self.base / "ordinary-run", self.tool / "export", manifest_digest="a" * 64)
        self.assertEqual(caught.exception.reason, "audit_path_inside_tool_source")
        read.assert_not_called()
        create.assert_not_called()
        verify.assert_not_called()

    def test_resolved_tool_alias_refuses_while_a_sibling_name_remains_separate(self):
        """what_bug_this_catches: lexical-only checks accepting a resolved tool alias or rejecting harmless prefix siblings."""
        alias = self.base / "alias-to-tool"
        resolve = Path.resolve
        physical_target = resolve(self.tool / "target-snapshot")

        def resolved(path, *args, **kwargs):
            if path == alias:
                return physical_target
            return resolve(path, *args, **kwargs)

        # The mapped result must obey resolve's physical-identity contract too:
        # Windows TEMP may use an 8.3 spelling while __file__ resolves long.
        # This unit seam is separate from the real junction control below.
        with patch("claim_auditor.provenance.__file__", self.module_path), \
                patch.object(Path, "resolve", new=resolved):
            with self.assertRaises(AuditError) as caught:
                guard_tool_paths(alias, self.base / "ordinary-run")
            self.assertEqual(caught.exception.reason, "audit_path_inside_tool_source")
            guard_tool_paths(self.tool.with_name("claim_auditor-target"), self.base / "ordinary-run")

    @unittest.skipUnless(os.name == "nt", "Windows junction regression")
    def test_real_tool_junction_refuses_before_target_reads_observation_or_output(self):
        """what_bug_this_catches: a physical tool alias escaping source/output exclusion despite lexical separation."""
        import _winapi

        self.tool.mkdir(parents=True)
        alias = self.base / "actual-tool-junction"
        _winapi.CreateJunction(str(self.tool), str(alias))
        self.addCleanup(os.rmdir, alias)
        self.assertTrue(alias.samefile(self.tool))
        self.assertEqual(alias.resolve(), self.tool.resolve())
        cases = [(alias, self.base / "ordinary-run"),
                 (alias / "target-snapshot", self.base / "ordinary-run"),
                 (self.base / "ordinary-snapshot", alias / "generated-run")]
        with patch("claim_auditor.provenance.__file__", self.module_path), \
                patch("claim_auditor.snapshot.load_snapshot") as load, \
                patch("claim_auditor.audit.service.capture_run_context") as observe, \
                patch.object(Path, "mkdir") as mkdir:
            for source, out in cases:
                with self.subTest(source=source, out=out), self.assertRaises(AuditError) as caught:
                    audit_snapshot(source, "README.md", "rules", out)
                self.assertEqual(caught.exception.reason, "audit_path_inside_tool_source")
            load.assert_not_called()
            observe.assert_not_called()
            mkdir.assert_not_called()
        self.assertFalse((self.tool / "generated-run").exists())
        self.assertFalse((self.base / "ordinary-run").exists())

    def test_real_sibling_with_tool_name_prefix_remains_separate(self):
        """what_bug_this_catches: string-prefix containment rejecting a physically separate ordinary sibling."""
        self.tool.mkdir(parents=True)
        sibling = self.tool.with_name("claim_auditor-target")
        sibling.mkdir()
        self.assertNotEqual(sibling.resolve(), self.tool.resolve())
        self.assertNotIn(self.tool.resolve(), sibling.resolve().parents)
        with patch("claim_auditor.provenance.__file__", self.module_path):
            guard_tool_paths(sibling, self.base / "ordinary-run")
            guard_tool_paths(self.base / "ordinary-snapshot", sibling / "run")

    def test_changed_target_keeps_distinct_tool_identity_in_actual_future_closed_contexts(self):
        """what_bug_this_catches: hashing copied target files as tool code or confusing snapshot and tool identity."""
        contexts = []
        for number, code in enumerate((b"def work():\n    return 1\n", b"def work():\n    return 2\n")):
            base = self.base / f"target-{number}"
            base.mkdir()
            snapshot, source = frozen_source(base, code=code)
            out = base / "run"
            manifest = audit_snapshot(source, "README.md", "rules", out)
            self.assertEqual(manifest.state, "complete")
            self.assertEqual(verify_report(out), manifest)
            context = manifest.run_context
            self.assertEqual((context.snapshot_id, context.snapshot_manifest_digest),
                             (snapshot.snapshot_id, snapshot.manifest_digest))
            self.assertEqual(context.tool_code.basis, "observed")
            self.assertEqual(context.workflow_revision.basis, "unknown")
            self.assertEqual(context.workflow_run_url.basis, "unknown")
            contexts.append(context)
        self.assertNotEqual(contexts[0].snapshot_manifest_digest, contexts[1].snapshot_manifest_digest)
        self.assertEqual(contexts[0].tool_code, contexts[1].tool_code)
