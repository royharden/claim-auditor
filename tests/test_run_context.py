"""Bound provenance/context regressions; no observed workflow or call is fabricated."""

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.audit.service import audit_snapshot
from claim_auditor.citations import verify_report
from claim_auditor.contracts import (
    AuditError, AuditReport, RunDeclarations, RunManifest, canonical_json, sha256, stable_id,
)
from claim_auditor.provenance import capture_run_context, context_bytes, validate_run_context
from claim_auditor.report import render_html, render_markdown

from .support import frozen_source


class RunContextTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.snapshot, self.source = frozen_source(self.base)

    def closed_run(self, name):
        out = self.base / name
        manifest = audit_snapshot(self.source, "README.md", "rules", out)
        self.assertEqual(manifest.state, "complete")
        self.assertEqual(verify_report(out).run_id, manifest.run_id)
        return out, manifest, AuditReport.model_validate_json((out / "report.json").read_bytes())

    def reseal(self, out, manifest, report, *, raw_context=None):
        # Adversarial edits to actual future outputs; no passing report is authored.
        hashes = dict(manifest.report_hashes)
        raw = canonical_json(report) + b"\n"
        (out / "report.json").write_bytes(raw)
        hashes["report.json"] = sha256(raw)
        if raw_context is not None:
            for name in ("context.json", "context.jsonl"):
                (out / name).write_bytes(raw_context)
                hashes[name] = sha256(raw_context)
        changed = manifest.model_copy(update={"report_hashes": hashes})
        (out / "RUN.json").write_bytes(canonical_json(changed) + b"\n")

    def test_legacy_null_context_parses_for_diagnostics_but_never_renders_or_verifies(self):
        """what_bug_this_catches: nullable legacy wire fields authorizing a new completed provenance-free report."""
        out, manifest, report = self.closed_run("legacy-negative-input")
        legacy_report = report.model_copy(update={"run_context": None})
        legacy_manifest = manifest.model_copy(update={"run_context": None, "context_digest": None})
        self.assertIsNone(AuditReport.model_validate_json(canonical_json(legacy_report)).run_context)
        self.assertIsNone(RunManifest.model_validate_json(canonical_json(legacy_manifest)).run_context)
        for render in (render_html, render_markdown):
            with self.subTest(render=render.__name__), self.assertRaises(AuditError) as caught:
                render(legacy_report)
            self.assertEqual(caught.exception.reason, "report_context_missing")
        self.reseal(out, legacy_manifest, legacy_report)
        with self.assertRaises(AuditError) as caught:
            verify_report(out)
        self.assertEqual(caught.exception.reason, "report_context_missing")

    def test_context_digest_cannot_disagree_with_exact_metadata_bytes(self):
        """what_bug_this_catches: accepting correct context objects with a different manifest byte pin."""
        out, manifest, report = self.closed_run("digest-negative-input")
        self.reseal(out, manifest.model_copy(update={"context_digest": "0" * 64}), report)
        with self.assertRaises(AuditError) as caught:
            verify_report(out)
        self.assertEqual(caught.exception.reason, "report_context_digest")

    def test_valid_context_from_another_run_cannot_replace_manifest_run_identity(self):
        """what_bug_this_catches: resealing another run's valid context while keeping the original RUN identity."""
        out, manifest, report = self.closed_run("first-run")
        _, other_manifest, other_report = self.closed_run("second-run")
        self.assertNotEqual(manifest.run_id, other_manifest.run_id)
        context = other_report.run_context
        raw = context_bytes(context)
        changed_report = report.model_copy(update={"run_context": context})
        changed_manifest = manifest.model_copy(update={"run_context": context, "context_digest": sha256(raw)})
        self.reseal(out, changed_manifest, changed_report, raw_context=raw)
        with self.assertRaises(AuditError) as caught:
            verify_report(out)
        self.assertEqual(caught.exception.reason, "report_context_mismatch")

    def test_valid_context_for_a_different_snapshot_cannot_render(self):
        """what_bug_this_catches: a well-formed context carrying another target's snapshot/manifest identity."""
        _, _, report = self.closed_run("target-negative-input")
        foreign = self.base / "foreign"
        foreign.mkdir()
        snapshot, _ = frozen_source(foreign, code=b"def other():\n    pass\n")
        context, errors = capture_run_context(
            run_id="synthetic-foreign-target", started_at=datetime.now(timezone.utc).isoformat(),
            snapshot=snapshot, mode="rules", provider=None, model=None, prompt_digest=None, packet_digest=None,
        )
        self.assertEqual(errors, [])
        self.assertNotEqual(context.snapshot_id, report.snapshot.snapshot_id)
        for render in (render_html, render_markdown):
            with self.subTest(render=render.__name__), self.assertRaises(AuditError) as caught:
                render(report.model_copy(update={"run_context": context}))
            self.assertEqual(caught.exception.reason, "report_context_mismatch")

    def test_owner_revision_declaration_never_becomes_observed_git_or_workflow(self):
        """what_bug_this_catches: a caller-supplied revision or reference being promoted to observed execution evidence."""
        declarations = RunDeclarations(owner_id="synthetic-unit-owner", tool_revision="a" * 40,
                                       workflow_revision=None, workflow_run_url=None,
                                       trigger_revision=None, trigger_kind=None)
        context, errors = capture_run_context(
            run_id="synthetic-declaration-unit", started_at=datetime.now(timezone.utc).isoformat(),
            snapshot=self.snapshot, mode="rules", provider=None, model=None,
            prompt_digest=None, packet_digest=None, declarations=declarations,
        )
        self.assertEqual(errors, [])
        self.assertEqual(context.tool_revision.basis, "owner_declared")
        self.assertEqual(context.tool_revision.value, "a" * 40)
        self.assertEqual(context.workflow_revision.basis, "unknown")
        self.assertEqual(context.workflow_run_url.basis, "unknown")
        forged = context.model_copy(update={"tool_revision": context.tool_revision.model_copy(update={"basis": "observed"})})
        fields = forged.model_dump(mode="json", exclude={"context_id"})
        forged = forged.model_copy(update={"context_id": stable_id("run-context", fields)})
        with self.assertRaises(AuditError) as caught:
            validate_run_context(forged)
        self.assertEqual(caught.exception.reason, "run_context_observation")
