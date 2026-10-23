"""Owned demo consumer input checks, never handwritten verdicts or gold labels."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.audit.service import audit_snapshot
from claim_auditor.citations import verify_report
from claim_auditor.contracts import AuditReport
from claim_auditor.report.demo import create_demo_source
from claim_auditor.snapshot import create_fixture_snapshot


class OwnedDemoSourceTests(unittest.TestCase):
    def test_selected_extensions_retain_original_assertion_bytes_and_owned_source_files(self):
        """what_bug_this_catches: extending a demo by silently replacing its original supported/absent/runtime inputs."""
        with TemporaryDirectory() as directory:
            out = Path(directory) / "owned-demo"
            self.assertEqual(create_demo_source(out), out)
            self.assertTrue({"README.md", "sample.py", "pyproject.toml"} <= {item.name for item in out.iterdir()})
            readme = (out / "README.md").read_bytes()
            for original in (
                b"The function `present` is declared in module `sample`.",
                b"The function `invented` is declared in module `sample`.",
                b"The service handles 10000 requests per second.",
            ):
                self.assertIn(original, readme)
            self.assertIn(b"def present(value: int = 3) -> int:", (out / "sample.py").read_bytes())
            self.assertIn(b'requires-python = ">=3.12"', (out / "pyproject.toml").read_bytes())
            self.assertIn(b"has literal default `value=3`", readme)
            self.assertIn(b"returns `3` for every input", readme)
            self.assertIn(b"has literal default `value=30`", readme)
            # Inspect owned bytes only. Claim extraction, resolution and complete
            # audits must consume production evidence later, with no expected
            # verdict/gold table embedded in this source inventory control.

    def test_generated_static_evidence_never_proves_the_stronger_runtime_paraphrase(self):
        """what_bug_this_catches: a literal default or declared subject verifying behavior for every input."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            source = create_demo_source(base / "owned-demo")
            snapshot_root = base / "snapshot"
            snapshot = create_fixture_snapshot(source, snapshot_root)
            out = base / "run"
            manifest = audit_snapshot(snapshot_root, "README.md", "rules", out)
            self.assertEqual(manifest.state, "complete")
            self.assertEqual(verify_report(out), manifest)
            report = AuditReport.model_validate_json((out / "report.json").read_bytes())
            self.assertEqual(report.snapshot.manifest_digest, snapshot.manifest_digest)
            evidence = {item.evidence_id: item for item in report.evidence}
            narrow = [item for item in report.findings if any(
                query.kind == "bounded_code_fact" and query.pattern == "literal-default/v1"
                and query.subject == "present" and query.key == "value"
                for query in item.claim.predicates
            )]
            self.assertEqual(len(narrow), 2)  # The published narrow and contrary input pair.
            observed_kinds = set()
            for finding in narrow:
                self.assertEqual(finding.citation_validation, "valid")
                self.assertTrue(finding.evidence_ids)
                for identifier in finding.evidence_ids:
                    item = evidence[identifier]  # Only actual producer evidence, never a handwritten ruling.
                    observed_kinds.add(item.kind)
                    self.assertEqual(item.query.pattern, "literal-default/v1")
                    self.assertEqual(item.span.path, "sample.py")
                    self.assertEqual(item.span.quote, "3")  # Parser cites the exact default literal node.
            self.assertEqual(observed_kinds, {"positive", "contrary"})
            runtime = [item for item in report.findings if item.claim.kind in {"behavioral", "operational"}]
            self.assertTrue(any("returns `3` for every input" in item.claim.span.quote for item in runtime))
            for finding in runtime:
                self.assertEqual(finding.verdict, "unknown")
                self.assertEqual(finding.accused_predicate_ids, [])
                self.assertEqual(finding.evidence_ids, [])
            self.assertEqual(manifest.run_context.workflow_revision.basis, "unknown")
            self.assertEqual(manifest.runtime_validation, "unverified")
