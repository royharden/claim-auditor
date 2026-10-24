"""Future local-fixture staging probes, never actual custody/operator attestations.

All receipt-shaped inputs explicitly identify themselves as synthetic unit controls.
No stage or receipt exists until later authorized test execution, and none certifies
rights, actual operator action, blindness, human review or heldout admission.
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.contracts import AuditError, canonical_json, sha256
from claim_auditor.evaluation.custody import (
    export_dev_source, stage_dev_family, stage_dev_labels, verify_dev_stage,
)
from claim_auditor.evaluation.rulings import append_ruling, load_rulings, make_ruling
from claim_auditor.snapshot import read_source

from .support import claim, frozen_source, gold, predicate, span_for


class CustodyLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.snapshot, self.snapshot_root = frozen_source(
            self.base, readme=b"Production uptime is 99.9 percent.\n",
        )
        entries = [{"path": item.path, "sha256": item.sha256, "size": item.size}
                   for item in self.snapshot.entries]
        provenance = dict(
            format="corpus-dev-provenance/1", designation="DEV_ONLY", heldout=False,
            ancestry={"fixture": "synthetic-local-regression", "independent_holdout": False},
            family_id="dev:control", author_id="D6-synthetic-fixture", author_type="agent",
            origin="Hand-authored local test source", rights_basis="Agent-authored synthetic fixture",
            source_inventory=entries,
            inventory_digest_method="sha256(sorted compact JSON source_inventory, ensure_ascii default)",
            source_inventory_digest=sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()),
        )
        receipt = dict(
            format="dev-access-receipt/1", receipt_id="SYNTHETIC-TEST-NOT-REAL-RECEIPT",
            operator_id="SYNTHETIC-TEST-NOT-A-REAL-OPERATOR",
            recorded_at="2026-10-23T00:00:00+00:00", intended_use="DEV_ONLY",
            rights_review="operator_attested", source_contains_annotation_material=False,
            access_control="operator_attestation_only", custody_verified=False, heldout=False, admitted=False,
        )
        self.provenance = self.base / "synthetic-provenance.json"
        self.receipt = self.base / "synthetic-access-input.json"
        self.provenance.write_bytes(canonical_json(provenance))
        self.receipt.write_bytes(canonical_json(receipt))
        self.stage = self.base / "stage"
        self.alias = "f-0123456789abcdef"
        self.pin = stage_dev_family(self.base / "source", self.stage, alias=self.alias,
                                    provenance_path=self.provenance, access_receipt_path=self.receipt)
        self.assertEqual(verify_dev_stage(self.stage, expected_seal_digest=self.pin), self.snapshot)

    def agent_history(self):
        raw = read_source(self.snapshot, self.snapshot_root, "README.md")
        span = span_for(self.snapshot, raw, end=len(raw.rstrip(b"\r\n")))
        atom = claim(span, predicate(kind="operational", subject=span.quote, module=None))
        atom = atom.model_copy(update={"uncertainty": ["unsupported_semantics"]})
        judgment = gold(atom, "unknown", answerable=False).model_copy(update={
            "disagreements": ["Synthetic dissent retained through export"],
        })
        bundle = self.base / "evidence-input.json"
        bundle.write_bytes(canonical_json({"evidence": [], "coverage": []}) + b"\n")
        ledger = self.base / "agent-rulings.jsonl"
        first = make_ruling(judgment, source_manifest_digest=self.snapshot.manifest_digest,
                            evidence_digest=sha256(bundle.read_bytes()), recorded_at="2026-10-23T00:00:00+00:00")
        append_ruling(ledger, first)
        revised = judgment.model_copy(update={"rationale": "Synthetic revised reasoning; not human gold."})
        second = make_ruling(revised, source_manifest_digest=self.snapshot.manifest_digest,
                             evidence_digest=sha256(bundle.read_bytes()), recorded_at="2026-10-23T00:00:00+00:00",
                             supersedes_ruling_id=first.ruling_id)
        append_ruling(ledger, second)
        return ledger, bundle, atom

    def test_wrong_external_seal_and_swapped_source_bytes_are_refused(self):
        """what_bug_this_catches: an old seal authorizing changed staged bytes or a self-selected source."""
        with self.assertRaises(AuditError) as caught:
            verify_dev_stage(self.stage, expected_seal_digest="0" * 64)
        # Changed pinned/sealed artifacts are integrity failures (exit 4), not input refusals.
        self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("dev_seal_changed", 4))
        frozen = self.stage / "source" / self.alias / "files" / "tiny.py"
        frozen.write_bytes(b"def fake():\n    pass\n")
        with self.assertRaises(AuditError) as caught:
            verify_dev_stage(self.stage, expected_seal_digest=self.pin)
        self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("dev_stage_artifact_changed", 4))
        self.assertIn(b"work", (self.base / "source" / "tiny.py").read_bytes())

    def test_exported_inference_source_contains_no_control_or_labels(self):
        """what_bug_this_catches: provenance/operator inputs or label material leaking into inference export."""
        labels = self.base / "private-label-input.jsonl"
        labels.write_bytes(b"SYNTHETIC-LABEL-SENTINEL\n")
        out = self.base / "source-export"
        digest = export_dev_source(self.stage, out, expected_seal_digest=self.pin)
        self.assertEqual(digest, self.snapshot.manifest_digest)
        observed = {path.relative_to(out).as_posix() for path in out.rglob("*") if path.is_file()}
        expected = {f"{self.alias}/manifest.json", *(f"{self.alias}/files/{entry.path}"
                                                    for entry in self.snapshot.entries)}
        self.assertEqual(observed, expected)
        self.assertFalse(any(b"SYNTHETIC-LABEL-SENTINEL" in path.read_bytes()
                             for path in out.rglob("*") if path.is_file()))
        self.assertTrue(labels.exists())

    def test_label_export_keeps_agent_attribution_history_and_dissent(self):
        """what_bug_this_catches: export upgrading agent judgments to human gold or dropping superseded dissent."""
        ledger, bundle, atom = self.agent_history()
        before = ledger.read_bytes()
        out = self.base / "label-export"
        digest = stage_dev_labels(self.stage, ledger, out, expected_seal_digest=self.pin,
                                  evidence_files={atom.claim_id: bundle})
        metadata = json.loads((out / "LABELS.json").read_bytes())
        self.assertEqual(digest, sha256((out / "LABELS.json").read_bytes()))
        self.assertEqual(metadata["judgment_rows"], 2)
        self.assertFalse(metadata["gold_created"])
        self.assertFalse(metadata["human_review_verified"])
        self.assertFalse(metadata["custody_verified"])
        self.assertEqual((out / "rulings.jsonl").read_bytes(), before)
        self.assertEqual(ledger.read_bytes(), before)
        rows = load_rulings(out / "rulings.jsonl")
        self.assertTrue(all(row.atom.annotator_type == "agent" and row.human_action_id is None for row in rows))
        self.assertTrue(all(row.atom.disagreements == ["Synthetic dissent retained through export"] for row in rows))

    def test_stale_evidence_refuses_export_and_preserves_history(self):
        """what_bug_this_catches: staging labels after evidence changed under an existing judgment."""
        ledger, bundle, atom = self.agent_history()
        before = ledger.read_bytes()
        bundle.write_bytes(bundle.read_bytes() + b" ")
        out = self.base / "stale-label-export"
        with self.assertRaises(AuditError) as caught:
            stage_dev_labels(self.stage, ledger, out, expected_seal_digest=self.pin,
                             evidence_files={atom.claim_id: bundle})
        self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("dev_label_evidence_changed", 4))
        self.assertFalse(out.exists())
        self.assertEqual(ledger.read_bytes(), before)
