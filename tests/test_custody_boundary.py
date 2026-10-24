"""DEV custody refusal source; never invent a successful operator receipt or stage."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.contracts import AuditError, canonical_json
from claim_auditor.evaluation.custody import (
    export_dev_source, stage_dev_family, stage_dev_labels, verify_dev_stage,
)


class CustodyBoundaryTests(unittest.TestCase):
    def test_dev_stager_denies_heldout_or_admission_before_reading_inputs(self):
        """what_bug_this_catches: a DEV staging helper certifying heldout/admission by a flag."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            for suffix, controls in (("heldout", {"designation": "HELDOUT"}),
                                     ("admission", {"admission_requested": True})):
                out = base / suffix
                with self.subTest(controls=controls), self.assertRaises(AuditError) as caught:
                    stage_dev_family(base / "MISSING-SOURCE", out, alias="f-0123456789abcdef",
                                     provenance_path=base / "MISSING-PROVENANCE.json",
                                     access_receipt_path=base / "MISSING-RECEIPT.json", **controls)
                self.assertEqual(caught.exception.reason, "custody_admission_unsupported")
                self.assertFalse(out.exists())

    def test_alias_cannot_traverse_or_encode_an_outcome(self):
        """what_bug_this_catches: unsafe or outcome-bearing family names entering source-only staging."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            for alias in ("../escape", "verified-family", "f-0123456789ABCDEf"):
                with self.subTest(alias=alias), self.assertRaises(AuditError) as caught:
                    stage_dev_family(base / "MISSING-SOURCE", base / "out", alias=alias,
                                     provenance_path=base / "MISSING-PROVENANCE.json",
                                     access_receipt_path=base / "MISSING-RECEIPT.json")
                self.assertEqual(caught.exception.reason, "unsafe_family_alias")
                self.assertFalse((base / "out").exists())

    def test_empty_operator_identity_cannot_be_a_successful_receipt(self):
        """what_bug_this_catches: a generated placeholder receipt creating an apparently admitted stage."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            provenance = base / "invalid-provenance.json"
            receipt = base / "invalid-receipt.json"
            provenance.write_bytes(b"{}")
            # Explicitly invalid negative input, never a real operator attestation.
            receipt.write_bytes(canonical_json(dict(
                format="dev-access-receipt/1", receipt_id="NEGATIVE-TEST-INVALID",
                operator_id="", recorded_at="2026-10-23T00:00:00+00:00", intended_use="DEV_ONLY",
                rights_review="operator_attested", source_contains_annotation_material=False,
                access_control="operator_attestation_only", custody_verified=False,
                heldout=False, admitted=False,
            )))
            with self.assertRaises(AuditError) as caught:
                stage_dev_family(base / "MISSING-SOURCE", base / "out", alias="f-0123456789abcdef",
                                 provenance_path=provenance, access_receipt_path=receipt)
            self.assertEqual(caught.exception.reason, "missing_access_receipt")
            self.assertFalse((base / "out").exists())

    def test_seal_requires_an_external_full_digest_and_exact_bytes(self):
        """what_bug_this_catches: reading an unpinned/self-selected seal as proof of an unchanged stage."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            # This is a malformed negative artifact, not a measured passing seal.
            (root / "SEAL.json").write_bytes(b"{}")
            # A missing pin is an input refusal (2); a pinned seal whose bytes changed is integrity (4).
            for pin, reason, exit_code in (("", "invalid_dev_seal", 2), ("0" * 64, "dev_seal_changed", 4)):
                with self.subTest(pin=pin), self.assertRaises(AuditError) as caught:
                    verify_dev_stage(root, expected_seal_digest=pin)
                self.assertEqual((caught.exception.reason, caught.exception.exit_code), (reason, exit_code))

    def test_source_and_label_exports_verify_before_creating_output(self):
        """what_bug_this_catches: export wrappers copying source or labels before source-seal verification."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            operations = [
                lambda out: export_dev_source(base / "MISSING-STAGE", out, expected_seal_digest=""),
                lambda out: stage_dev_labels(base / "MISSING-STAGE", base / "MISSING-RULINGS.jsonl", out,
                                             expected_seal_digest="", evidence_files={}),
            ]
            for number, operation in enumerate(operations):
                out = base / f"export-{number}"
                with self.subTest(number=number), self.assertRaises(AuditError) as caught:
                    operation(out)
                self.assertEqual(caught.exception.reason, "invalid_dev_seal")
                self.assertFalse(out.exists())
