"""All-case closure and descriptive denominator controls; execution is deferred."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from claim_auditor.contracts import AuditError, sha256
from claim_auditor.evaluation.dataset import evaluate_dataset, preflight_dataset, render_dataset_markdown
from claim_auditor.evaluation.runner import PAIRED_ARMS
from claim_auditor.evaluation.verify import verify_paired
from claim_auditor.snapshot.safeio import read_ordinary

from .dataset_support import DatasetFixture


class DatasetTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self._fixture = None

    @property
    def fixture(self):
        if self._fixture is None:
            self._fixture = DatasetFixture(self.base)
        return self._fixture

    def assert_no_gold_on_refusal(self, pin, *reasons):
        labels = set(self.fixture.gold_paths)
        opened = []

        def no_gold(root, relative, *args, **kwargs):
            path = Path(root) / relative
            if path in labels:
                opened.append(path)
                raise AssertionError("No case's gold may open before ALL inference closes")
            return read_ordinary(root, relative, *args, **kwargs)

        out = self.base / "refused-output"
        with patch("claim_auditor.evaluation.dataset.read_ordinary", side_effect=no_gold):
            with self.assertRaises(AuditError) as caught:
                evaluate_dataset(self.fixture.path, out, manifest_digest=pin)
        self.assertIn(caught.exception.reason, reasons)
        self.assertEqual(opened, [])
        self.assertFalse(out.exists())

    def test_later_bad_pin_prevents_even_earlier_gold_from_opening(self):
        """what_bug_this_catches: scoring an early case before discovering a later unverified closure."""
        cases = list(self.fixture.manifest.cases)
        cases[1] = cases[1].model_copy(update={"run_manifest_digest": "0" * 64})
        self.assert_no_gold_on_refusal(self.fixture.write_manifest(cases=cases), "paired_artifact_integrity")

    def test_later_unclosed_run_prevents_all_gold_even_when_its_pin_matches(self):
        """what_bug_this_catches: trusting a matching byte pin without requiring a completed inference run."""
        manifest = json.loads((self.fixture.runs[1] / "PAIRED.json").read_bytes())
        manifest.update(state="created", completed_at=None)
        pin = self.fixture.reseal_run(1, manifest)
        self.assert_no_gold_on_refusal(pin, "paired_not_closed")

    def test_duplicate_source_content_family_or_ancestry_refuses_not_deduplicates(self):
        """what_bug_this_catches: selecting a successful representative after duplicate/related cases inflate the study."""
        for field in ("snapshot_id", "source_content_digest", "family_id", "ancestry_id"):
            cases = list(self.fixture.manifest.cases)
            cases[1] = cases[1].model_copy(update={field: getattr(cases[0], field)})
            with self.subTest(field=field), patch("claim_auditor.evaluation.dataset.verify_paired") as verify:
                self.assert_no_gold_on_refusal(self.fixture.write_manifest(cases=cases), "dataset_duplicate_case")
                verify.assert_not_called()

    def test_aggregate_manifest_pin_is_required_before_any_case_or_gold(self):
        """what_bug_this_catches: substituting an unpinned aggregate declaration for exact per-case custody inputs."""
        with patch("claim_auditor.evaluation.dataset.verify_paired") as verify:
            self.assert_no_gold_on_refusal("0" * 64, "dataset_manifest_changed")
            verify.assert_not_called()

    def test_exact_raw_case_gold_seal_is_distinct_from_aggregate_manifest_pin(self):
        """what_bug_this_catches: treating semantically equal re-encoded labels as the exact pinned curator bytes."""
        original = self.fixture.gold_paths[1].read_bytes()
        # One JSONL record with equivalent JSON meaning, different raw bytes.
        self.fixture.gold_paths[1].write_bytes(original.rstrip(b"\n") + b" \n")
        before = preflight_dataset(self.fixture.path, manifest_digest=self.fixture.pin)
        self.assertFalse(before["gold_opened"])
        out = self.base / "gold-refusal"
        with self.assertRaises(AuditError) as caught:
            evaluate_dataset(self.fixture.path, out, manifest_digest=self.fixture.pin)
        # Gold bytes changed after the curator pin: integrity (4), not input (2).
        self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("dataset_gold_changed", 4))
        self.assertFalse((out / "DATASET.json").exists())
        failed = json.loads((out / "FAILED.json").read_bytes())
        self.assertEqual(failed["phase"], "gold_binding_after_all_inference_closed")
        self.assertEqual(failed["reason"], "dataset_gold_changed")

    def test_missing_arm_cannot_disappear_before_global_closure(self):
        """what_bug_this_catches: silently scoring only surviving methods after an arm vanished from a case."""
        manifest = json.loads((self.fixture.runs[1] / "PAIRED.json").read_bytes())
        manifest["arms"].pop("packet_grep")
        self.assert_no_gold_on_refusal(self.fixture.reseal_run(1, manifest), "paired_row_integrity")

    def test_resealed_missing_row_cannot_hide_an_atom_before_gold(self):
        """what_bug_this_catches: rehashing empty case predictions to shrink the study's extraction denominator."""
        root = self.fixture.runs[1]
        manifest = json.loads((root / "PAIRED.json").read_bytes())
        arm = "packet_candidate"
        self.assertTrue((root / arm / "predictions.jsonl").read_bytes())
        (root / arm / "predictions.jsonl").write_bytes(b"")
        manifest["artifacts"][f"{arm}/predictions.jsonl"] = sha256(b"")
        manifest["arms"][arm].update(rows=0, failure_rows=0)
        self.assert_no_gold_on_refusal(self.fixture.reseal_run(1, manifest, arm=arm),
                                       "paired_proof_mismatch", "paired_row_integrity")

    def test_hidden_attempt_cannot_disappear_before_gold(self):
        """what_bug_this_catches: case metadata suppressing a physical attempt that remains in durable accounting."""
        manifest = json.loads((self.fixture.runs[1] / "PAIRED.json").read_bytes())
        arm = "live_extraction"
        info = manifest["arms"][arm]
        self.assertTrue(info["attempts"])
        info["attempts"] = []
        info["response"]["attempts"] = []
        self.assert_no_gold_on_refusal(self.fixture.reseal_run(1, manifest, arm=arm), "paired_attempt_integrity")

    def test_source_version_or_unbacked_protocol_cannot_disappear_before_gold(self):
        """what_bug_this_catches: mixing source versions/protocol claims after observing a case's labels."""
        cases = list(self.fixture.manifest.cases)
        cases[1] = cases[1].model_copy(update={"protocol_digest": "0" * 64})
        self.assert_no_gold_on_refusal(self.fixture.write_manifest(cases=cases), "dataset_protocol_mismatch")
        manifest = json.loads((self.fixture.runs[1] / "PAIRED.json").read_bytes())
        manifest["code_digest"] = "0" * 64
        self.assert_no_gold_on_refusal(self.fixture.reseal_run(1, manifest), "paired_identity_mismatch")

    def test_small_agent_fake_study_preserves_failures_utility_and_inconclusive_status(self):
        """what_bug_this_catches: aggregation dropping failed cases or relabeling privileged/fake results as accepted comparison."""
        # Separate real future closure fixture with one explicitly invalid fake arm.
        failed_base = self.base / "with-failure"
        failed_base.mkdir()
        fixture = DatasetFixture(failed_base, fail_first_extraction=True)
        verified_cases, opened = [], []

        def verify(*args, **kwargs):
            value = verify_paired(*args, **kwargs)
            verified_cases.append(args[0])
            return value

        def observe(root, relative, *args, **kwargs):
            path = Path(root) / relative
            if path in fixture.gold_paths:
                self.assertEqual(len(verified_cases), len(fixture.manifest.cases))
                opened.append(path)
            return read_ordinary(root, relative, *args, **kwargs)

        out = failed_base / "aggregate"
        with patch("claim_auditor.evaluation.dataset.verify_paired", side_effect=verify), patch("claim_auditor.evaluation.dataset.read_ordinary", side_effect=observe):
            results = evaluate_dataset(fixture.path, out, manifest_digest=fixture.pin)
        self.assertEqual(opened, fixture.gold_paths)
        summary = json.loads((out / "SUMMARY.json").read_bytes())
        self.assertEqual(summary["equal_packet_methods"], list(PAIRED_ARMS))
        self.assertEqual(summary["separate_utility_method"], "product_full_index")
        self.assertNotIn("product_full_index", summary["equal_packet_methods"])
        self.assertEqual(summary["gold_atoms"], 2)
        result = results["live_extraction"]
        self.assertEqual(result.counts["gold_atoms"], 2)
        self.assertGreaterEqual(result.counts["invalid_output"], 1)
        self.assertGreaterEqual(result.counts["omitted_atoms"], 1)
        self.assertIsNone(result.attempt_summary.input_tokens)
        self.assertIsNone(result.attempt_summary.median_seconds)
        self.assertTrue(all(interval.status == "inconclusive" for interval in result.intervals.values()))
        self.assertFalse(result.comparative_complete)
        self.assertFalse(result.human_adjudicated)
        for state in summary["target_states"].values():
            self.assertEqual(state["status"], "inconclusive_for_comparative_acceptance")
        self.assertIn("promoted_120_atom_12_independent_ancestor_minimum_not_met", summary["missing_conditions"])
        self.assertIn("actual_human_review_receipt_unresolved", summary["missing_conditions"])
        self.assertIn("Separate full-index utility", render_dataset_markdown(summary))
