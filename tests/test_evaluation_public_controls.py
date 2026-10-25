"""Reviewer-authored controls using public synthetic inputs only."""

import unittest

from claim_auditor.contracts import PredictionRow
from claim_auditor.evaluation.scoring import score_rows
from evals.dev_controls import check_controls, control_rows, synthetic_prediction


class PublicEvaluationControls(unittest.TestCase):
    def test_handcomputed_harm_directions_and_adversaries(self):
        """what_bug_this_catches: accuracy hiding false accusations or false reassurance."""
        report = check_controls()
        confusion = report["mixed"]["confusion"]
        self.assertEqual(confusion["verified"]["missing"], 1)
        self.assertEqual(confusion["missing"]["verified"], 1)
        self.assertEqual(report["adversaries"]["all_unknown"]["metrics"]["unknown_overuse"], 1.0)
        self.assertEqual(report["adversaries"]["all_missing"]["metrics"]["false_accusation_rate"], 1.0)

    def test_every_failure_kind_stays_in_gold_denominator(self):
        """what_bug_this_catches: provider/input/citation failures dropping hard gold atoms."""
        _, gold = control_rows()
        for status in ("invalid_output", "abstention_screened", "input_too_large", "citation_failure", "execution_failure"):
            with self.subTest(status=status):
                row = PredictionRow(prediction_id="failure", family_id=gold[0].family_id, finding=None,
                                    status=status, error="synthetic failure", accused_predicate_ids=[])
                result = score_rows([row], gold, include_intervals=False)
                self.assertEqual(result.counts["gold_atoms"], 4)
                self.assertEqual(result.counts["omitted_atoms"], 4)
                self.assertEqual(result.counts[status], 1)
                self.assertEqual(result.metrics["extraction_recall"], 0.0)
                self.assertEqual(len([item for item in result.items if item.gold_id]), 4)

    def test_duplicate_and_omitted_atoms_cannot_inflate_recall(self):
        """what_bug_this_catches: rewarding duplicate predictions while ignoring omissions."""
        _, gold = control_rows()
        rows = [synthetic_prediction(gold[0].claim, "verified", i) for i in range(2)]
        result = score_rows(rows, gold, include_intervals=False)
        self.assertEqual(result.counts["extra_predictions"], 1)
        self.assertEqual(result.counts["omitted_atoms"], 3)
        self.assertEqual(result.metrics["extraction_precision"], 0.5)
        self.assertEqual(result.metrics["extraction_recall"], 0.25)

    def test_empty_controls_are_undefined_and_cannot_pass(self):
        """what_bug_this_catches: empty datasets looking like a perfect benchmark."""
        result = score_rows([], [], include_intervals=False)
        for metric in ("accusation_precision", "verified_precision", "defect_recall", "extraction_recall"):
            self.assertIsNone(result.metrics[metric])
        self.assertEqual(result.counts["dev_targets_met"], 0)
        self.assertFalse(result.human_adjudicated)

    def test_matcher_preserves_negation_condition_and_snapshot(self):
        """what_bug_this_catches: giving credit after erasing a qualifier or changing source identity."""
        _, gold = control_rows()
        atom = gold[0].claim
        for changes in ({"negated": True}, {"condition": "only in debug mode"}, {"subject": "Alpha"}):
            with self.subTest(changes=changes):
                changed = atom.model_copy(update={"predicates": [atom.predicates[0].model_copy(update=changes)]})
                result = score_rows([synthetic_prediction(changed, "verified", 0)], [gold[0]], include_intervals=False)
                self.assertEqual(result.counts["matched_atoms"], 0)
                self.assertEqual(result.counts["omitted_atoms"], 1)
                self.assertEqual(result.metrics["extraction_recall"], 0.0)
        changed = atom.model_copy(update={"span": atom.span.model_copy(update={"snapshot_id": "fixture:other"})})
        result = score_rows([synthetic_prediction(changed, "verified", 0)], [gold[0]], include_intervals=False)
        self.assertEqual(result.counts["matched_atoms"], 0)

    def test_rejected_citation_is_not_a_verified_hit(self):
        """what_bug_this_catches: an invalid active citation retaining verified scoring credit."""
        _, gold = control_rows()
        row = synthetic_prediction(gold[0].claim, "verified", 0)
        row = row.model_copy(update={"finding": row.finding.model_copy(update={"citation_validation": "failed"})})
        result = score_rows([row], [gold[0]], include_intervals=False)
        self.assertEqual(result.counts["citation_rejected"], 1)
        self.assertEqual(result.counts["correct_verified"], 0)
        self.assertEqual(result.metrics["extraction_recall"], 0.0)
        self.assertEqual(result.counts["dev_targets_met"], 0)
