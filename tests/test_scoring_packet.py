"""Hand-authored scorer controls, never a human-gold or measured passing corpus."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pydantic import ValidationError

from claim_auditor.contracts import AuditError, EvaluationPacket, PredictionRow, canonical_json
from claim_auditor.evaluation.baseline import run_packet_grep
from claim_auditor.evaluation.scoring import read_jsonl, score_rows
from claim_auditor.snapshot import read_source

from .support import claim, frozen_source, gold, packet_for, predicate, prediction, span_for


class ScoringPacketTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.snapshot, self.root = frozen_source(self.base)
        raw = read_source(self.snapshot, self.root, "README.md")
        self.atom = claim(span_for(self.snapshot, raw))

    def test_duplicate_prediction_ids_are_rejected_not_overwritten(self):
        """what_bug_this_catches: duplicate prediction identities shrinking the denominator."""
        row = prediction(self.atom, "unknown")
        with self.assertRaises(AuditError) as caught:
            score_rows([row, row], [gold(self.atom, "verified")], include_intervals=False)
        self.assertEqual(caught.exception.reason, "duplicate_item_identity")

    def test_distinct_ids_for_duplicate_atoms_remain_extra_predictions(self):
        """what_bug_this_catches: repeated extracted atoms each earning credit for one gold atom."""
        rows = [prediction(self.atom, "verified", identifier=f"prediction:{i}") for i in range(2)]
        result = score_rows(rows, [gold(self.atom, "verified")], include_intervals=False)
        self.assertEqual(result.counts["matched_atoms"], 1)
        self.assertEqual(result.counts["extra_predictions"], 1)
        self.assertEqual(result.counts["prediction_rows"], 2)
        self.assertEqual(result.metrics["extraction_precision"], 0.5)

    def test_invalid_artifact_and_missing_finding_are_rejected(self):
        """what_bug_this_catches: malformed prediction artifacts becoming an empty clean run."""
        path = self.base / "predictions.jsonl"
        for raw in (b'{"prediction_id":"x","invented":true}\n', b"\n", b"not-json\n"):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                with self.assertRaises(AuditError) as caught:
                    read_jsonl(path, PredictionRow)
                self.assertEqual(caught.exception.reason, "invalid_evaluation_input")
        row = PredictionRow(prediction_id="broken", family_id="dev:control", finding=None,
                            status="prediction", error=None, accused_predicate_ids=[])
        with self.assertRaises(AuditError) as caught:
            score_rows([row], [gold(self.atom, "verified")], include_intervals=False)
        self.assertEqual(caught.exception.reason, "invalid_prediction")

    def test_all_unknown_cannot_win_by_avoiding_accusations(self):
        """what_bug_this_catches: abstaining on every answerable atom satisfying quality gates."""
        atoms = [self.atom, claim(self.atom.span, predicate(subject="invented"), identifier="claim:missing")]
        expected = [gold(atoms[0], "verified"), gold(atoms[1], "missing", identifier="gold:missing")]
        rows = [prediction(atom, "unknown", identifier=f"prediction:{i}") for i, atom in enumerate(atoms)]
        result = score_rows(rows, expected, include_intervals=False)
        self.assertEqual(result.metrics["unknown_overuse"], 1.0)
        self.assertEqual(result.metrics["answerability_coverage"], 0.0)
        self.assertEqual(result.metrics["defect_recall"], 0.0)
        self.assertIsNone(result.metrics["accusation_precision"])
        self.assertEqual(result.counts["dev_targets_met"], 0)
        self.assertFalse(result.human_adjudicated)
        self.assertFalse(result.comparative_complete)

    def test_all_missing_exposes_false_and_unknowable_accusations(self):
        """what_bug_this_catches: always accusing inflating defect recall without harm metrics."""
        atoms = [self.atom,
                 claim(self.atom.span, predicate(subject="invented"), identifier="claim:missing"),
                 claim(self.atom.span, predicate(kind="operational", subject="uptime"), identifier="claim:uptime")]
        expected = [gold(atoms[0], "verified"), gold(atoms[1], "missing", identifier="gold:missing"),
                    gold(atoms[2], "unknown", identifier="gold:uptime", answerable=False)]
        rows = [prediction(atom, "missing", identifier=f"prediction:{i}") for i, atom in enumerate(atoms)]
        result = score_rows(rows, expected, include_intervals=False)
        self.assertEqual(result.metrics["defect_recall"], 1.0)
        self.assertEqual(result.metrics["false_accusation_rate"], 1.0)
        self.assertEqual(result.metrics["unknowable_accusation_rate"], 1.0)
        self.assertAlmostEqual(result.metrics["accusation_precision"], 1 / 3)
        self.assertEqual(result.counts["dev_targets_met"], 0)
        self.assertFalse(result.comparative_complete)

    def test_failure_rows_do_not_remove_gold_atoms(self):
        """what_bug_this_catches: screened/provider failures disappearing from all-atom accounting."""
        row = PredictionRow(prediction_id="held", family_id="dev:control", finding=None,
                            status="abstention_screened", error="input held", accused_predicate_ids=[])
        result = score_rows([row], [gold(self.atom, "verified")], include_intervals=False)
        self.assertEqual(result.counts["gold_atoms"], 1)
        self.assertEqual(result.counts["omitted_atoms"], 1)
        self.assertEqual(result.counts["abstention_screened"], 1)
        self.assertEqual(result.metrics["extraction_recall"], 0.0)

    def test_packet_schema_refuses_labels_and_rationale(self):
        """what_bug_this_catches: scorer-only labels entering inference through open packet fields."""
        raw = read_source(self.snapshot, self.root, "README.md")
        payload = packet_for(self.snapshot, raw).model_dump(mode="json")
        for key, value in (("gold", []), ("labels", {"work": "verified"}),
                           ("rationale", "curator answer")):
            with self.subTest(key=key), self.assertRaises(ValidationError):
                EvaluationPacket.model_validate_json(canonical_json({**payload, key: value}))

    def test_packet_without_excerpt_does_not_search_full_snapshot(self):
        """what_bug_this_catches: a bounded packet arm silently using full-repository evidence."""
        with TemporaryDirectory() as directory:
            raw = b"The file `tiny.py` exists.\n"
            snapshot, root = frozen_source(Path(directory), readme=raw)
            result = run_packet_grep(packet_for(snapshot, raw), snapshot, root)
            self.assertEqual(len(result.predictions), 1)
            self.assertEqual(result.predictions[0].finding.verdict, "unknown")
            self.assertEqual(result.evidence, [])
