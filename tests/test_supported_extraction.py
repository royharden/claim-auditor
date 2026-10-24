"""Handcomputed tiny scorer controls, never benchmark scores or citation proof."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.contracts import canonical_json, stable_id
from claim_auditor.evaluation.annotation import (
    audit_manual_omissions, make_manual_inventory, record_manual_annotation,
    select_manual_atom, select_manual_span,
)
from claim_auditor.evaluation.scoring import score_rows

from .support import claim, frozen_source, gold, predicate, prediction, span_for


class SupportedExtractionTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.lines = [b"The function `work` is declared in module `tiny`.",
                      b"The function `invented` is declared in module `tiny`.",
                      b"Production uptime is 99.9 percent.", b"This is the best tool."]
        self.raw = b"\n".join(self.lines) + b"\n"
        self.snapshot, _ = frozen_source(self.base, readme=self.raw)

    def atom(self, number, query):
        line = self.lines[number]
        start = self.raw.index(line)
        return claim(span_for(self.snapshot, self.raw, start=start, end=start + len(line)), query,
                     identifier=f"claim:tiny-control-{number}")

    def controls(self):
        return (self.atom(0, predicate()), self.atom(1, predicate(subject="invented")),
                self.atom(2, predicate(kind="operational", subject=self.lines[2].decode(), module=None)))

    def test_supported_recall_and_all_atom_recall_keep_distinct_denominators(self):
        """what_bug_this_catches: unsupported/omitted atoms disappearing when extraction target keys switch to supported kinds."""
        supported, omitted_supported, operational = self.controls()
        labels = [gold(supported, "verified", identifier="gold:0"),
                  gold(omitted_supported, "missing", identifier="gold:1"),
                  gold(operational, "unknown", identifier="gold:2", answerable=False)]
        rows = [prediction(supported, "verified", identifier="prediction:0"),
                prediction(operational, "unknown", identifier="prediction:2")]
        result = score_rows(rows, labels, include_intervals=False)
        # Two matched atoms / three gold; one matched supported / two supported gold.
        self.assertEqual(result.metrics["extraction_precision"], 1.0)
        self.assertAlmostEqual(result.metrics["extraction_recall"], 2 / 3)
        self.assertEqual(result.metrics["supported_extraction_precision"], 1.0)
        self.assertEqual(result.metrics["supported_extraction_recall"], 1 / 2)
        self.assertAlmostEqual(result.metrics["addressable_share"], 2 / 3)
        self.assertEqual(result.counts["supported_extraction_recall_numerator"], 1)
        self.assertEqual(result.counts["supported_extraction_recall_denominator"], 2)
        self.assertEqual(result.counts["gold_atoms"], 3)
        self.assertEqual(result.counts["omitted_atoms"], 1)
        self.assertEqual(result.counts["dev_targets_met"], 0)
        self.assertFalse(result.comparative_complete)

    def test_invalid_supported_prediction_still_penalizes_supported_precision(self):
        """what_bug_this_catches: counting only valid supported outputs and hiding malformed attempts from precision."""
        supported, invalid_supported, operational = self.controls()
        labels = [gold(supported, "verified", identifier="gold:0"),
                  gold(operational, "unknown", identifier="gold:2", answerable=False)]
        invalid = prediction(invalid_supported, "unknown", identifier="prediction:invalid", status="invalid_output")
        invalid = invalid.model_copy(update={"error": "synthetic invalid supported output"})
        rows = [prediction(supported, "verified", identifier="prediction:0"),
                prediction(operational, "unknown", identifier="prediction:2"), invalid]
        result = score_rows(rows, labels, include_intervals=False)
        self.assertAlmostEqual(result.metrics["extraction_precision"], 2 / 3)
        self.assertEqual(result.metrics["extraction_recall"], 1.0)
        self.assertEqual(result.metrics["supported_extraction_precision"], 1 / 2)
        self.assertEqual(result.metrics["supported_extraction_recall"], 1.0)
        self.assertEqual(result.counts["supported_extraction_precision_numerator"], 1)
        self.assertEqual(result.counts["supported_extraction_precision_denominator"], 2)
        self.assertEqual(result.counts["prediction_rows"], 3)
        self.assertEqual(result.counts["invalid_output"], 1)
        self.assertEqual(result.counts["extra_predictions"], 1)

    def test_all_unsupported_sample_keeps_all_atom_omissions_and_undefined_supported_rates(self):
        """what_bug_this_catches: unsupported-only inputs receiving perfect supported metrics from zero denominators."""
        _, _, operational = self.controls()
        marketing = self.atom(3, predicate(kind="marketing", subject=self.lines[3].decode(), module=None))
        labels = [gold(operational, "unknown", identifier="gold:op", answerable=False),
                  gold(marketing, "unknown", identifier="gold:marketing", answerable=False)]
        result = score_rows([prediction(operational, "unknown")], labels, include_intervals=False)
        self.assertIsNone(result.metrics["supported_extraction_precision"])
        self.assertIsNone(result.metrics["supported_extraction_recall"])
        self.assertEqual(result.metrics["extraction_precision"], 1.0)
        self.assertEqual(result.metrics["extraction_recall"], 1 / 2)
        self.assertEqual(result.metrics["addressable_share"], 0.0)
        self.assertEqual(result.counts["omitted_atoms"], 1)
        self.assertEqual(result.counts["dev_targets_met"], 0)

    def test_source_first_omission_handoff_retains_unsupported_atom_in_scorer(self):
        """what_bug_this_catches: narrowing a source-first annotation to candidate-supported atoms before scoring."""
        base = self.base / "manual"
        base.mkdir()
        raw = self.lines[0] + b"\n" + self.lines[2] + b"\n"
        _, root = frozen_source(base, readme=raw)
        atoms, parents = [], []
        for number, line in enumerate((self.lines[0], self.lines[2])):
            start = raw.index(line)
            end = start + len(line)
            parent = select_manual_span(root, start_byte=start, end_byte=end)
            query = predicate() if number == 0 else predicate(kind="operational", subject=line.decode(), module=None)
            atoms.append(select_manual_atom(
                root, start_byte=start, end_byte=end, parent_start_byte=start, parent_end_byte=end,
                atom_ordinal=0, kind=query.kind, normalized=line.decode(), predicates=[query],
                uncertainty=[] if number == 0 else ["unsupported_semantics"],
            ))
            parents.append(parent)
        unreviewed = make_manual_inventory(root, claims=atoms, parent_spans=parents, block_reviews={})
        reviews = {block.block_id: ("extracted", "Synthetic agent selected original assertion; not human review.")
                   for block in unreviewed.blocks}
        inventory = make_manual_inventory(root, claims=atoms, parent_spans=parents, block_reviews=reviews)
        self.assertTrue(inventory.complete)
        annotation = base / "agent-annotation.json"
        record_manual_annotation(root, annotation, family_id="dev:control", inventory=inventory,
                                 parent_spans=parents, annotator_type="agent", annotator_id="D6-synthetic-control",
                                 recorded_at="2026-10-23T00:00:00+00:00")
        candidate = make_manual_inventory(root, claims=atoms[:1], parent_spans=parents[:1],
                                          block_reviews={unreviewed.blocks[0].block_id: reviews[unreviewed.blocks[0].block_id]})
        candidate_path = base / "synthetic-candidate-input.json"
        candidate_path.write_bytes(canonical_json(candidate) + b"\n")
        omissions = base / "omissions.json"
        audit_manual_omissions(root, annotation, candidate_path, omissions)
        omitted_ids = json.loads(omissions.read_bytes())["omitted_manual_ids"]
        self.assertEqual(omitted_ids, [atoms[1].claim_id])
        labels = [gold(atoms[0], "verified", identifier=stable_id("annotation-subject", "dev:control", atoms[0].claim_id)),
                  gold(atoms[1], "unknown", identifier=stable_id("annotation-subject", "dev:control", atoms[1].claim_id), answerable=False)]
        result = score_rows([prediction(atoms[0], "verified")], labels, include_intervals=False)
        self.assertEqual(result.counts["gold_atoms"], 2)
        self.assertEqual(result.counts["omitted_atoms"], 1)
        self.assertEqual(result.metrics["supported_extraction_recall"], 1.0)
        self.assertEqual(result.metrics["extraction_recall"], 1 / 2)
        self.assertEqual(result.metrics["addressable_share"], 1 / 2)
        omitted = next(item for item in result.items if item.status == "omitted")
        self.assertEqual(omitted.gold_id, labels[1].gold_id)
        self.assertEqual(omitted.expected, "unknown")
        self.assertFalse(result.human_adjudicated)
        self.assertFalse(result.comparative_complete)
