"""Source-first manual denominator controls, with synthetic agent records only."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from claim_auditor.contracts import AuditError, GoldAtom, canonical_json, sha256, stable_id
from claim_auditor.evaluation.annotation import (
    audit_manual_omissions, export_manual_gold, export_manual_proposals, make_manual_inventory,
    prepare_source_annotation, record_manual_annotation, record_manual_ruling,
    select_manual_atom, select_manual_span,
)

from .support import frozen_source, gold, predicate


class ManualAnnotationTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.raw = "😀 If enabled, the widget never loses data and works under load.\r\nLatency is guaranteed.\r\n".encode()
        self.snapshot, self.root = frozen_source(self.base, readme=self.raw)
        self.parent_end = self.raw.index(b"\r\n")
        self.atom_start = self.raw.index(b"the widget")
        self.atom_end = self.raw.index(b" and works")

    def atom(self, *, ordinal=0, **changes):
        fields = dict(start_byte=self.atom_start, end_byte=self.atom_end,
                      parent_start_byte=0, parent_end_byte=self.parent_end, atom_ordinal=ordinal,
                      kind="behavioral", normalized=self.raw[self.atom_start:self.atom_end].decode(),
                      predicates=[predicate(kind="behavioral", subject="the widget", module=None,
                                            negated=True, condition="If enabled", qualifiers=["under load"])],
                      uncertainty=["manual_semantic_judgment_required"])
        fields.update(changes)
        return select_manual_atom(self.root, **fields)

    def inventory(self):
        atom = self.atom()
        parent = select_manual_span(self.root, start_byte=0, end_byte=self.parent_end)
        initial = make_manual_inventory(self.root, claims=[atom], parent_spans=[parent], block_reviews={})
        reviews = {initial.blocks[0].block_id: ("extracted", "Synthetic agent selected this original assertion.")}
        inventory = make_manual_inventory(self.root, claims=[atom], parent_spans=[parent], block_reviews=reviews)
        return atom, parent, inventory

    def record(self, out, *, inventory=None, **changes):
        _, parent, original = self.inventory()
        fields = dict(family_id="dev:manual", inventory=original if inventory is None else inventory,
                      parent_spans=[parent], annotator_type="agent", annotator_id="D6-synthetic-agent",
                      recorded_at="2026-10-23T00:00:00+00:00")
        fields.update(changes)
        return record_manual_annotation(self.root, out, **fields)

    def test_source_package_preserves_every_raw_line_without_candidate_prefill(self):
        """what_bug_this_catches: candidate extractor omissions defining the manual annotation denominator."""
        out = self.base / "source-review"
        with patch("claim_auditor.inventory.extract_inventory") as extractor:
            prepare_source_annotation(self.root, out, family_id="dev:manual")
            extractor.assert_not_called()
        package = json.loads((out / "SOURCE.json").read_bytes())
        inventory = package["raw_inventory"]
        self.assertFalse(package["candidate_extractor_loaded"])
        self.assertFalse(package["candidate_findings_loaded"])
        self.assertFalse(package["human_review_performed"])
        self.assertFalse(package["gold_created"])
        self.assertEqual(inventory["claims"], [])
        self.assertFalse(inventory["complete"])
        self.assertEqual(len(inventory["blocks"]), 2)
        self.assertEqual("".join(block["span"]["quote"] for block in inventory["blocks"]).encode(), self.raw)
        self.assertEqual((out / "snapshot" / "files" / "README.md").read_bytes(), self.raw)

    def test_manual_atom_not_limited_to_rules_retains_full_parent_and_qualifiers(self):
        """what_bug_this_catches: a clipped manual atom losing parent condition/negation or borrowing extractor IDs."""
        with patch("claim_auditor.inventory.extract_inventory") as extractor:
            atom = self.atom()
            extractor.assert_not_called()
        self.assertEqual(atom.extraction_method, "manual")
        self.assertEqual(atom.span.quote.encode(), self.raw[self.atom_start:self.atom_end])
        self.assertEqual(atom.parent_id, stable_id("sentence", self.snapshot.snapshot_id, "README.md", 0, self.parent_end))
        self.assertTrue(atom.predicates[0].negated)
        self.assertEqual(atom.predicates[0].condition, "If enabled")
        self.assertEqual(atom.predicates[0].qualifiers, ["under load"])
        self.assertNotEqual(atom.predicates[0].predicate_id, "p:work")
        _, parent, inventory = self.inventory()
        self.assertEqual(parent.quote.encode(), self.raw[:self.parent_end])
        self.assertEqual(inventory.claims[0], atom)

    def test_utf8_split_or_noncontaining_parent_is_refused(self):
        """what_bug_this_catches: manual source selection splitting a code point or detaching qualifier context."""
        with self.assertRaises(AuditError) as caught:
            select_manual_span(self.root, start_byte=1, end_byte=4)
        self.assertEqual(caught.exception.reason, "manual_utf8_boundary")
        with self.assertRaises(AuditError) as caught:
            self.atom(parent_end_byte=self.atom_end - 1)
        self.assertEqual(caught.exception.reason, "manual_parent_bounds")

    def test_unreviewed_raw_line_cannot_be_reflagged_complete(self):
        """what_bug_this_catches: omitted source lines disappearing behind a caller-supplied complete flag."""
        _, _, inventory = self.inventory()
        self.assertFalse(inventory.complete)
        self.assertEqual(inventory.blocks[1].status, "unparsed")
        self.assertEqual(inventory.errors[0].reason, "manual_review_incomplete")
        out = self.base / "forged-complete.json"
        forged = inventory.model_copy(update={"complete": True, "errors": []})
        with self.assertRaises(AuditError) as caught:
            self.record(out, inventory=forged)
        self.assertEqual(caught.exception.reason, "manual_inventory_changed")
        self.assertFalse(out.exists())

    def test_duplicate_atoms_with_different_ordinals_cannot_inflate_denominator(self):
        """what_bug_this_catches: changing an atom ordinal counting the same source meaning twice."""
        parent = select_manual_span(self.root, start_byte=0, end_byte=self.parent_end)
        with self.assertRaises(AuditError) as caught:
            make_manual_inventory(self.root, claims=[self.atom(ordinal=0), self.atom(ordinal=1)],
                                  parent_spans=[parent], block_reviews={})
        self.assertEqual(caught.exception.reason, "manual_atom_conflict")

    def test_agent_history_cannot_be_silently_upgraded_to_human(self):
        """what_bug_this_catches: revising agent inventory into human gold while retaining the old author lineage."""
        previous = self.base / "agent.json"
        self.record(previous)
        before = previous.read_bytes()
        out = self.base / "human-negative-input.json"
        fields = dict(annotator_type="human", annotator_id="NEGATIVE-TEST-NO-HUMAN",
                      action_id="NEGATIVE-TEST-NO-REAL-ACTION", previous_path=previous)
        with self.assertRaises(AuditError) as caught:
            self.record(out, **fields)
        self.assertEqual(caught.exception.reason, "human_action_required")
        with self.assertRaises(AuditError) as caught:
            self.record(out, human_confirmation=True, **fields)
        self.assertEqual(caught.exception.reason, "manual_revision_conflict")
        self.assertFalse(out.exists())
        self.assertEqual(previous.read_bytes(), before)

    def test_empty_candidate_inventory_does_not_drop_manual_omissions(self):
        """what_bug_this_catches: reporting only extractor-discovered atoms and erasing the manual denominator."""
        annotation_path = self.base / "manual.json"
        record = self.record(annotation_path)
        # Synthetic empty candidate input, not a measured passing report fixture.
        empty = make_manual_inventory(self.root, claims=[], parent_spans=[], block_reviews={})
        candidate_path = self.base / "synthetic-empty-candidate.json"
        candidate_path.write_bytes(canonical_json(empty) + b"\n")
        out = self.base / "omissions.json"
        digest = audit_manual_omissions(self.root, annotation_path, candidate_path, out)
        result = json.loads(out.read_bytes())
        expected = [atom.claim_id for atom in record.inventory.claims]
        self.assertEqual(result["all_manual_claim_ids"], expected)
        self.assertEqual(result["omitted_manual_ids"], expected)
        self.assertEqual(result["matched_manual_ids"], [])
        self.assertEqual(result["status"], "provisional_manual_review_incomplete")
        self.assertTrue(result["pending_block_ids"])
        self.assertFalse(result["comparative_complete"])
        self.assertEqual(digest, sha256(out.read_bytes()))

    def test_agent_annotation_cannot_export_a_human_gold_file(self):
        """what_bug_this_catches: preliminary agent annotation being bulk-exported as human-adjudicated gold."""
        annotation_path = self.base / "agent-only.json"
        self.record(annotation_path)
        before = annotation_path.read_bytes()
        out = self.base / "forbidden-human-gold"
        with self.assertRaises(AuditError) as caught:
            export_manual_gold(
                self.root, annotation_path, self.base / "NO-HUMAN-RULINGS.jsonl", out,
                evidence_files={}, ruling_ids={}, operator_id="NEGATIVE-TEST-NO-OPERATOR",
                action_id="NEGATIVE-TEST-NO-REAL-ACTION", recorded_at="2026-10-23T00:00:00+00:00",
                adjudication_rationale="Invalid negative input; no human action or adjudication occurred.",
            )
        self.assertEqual(caught.exception.reason, "manual_actor_conflict")
        self.assertFalse(out.exists())
        self.assertEqual(annotation_path.read_bytes(), before)

    def test_preliminary_proposal_export_keeps_pending_coverage_and_agent_type(self):
        """what_bug_this_catches: a preliminary manual proposal export claiming human gold or complete source review."""
        annotation_path = self.base / "agent-inventory.json"
        record = self.record(annotation_path)
        before = annotation_path.read_bytes()
        atom = record.inventory.claims[0]
        judgment = gold(atom, "unknown", answerable=False,
                        identifier=stable_id("annotation-subject", record.family_id, atom.claim_id))
        judgment = judgment.model_copy(update={"family_id": record.family_id, "annotator_id": record.annotator_id})
        evidence = self.base / "empty-evidence.json"
        evidence.write_bytes(canonical_json({"evidence": [], "coverage": []}) + b"\n")
        ledger = self.base / "agent-history.jsonl"
        row = record_manual_ruling(self.root, annotation_path, ledger, atom=judgment,
                                   evidence_path=evidence, recorded_at="2026-10-23T00:00:00+00:00")
        out = self.base / "preliminary-proposals"
        export_manual_proposals(self.root, annotation_path, ledger, out,
                                evidence_files={atom.claim_id: evidence}, ruling_ids={atom.claim_id: row.ruling_id})
        metadata = json.loads((out / "EXPORT.json").read_bytes())
        self.assertEqual(metadata["mode"], "agent_preliminary_proposals")
        self.assertFalse(metadata["manual_inventory_complete"])
        self.assertTrue(metadata["pending_block_ids"])
        self.assertFalse(metadata["human_confirmation"])
        self.assertFalse(metadata["human_review_independently_verified"])
        self.assertFalse(metadata["comparative_complete"])
        self.assertFalse((out / "gold.jsonl").exists())
        rows = [GoldAtom.model_validate_json(line) for line in (out / "agent-proposals.jsonl").read_bytes().splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].annotator_type, "agent")
        self.assertEqual(annotation_path.read_bytes(), before)
        self.assertEqual((self.root / "files" / "README.md").read_bytes(), self.raw)
