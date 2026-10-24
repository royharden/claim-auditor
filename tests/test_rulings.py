"""Append-only annotation regressions; all judgment inputs are synthetic DEV controls."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.contracts import AuditError, canonical_json, sha256
from claim_auditor.evaluation.rulings import (
    append_ruling, current_rulings, export_rulings, import_rulings, load_rulings, make_ruling,
)
from claim_auditor.snapshot import read_source

from .support import claim, frozen_source, gold, span_for


class RulingTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.snapshot, root = frozen_source(self.base)
        self.atom = claim(span_for(self.snapshot, read_source(self.snapshot, root, "README.md")))
        self.ledger = self.base / "rulings.jsonl"
        self.evidence_digest = sha256(canonical_json([]))

    def ruling(self, *, atom=None, previous=None, evidence=None, manifest=None, human_action=None):
        return make_ruling(
            gold(self.atom, "verified") if atom is None else atom,
            source_manifest_digest=manifest or self.snapshot.manifest_digest,
            evidence_digest=evidence or self.evidence_digest,
            recorded_at="2026-10-23T00:00:00+00:00",
            supersedes_ruling_id=previous, human_action_id=human_action,
        )

    def current(self, *, evidence=None, manifest=None):
        return current_rulings(
            self.ledger, source_manifest_digest=manifest or self.snapshot.manifest_digest,
            claim_digests={self.atom.claim_id: sha256(canonical_json(self.atom))},
            evidence_digests={self.atom.claim_id: evidence or self.evidence_digest},
        )

    def test_exact_reimport_is_idempotent_and_export_preserves_bytes(self):
        """what_bug_this_catches: repeated imports becoming extra judgments or rewriting history."""
        row = self.ruling()
        append_ruling(self.ledger, row)
        before = self.ledger.read_bytes()
        export = self.base / "export.jsonl"
        digest = export_rulings(self.ledger, export)
        self.assertEqual(export.read_bytes(), before)
        self.assertEqual(digest, sha256(before))
        self.assertEqual(import_rulings(self.ledger, export), [])
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertEqual([r.ruling_id for r in load_rulings(self.ledger)], [row.ruling_id])

    def test_revision_keeps_predecessor_and_disagreement(self):
        """what_bug_this_catches: latest-ruling projection deleting earlier judgments or disagreement."""
        first_atom = gold(self.atom, "verified").model_copy(update={"disagreements": ["reviewer disputes scope"]})
        first = self.ruling(atom=first_atom)
        append_ruling(self.ledger, first)
        prefix = self.ledger.read_bytes()
        revised = first_atom.model_copy(update={"rationale": "Reconsidered; same source and retained disagreement."})
        second = self.ruling(atom=revised, previous=first.ruling_id)
        append_ruling(self.ledger, second)
        self.assertTrue(self.ledger.read_bytes().startswith(prefix))
        self.assertEqual([r.ruling_id for r in load_rulings(self.ledger)], [first.ruling_id, second.ruling_id])
        self.assertEqual([r.ruling_id for r in self.current()], [second.ruling_id])
        self.assertEqual(self.current()[0].atom.disagreements, first_atom.disagreements)

    def test_changed_current_source_or_evidence_binding_is_refused(self):
        """what_bug_this_catches: applying a stale judgment to newly reopened source/evidence bytes."""
        append_ruling(self.ledger, self.ruling())
        before = self.ledger.read_bytes()
        for changes in ({"evidence": "1" * 64}, {"manifest": "2" * 64}):
            with self.subTest(changes=changes), self.assertRaises(AuditError) as caught:
                self.current(**changes)
            self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("ruling_binding_changed", 4))
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_another_annotator_cannot_rebind_same_subject(self):
        """what_bug_this_catches: a new annotator silently relabeling a changed claim/evidence subject."""
        first = self.ruling()
        append_ruling(self.ledger, first)
        other = first.atom.model_copy(update={"annotator_id": "another-agent-negative-control"})
        incoming = self.ruling(atom=other, evidence="1" * 64)
        before = self.ledger.read_bytes()
        with self.assertRaises(AuditError) as caught:
            append_ruling(self.ledger, incoming)
        self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("ruling_binding_changed", 4))
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_revision_must_supersede_latest_and_preserve_disagreement(self):
        """what_bug_this_catches: overwriting another revision or erasing a dissenting observation."""
        atom = gold(self.atom, "verified").model_copy(update={"disagreements": ["scope disputed"]})
        first = self.ruling(atom=atom)
        append_ruling(self.ledger, first)
        altered = atom.model_copy(update={"rationale": "Changed judgment reasoning."})
        before = self.ledger.read_bytes()
        for incoming, reason in (
            (self.ruling(atom=altered), "ruling_revision_conflict"),
            (self.ruling(atom=altered.model_copy(update={"disagreements": []}), previous=first.ruling_id),
             "ruling_disagreement_lost"),
        ):
            with self.subTest(reason=reason), self.assertRaises(AuditError) as caught:
                append_ruling(self.ledger, incoming)
            self.assertEqual(caught.exception.reason, reason)
            self.assertEqual(self.ledger.read_bytes(), before)

    def test_human_typed_negative_input_requires_explicit_operator_action(self):
        """what_bug_this_catches: an imported human-typed record bypassing the operator-action gate."""
        # Invalid provenance is solely a refusal probe; it is never stored or scored.
        fake_human = gold(self.atom, "verified").model_copy(update={
            "annotator_type": "human", "annotator_id": "NEGATIVE-TEST-NO-HUMAN",
            "adjudicated_at": "2026-10-22T00:00:00+00:00",
        })
        row = self.ruling(atom=fake_human, human_action="NEGATIVE-TEST-NOT-A-REAL-ACTION")
        with self.assertRaises(AuditError) as caught:
            append_ruling(self.ledger, row)
        self.assertEqual(caught.exception.reason, "human_action_required")
        self.assertFalse(self.ledger.exists())

    def test_unterminated_append_is_not_silently_recovered(self):
        """what_bug_this_catches: a crashed partial append being truncated or accepted as history."""
        self.ledger.write_bytes(canonical_json(self.ruling()))
        before = self.ledger.read_bytes()
        with self.assertRaises(AuditError) as caught:
            load_rulings(self.ledger)
        self.assertEqual(caught.exception.reason, "incomplete_ruling_append")
        self.assertEqual(self.ledger.read_bytes(), before)
