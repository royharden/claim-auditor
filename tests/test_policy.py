"""Consequential accusation rules, using explicit index seams rather than target imports."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.audit.policy import decide_finding
from claim_auditor.contracts import PredicateResult, ScopeGap
from claim_auditor.index import Fact, StaticIndex, resolve
from claim_auditor.snapshot import read_source

from .support import claim, frozen_source, predicate, span_for


class PolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.snapshot, self.root = frozen_source(Path(temporary.name))
        raw = read_source(self.snapshot, self.root, "README.md")
        self.span = span_for(self.snapshot, raw)

    def test_dynamic_or_unparsed_scope_never_accuses_absence(self):
        """what_bug_this_catches: an empty partial index being treated as exhaustive absence."""
        query = predicate(subject="invented")
        cases = [dict(dynamic_flags=["tiny.py:dynamic_namespace"]),
                 dict(parse_failures=[ScopeGap(path="tiny.py", reason="syntax_error")]),
                 dict(snapshot=self.snapshot.model_copy(update={
                     "complete": False,
                     "exclusions": [ScopeGap(path="hidden.py", reason="unavailable")],
                 }))]
        for changes in cases:
            fields = dict(snapshot=self.snapshot, root=self.root)
            fields.update(changes)
            with self.subTest(changes=changes):
                result = resolve(StaticIndex(**fields), query)
                finding = decide_finding(claim(self.span, query), [result], citation_valid=True)
                self.assertEqual(result.state, "unknown")
                self.assertEqual(finding.verdict, "unknown")
                self.assertEqual(finding.accused_predicate_ids, [])
                self.assertFalse(any(e.kind == "negative" for e in result.evidence))

    def test_whole_value_contradiction_is_missing_not_partial(self):
        """what_bug_this_catches: subject existence rescuing a fully wrong literal value."""
        with TemporaryDirectory() as directory:
            raw = b"LIMIT = 2\n"
            snapshot, root = frozen_source(Path(directory), code=raw)
            query = predicate(kind="config_literal", subject="LIMIT", key="LIMIT", expected=3)
            index = StaticIndex(snapshot=snapshot, root=root, facts=[
                Fact("config_literal", "LIMIT", "LIMIT", 2, "tiny.py", "tiny", 0, 9, 1, 1),
            ])
            result = resolve(index, query)
            finding = decide_finding(claim(span_for(snapshot, read_source(snapshot, root, "README.md")), query),
                                     [result], citation_valid=True)
            self.assertEqual(result.state, "contradicted")
            self.assertEqual(finding.verdict, "missing")
            self.assertEqual(finding.supported_predicate_ids, [])
            self.assertEqual(finding.accused_predicate_ids, [query.predicate_id])

    def test_negation_reverses_complete_absence_and_located_presence(self):
        """what_bug_this_catches: treating a negated claim like its positive proposition."""
        query = predicate(negated=True)
        index = StaticIndex(snapshot=self.snapshot, root=self.root)
        absent = resolve(index, query)
        self.assertEqual(decide_finding(claim(self.span, query), [absent], citation_valid=True).verdict,
                         "verified")
        index.facts = [Fact("symbol_declared", "work", None, None, "tiny.py", "tiny", 0, 21, 1, 2)]
        present = resolve(index, query)
        self.assertEqual(decide_finding(claim(self.span, query), [present], citation_valid=True).verdict,
                         "missing")

    def test_runtime_proxy_cannot_become_verification(self):
        """what_bug_this_catches: a model or suggestive name verifying runtime reliability."""
        query = predicate(kind="behavioral", subject="retries reliably")
        result = PredicateResult(predicate_id=query.predicate_id, state="unknown",
                                 reason="unsupported_semantics", evidence=[], coverage=[], complete=True)
        finding = decide_finding(claim(self.span, query), [result], citation_valid=True,
                                 model_proposal="verified")
        self.assertEqual(finding.verdict, "unknown")
        self.assertEqual(finding.accused_predicate_ids, [])

    def test_failed_citation_suppresses_support_and_active_evidence(self):
        """what_bug_this_catches: retaining a supported verdict after citation integrity fails."""
        index = StaticIndex(snapshot=self.snapshot, root=self.root)
        query = predicate(subject="invented")
        finding = decide_finding(claim(self.span, query), [resolve(index, query)], citation_valid=False)
        self.assertEqual(finding.verdict, "unknown")
        self.assertEqual(finding.evidence_ids, [])
        self.assertEqual(finding.citation_validation, "failed")
