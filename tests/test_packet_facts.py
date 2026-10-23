"""Complete admitted-file proof controls; parser/platform execution remains deferred."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.audit.policy import decide_finding
from claim_auditor.contracts import PacketExcerpt
from claim_auditor.evaluation.packet_facts import build_packet_facts, resolve_packet_predicate
from claim_auditor.snapshot import read_source

from .support import claim, frozen_source, packet_for, predicate, span_for


class PacketFactTests(unittest.TestCase):
    def inputs(self, code, *, partial=False):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        snapshot, root = frozen_source(Path(temporary.name), code=code)
        raw = read_source(snapshot, root, "README.md")
        entry = next(e for e in snapshot.entries if e.path == "tiny.py")
        after = len(code) - 1 if partial else len(code)
        excerpt = PacketExcerpt(path="tiny.py", start_byte=0, end_byte=after,
                                file_sha256=entry.sha256, quote=code[:after].decode(), anchor="work")
        packet = packet_for(snapshot, raw, excerpts=[excerpt])
        return snapshot, root, raw, packet, build_packet_facts(packet)

    def test_complete_explicit_module_supports_a_declaration_with_reopened_evidence(self):
        """what_bug_this_catches: complete admitted declarations remaining unusable or borrowing hidden files."""
        snapshot, root, _, packet, facts = self.inputs(b"def work():\n    pass\n")
        self.assertEqual(facts.complete_paths, {"tiny.py"})  # real future parser prerequisite
        result = resolve_packet_predicate(packet, facts, snapshot, root, predicate())
        self.assertEqual(result.state, "established")
        self.assertEqual([e.kind for e in result.evidence], ["positive"])
        self.assertEqual(result.evidence[0].span.path, "tiny.py")
        self.assertEqual(result.coverage, [])
        self.assertFalse(facts.diagnostics()["absence_authority"])

    def test_partial_file_cannot_be_promoted_to_a_complete_module(self):
        """what_bug_this_catches: parsing a truncated snippet as an entire trusted namespace."""
        snapshot, root, _, packet, facts = self.inputs(b"def work():\n    pass\n", partial=True)
        self.assertNotIn("tiny.py", facts.complete_paths)
        result = resolve_packet_predicate(packet, facts, snapshot, root, predicate())
        self.assertEqual(result.state, "unknown")
        self.assertEqual(result.reason, "packet_incomplete_file_context")
        self.assertEqual(result.evidence, [])

    def test_dynamic_scope_cannot_supply_an_accusation(self):
        """what_bug_this_catches: a conditional declaration being mistaken for a complete static namespace."""
        code = b"if enabled:\n    def work():\n        pass\n"
        snapshot, root, raw, packet, facts = self.inputs(code)
        self.assertIn("tiny.py", facts.complete_paths)
        self.assertTrue(facts.flags["tiny.py"])
        query = predicate(subject="invented")
        result = resolve_packet_predicate(packet, facts, snapshot, root, query)
        finding = decide_finding(claim(span_for(snapshot, raw), query), [result], citation_valid=True)
        self.assertEqual(finding.verdict, "unknown")
        self.assertEqual(finding.accused_predicate_ids, [])

    def test_absent_symbol_never_becomes_packet_negative_coverage(self):
        """what_bug_this_catches: even complete packet files acquiring undeclared absence authority."""
        snapshot, root, raw, packet, facts = self.inputs(b"def work():\n    pass\n")
        self.assertIn("tiny.py", facts.complete_paths)
        for negated in (False, True):
            query = predicate(subject="invented", negated=negated)
            with self.subTest(negated=negated):
                result = resolve_packet_predicate(packet, facts, snapshot, root, query)
                self.assertEqual(result.state, "unknown")
                self.assertEqual(result.evidence, [])
                self.assertEqual(result.coverage, [])
                self.assertEqual(decide_finding(claim(span_for(snapshot, raw), query), [result], citation_valid=True).verdict,
                                 "unknown")

    def test_opposite_literal_requires_exact_complete_binding_and_namespace(self):
        """what_bug_this_catches: a whole wrong value becoming partial or borrowing another key's value."""
        snapshot, root, raw, packet, facts = self.inputs(b"LIMIT = 2\n")
        self.assertIn("tiny.py", facts.complete_paths)
        query = predicate(kind="config_literal", subject="LIMIT", path="tiny.py", key="LIMIT", expected=3)
        result = resolve_packet_predicate(packet, facts, snapshot, root, query)
        self.assertEqual(result.state, "contradicted")
        self.assertEqual([e.kind for e in result.evidence], ["contrary"])
        self.assertEqual(decide_finding(claim(span_for(snapshot, raw), query), [result], citation_valid=True).verdict,
                         "missing")
        wrong_scope = query.model_copy(update={"path": "other.py", "module": "other"})
        absent_key = query.model_copy(update={"key": "OTHER", "subject": "OTHER"})
        for alternative in (wrong_scope, absent_key):
            with self.subTest(alternative=alternative):
                unresolved = resolve_packet_predicate(packet, facts, snapshot, root, alternative)
                self.assertEqual(unresolved.state, "unknown")
                self.assertEqual(unresolved.evidence, [])
