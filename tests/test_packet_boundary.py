"""Reopening/authority tests shared by every packet-limited treatment."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.contracts import AuditError, PacketExcerpt, canonical_json, sha256
from claim_auditor.evaluation.arms import (
    packet_inventory, resolve_packet_claims, validate_packet, validate_proposal_citations,
)
from claim_auditor.evaluation.packet_facts import build_packet_facts
from claim_auditor.snapshot import read_source

from .provider_support import proposal_for, proposed_atom
from .support import frozen_source, packet_for, span_for


class PacketBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.snapshot, self.root = frozen_source(self.base)
        self.raw = read_source(self.snapshot, self.root, "README.md")
        self.code = read_source(self.snapshot, self.root, "tiny.py")
        entry = next(e for e in self.snapshot.entries if e.path == "tiny.py")
        self.excerpt = PacketExcerpt(path="tiny.py", start_byte=0, end_byte=len(self.code),
                                     file_sha256=entry.sha256, quote=self.code.decode(), anchor="work")

    def test_rehashed_packet_cannot_forge_excerpt_bytes(self):
        """what_bug_this_catches: internally consistent packet hashes substituting for source reopening."""
        forged = self.excerpt.model_copy(update={"quote": self.excerpt.quote.replace("work", "fake")})
        packet = packet_for(self.snapshot, self.raw, excerpts=[forged])
        self.assertEqual(sha256(canonical_json(packet.model_dump(mode="json", exclude={"packet_digest"}))),
                         packet.packet_digest)
        with self.assertRaises(AuditError) as caught:
            validate_packet(packet, self.snapshot, self.root)
        self.assertEqual(caught.exception.reason, "citation_quote_or_lines")

    def test_unused_model_pointer_still_needs_valid_coordinates(self):
        """what_bug_this_catches: invalid citations surviving because deterministic inference ignores them."""
        packet = packet_for(self.snapshot, self.raw, excerpts=[self.excerpt])
        pointer = span_for(self.snapshot, self.code, path="tiny.py").model_copy(update={
            "start_line": 2, "end_line": 2,
        })
        proposal = proposal_for(proposed_atom(self.snapshot, self.raw), relation="supports", evidence=[pointer])
        with self.assertRaises(AuditError) as caught:
            validate_proposal_citations(packet, self.snapshot, self.root, [proposal])
        self.assertEqual(caught.exception.reason, "citation_quote_or_lines")

    def test_candidate_cannot_retrieve_unadmitted_declaration_or_accuse_absence(self):
        """what_bug_this_catches: a candidate using the full index for undeclared packet evidence."""
        packet = packet_for(self.snapshot, self.raw)
        inventory = packet_inventory(packet, self.snapshot, self.root)
        rows, evidence = resolve_packet_claims(packet, self.snapshot, self.root, inventory.claims,
                                               facts=build_packet_facts(packet))
        self.assertTrue(rows)
        self.assertTrue(all(row.finding.verdict == "unknown" for row in rows))
        self.assertTrue(all(not row.accused_predicate_ids for row in rows))
        self.assertEqual(evidence, [])

    def test_packet_never_gains_absence_certificates_by_resealing(self):
        """what_bug_this_catches: a caller granting packet arms exhaustive-absence authority by flag."""
        packet = packet_for(self.snapshot, self.raw).model_copy(update={"absence_certificates": True})
        body = packet.model_dump(mode="json", exclude={"packet_digest"})
        packet = packet.model_copy(update={"packet_digest": sha256(canonical_json(body))})
        with self.assertRaises(AuditError) as caught:
            validate_packet(packet, self.snapshot, self.root)
        self.assertEqual(caught.exception.reason, "packet_absence_privilege")
