"""Packet-only deterministic support; no full-index query or absence privilege."""

from __future__ import annotations

from pathlib import Path

from claim_auditor.audit.policy import decide_finding
from claim_auditor.citations import validate_span
from claim_auditor.contracts import (
    AuditError, Claim, EvaluationPacket, Evidence, Inventory, Limits, PredicateResult, PredictionRow,
    ProviderProposal, Snapshot, Span, canonical_json, sha256, stable_id,
)
from claim_auditor.inventory import extract_inventory


def validate_packet(packet: EvaluationPacket, snapshot: Snapshot, root: Path) -> None:
    """Reopen admitted bytes solely for integrity, never hidden retrieval."""
    fields = packet.model_dump(mode="json", exclude={"packet_digest"})
    if sha256(canonical_json(fields)) != packet.packet_digest:
        raise AuditError("packet_integrity_failure", "packet digest differs", 4)
    if (packet.snapshot_id, packet.snapshot_manifest_digest) != (snapshot.snapshot_id, snapshot.manifest_digest):
        raise AuditError("packet_snapshot_mismatch", "packet belongs to another snapshot", 4)
    if canonical_json(packet.scope_entries) != canonical_json(snapshot.entries):
        raise AuditError("packet_scope_mismatch", "packet source inventory differs", 4)
    if packet.absence_certificates:
        raise AuditError("packet_absence_privilege", "packet arms cannot acquire absence certificates", 4)
    raw = packet.readme_text.encode("utf-8")
    if len(raw) > Limits().max_readme_bytes:
        raise AuditError("input_too_large", "mandatory README exceeds admitted cap")
    if len(canonical_json({"entries": packet.scope_entries, "exclusions": packet.exclusions})) > 8 * 1024:
        raise AuditError("input_too_large", "mandatory scope metadata exceeds admitted cap")
    if sha256(raw) != packet.readme_sha256:
        raise AuditError("packet_integrity_failure", "README digest differs", 4)
    validate_span(snapshot, root, _span(packet, packet.readme_path, packet.readme_sha256, 0, raw))
    if len(packet.excerpts) > 5000 or sum(len(e.quote.encode("utf-8")) for e in packet.excerpts) > 48 * 1024:
        raise AuditError("input_too_large", "packet evidence exceeds admitted bound")
    for excerpt in packet.excerpts:
        quote = excerpt.quote.encode("utf-8")
        if len(quote) > 1024 or excerpt.end_byte - excerpt.start_byte != len(quote):
            raise AuditError("packet_integrity_failure", "excerpt bounds differ", 4)
        # The sole resolver calculates/checks line coordinates against frozen bytes.
        # These bytes are not exposed to inference beyond the admitted interval.
        from claim_auditor.snapshot import read_source

        frozen = read_source(snapshot, root, excerpt.path)
        span = _span(packet, excerpt.path, excerpt.file_sha256, excerpt.start_byte, quote, frozen)
        validate_span(snapshot, root, span)


def _span(packet: EvaluationPacket, path: str, digest: str, start: int, quote: bytes,
          frozen: bytes | None = None) -> Span:
    raw = quote if frozen is None else frozen
    end = start + len(quote)
    return Span(snapshot_id=packet.snapshot_id, path=path, file_sha256=digest,
                start_byte=start, end_byte=end, start_line=raw[:start].count(b"\n") + 1,
                end_line=raw[:max(start, end - 1)].count(b"\n") + 1,
                quote=quote.decode("utf-8"), quote_sha256=sha256(quote))


def packet_inventory(packet: EvaluationPacket, snapshot: Snapshot, root: Path) -> Inventory:
    """The existing inventory reads only the integrity-checked packet README."""
    inventory = extract_inventory(snapshot, root, packet.readme_path)
    if inventory.readme_sha256 != packet.readme_sha256:
        raise AuditError("packet_integrity_failure", "candidate inventory read a different README", 4)
    return inventory


def failure_row(snapshot_id: str, arm: str, status: str, reason: str,
                ordinal: int = 0) -> PredictionRow:
    """One explicit pipeline row even when an arm produces no usable atoms."""
    return PredictionRow(prediction_id=stable_id("paired-failure", snapshot_id, arm, ordinal, reason),
                         family_id=snapshot_id, finding=None, accused_predicate_ids=[],
                         status=status, error=reason)


def validate_proposal_citations(packet: EvaluationPacket, snapshot: Snapshot, root: Path,
                                proposals: list[ProviderProposal]) -> None:
    """Reopen even unused model pointers; an invalid pointer is an integrity error."""
    for proposal in proposals:
        for span in proposal.evidence_spans:
            if not any(span.path == excerpt.path and span.file_sha256 == excerpt.file_sha256
                       and excerpt.start_byte <= span.start_byte < span.end_byte <= excerpt.end_byte
                       and excerpt.quote.encode("utf-8")[span.start_byte - excerpt.start_byte:
                                                         span.end_byte - excerpt.start_byte] == span.quote.encode("utf-8")
                       for excerpt in packet.excerpts):
                raise AuditError("unadmitted_evidence_span", "model pointer escapes packet", 4)
            validate_span(snapshot, root, span)


def resolve_packet_claims(packet: EvaluationPacket, snapshot: Snapshot, root: Path,
                          claims: list[Claim], *,
                          source_inventory: Inventory | None = None,
                          model_proposal: str | None = None) -> tuple[list[PredictionRow], list[Evidence]]:
    """Establish only exact, code-recognized positive path predicates.

    A model's semantics, confidence and proposed verdict never establish support.
    Other kinds stay unknown until a bounded packet-owned proof is implemented.
    """
    predictions: list[PredictionRow] = []
    evidence: list[Evidence] = []
    seen: set[str] = set()
    for claim in claims:
        if claim.claim_id in seen:
            raise AuditError("invalid_output", "duplicate proposed claim identity")
        seen.add(claim.claim_id)
        if (claim.span.path, claim.span.file_sha256) != (packet.readme_path, packet.readme_sha256):
            raise AuditError("unadmitted_claim_span", "proposal is not a packet README atom", 4)
        validate_span(snapshot, root, claim.span)
        # Parse each new exact span independently; never require prior discovery
        # by the candidate inventory or pass its atoms into a provider request.
        from claim_auditor.inventory import _predicate

        fields, uncertainty = _predicate(claim.span.quote, {})
        recognized = (len(claim.predicates) == 1 and claim.kind == fields["kind"]
                      and claim.normalized == " ".join(claim.span.quote.split())
                      and claim.uncertainty == uncertainty
                      and claim.predicates[0].model_dump(mode="json", exclude={"predicate_id"}) == fields)
        # A narrow quote may drop a surrounding "if", negation or example fence.
        # Existing independently parsed whole assertions constrain support only:
        # every new valid model atom is still emitted, with unknown when no such
        # code-owned assertion support exists. Nothing is sent to the provider.
        assertion_context = source_inventory is not None and any(
            source_claim.span == claim.span
            and source_claim.kind == claim.kind
            and not source_claim.uncertainty
            and [p.model_dump(exclude={"predicate_id"}) for p in source_claim.predicates]
                == [p.model_dump(exclude={"predicate_id"}) for p in claim.predicates]
            for source_claim in source_inventory.claims
        )
        results: list[PredicateResult] = []
        for predicate in claim.predicates:
            proof: list[Evidence] = []
            # Negation/qualifiers/conditions cannot become a path-existence shortcut.
            eligible = (recognized and assertion_context and not claim.uncertainty and len(claim.predicates) == 1
                        and predicate.kind == "path_exists" and not predicate.negated
                        and predicate.condition is None and not predicate.qualifiers)
            excerpt = next((e for e in packet.excerpts if e.path == predicate.path), None) if eligible else None
            if excerpt is not None:
                from claim_auditor.snapshot import read_source

                frozen = read_source(snapshot, root, excerpt.path)
                pointer = _span(packet, excerpt.path, excerpt.file_sha256, excerpt.start_byte,
                                excerpt.quote.encode("utf-8"), frozen)
                validate_span(snapshot, root, pointer)
                proof.append(Evidence(evidence_id=stable_id("packet-evidence", packet.packet_digest, predicate.predicate_id),
                                      kind="positive", span=pointer, coverage_id=None, query=predicate,
                                      scope_id=snapshot.scope_id, parser_version="literal-path/1",
                                      index_version="packet-proof/1", pattern_version="none"))
            evidence.extend(proof)
            results.append(PredicateResult(predicate_id=predicate.predicate_id,
                                           state="established" if proof else "unknown",
                                           reason="admitted_path_excerpt" if proof else "packet_no_complete_proof",
                                           evidence=proof, coverage=[], complete=bool(proof)))
        finding = decide_finding(claim, results, citation_valid=True, model_proposal=model_proposal)
        predictions.append(PredictionRow(prediction_id=claim.claim_id, family_id=snapshot.snapshot_id,
                                         finding=finding, accused_predicate_ids=finding.accused_predicate_ids,
                                         status="prediction", error=None))
    return predictions, evidence
