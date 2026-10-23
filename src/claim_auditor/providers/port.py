"""Packet-only fake/replay proposals. No SDK, HTTP, credentials or target imports."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Protocol

from pydantic import ValidationError

from ..accounting import BudgetLedger
from ..contracts import (
    Attempt, AuditError, BudgetState, ProviderFixture, ProviderRequest,
    ProviderResponse, Span, canonical_json, sha256, stable_id, validate_relative_path,
)
from ..screen import screen_original_strings
from ..snapshot.safeio import SnapshotError, read_ordinary


def request_digest(request: ProviderRequest) -> str:
    """Binds arm, full immutable packet, prompt/model/policy and caps."""
    return sha256(canonical_json(request))


class FixtureTransport(Protocol):
    mode: str

    def propose(self, request: ProviderRequest, attempt_index: int) -> ProviderFixture: ...


class FakeTransport:
    mode = "fake"

    def __init__(self, fixtures: list[ProviderFixture]) -> None:
        self.fixtures = tuple(fixtures)

    def propose(self, request: ProviderRequest, attempt_index: int) -> ProviderFixture:
        if attempt_index >= len(self.fixtures):
            raise AuditError("fixture_missing", "No fallback or repeated last fixture is permitted.")
        return self.fixtures[attempt_index]


class ReplayTransport:
    mode = "replay"

    def __init__(self, paths: list[Path]) -> None:
        self.paths = tuple(paths)

    def propose(self, request: ProviderRequest, attempt_index: int) -> ProviderFixture:
        if attempt_index >= len(self.paths):
            raise AuditError("replay_missing", "Every retry requires its own explicitly supplied replay.")
        path = self.paths[attempt_index]
        try:
            return ProviderFixture.model_validate_json(read_ordinary(path.parent, path.name, cap=2 * 1024 * 1024))
        except (SnapshotError, OSError, ValidationError, ValueError) as exc:
            raise AuditError("invalid_replay", "Replay is not a bounded closed ProviderFixture.") from exc


def _readme_span(request: ProviderRequest, span: Span) -> None:
    packet = request.packet
    raw = packet.readme_text.encode("utf-8")
    if (span.snapshot_id != packet.snapshot_id or span.path != packet.readme_path
            or span.file_sha256 != packet.readme_sha256
            or not 0 <= span.start_byte < span.end_byte <= len(raw)
            or raw[span.start_byte:span.end_byte] != span.quote.encode("utf-8")):
        raise AuditError("invalid_proposal_span", "README span is not the exact admitted source bytes.")
    from ..inventory.raw import RawDocument

    if (span.start_line, span.end_line) != RawDocument.decode(raw).line_bounds(span.start_byte, span.end_byte):
        raise AuditError("invalid_proposal_span", "README line coordinates differ.")


def _validate_request(request: ProviderRequest) -> None:
    packet = request.packet
    validate_relative_path(packet.readme_path)
    if (len(packet.readme_text.encode("utf-8")) > 128 * 1024
            or len(packet.excerpts) > 5000
            or any(len(excerpt.quote.encode("utf-8")) > 1024 for excerpt in packet.excerpts)
            or sum(len(excerpt.quote.encode("utf-8")) for excerpt in packet.excerpts) > 48 * 1024
            or len(canonical_json({"entries": packet.scope_entries, "exclusions": packet.exclusions})) > 8 * 1024):
        raise AuditError("input_too_large", "Packet exceeds mandatory README/evidence/scope caps.")
    fields = packet.model_dump(mode="json")
    fields.pop("packet_digest")
    if sha256(canonical_json(fields)) != packet.packet_digest:
        raise AuditError("packet_digest_mismatch", "Packet content differs from its sealed identity.")
    if request.input_digest != sha256(canonical_json(packet)):
        raise AuditError("input_digest_mismatch", "Input digest must hash the complete canonical packet.")
    if sha256(packet.readme_text.encode("utf-8")) != packet.readme_sha256:
        raise AuditError("readme_digest_mismatch", "README bytes differ from packet identity.")
    if packet.absence_certificates:
        raise AuditError("packet_absence_forbidden", "Packet port grants no absence authority.")
    entries = {entry.path: entry for entry in packet.scope_entries}
    if len(entries) != len(packet.scope_entries):
        raise AuditError("duplicate_scope_entry", "Packet scope paths must be unique.")
    for excerpt in packet.excerpts:
        entry = entries.get(excerpt.path)
        if (entry is None or entry.status != "included" or entry.sha256 != excerpt.file_sha256
                or not 0 <= excerpt.start_byte < excerpt.end_byte <= entry.size
                or len(excerpt.quote.encode("utf-8")) != excerpt.end_byte - excerpt.start_byte):
            raise AuditError("invalid_packet_excerpt", "Excerpt coordinates/identity differ from admitted scope.")


def _validate_fixture(request: ProviderRequest, fixture: ProviderFixture) -> None:
    if fixture.request_digest != request_digest(request):
        raise AuditError("replay_identity_mismatch", "Fixture arm/packet/input/prompt/model/policy/caps differ.")
    seen: set[str] = set()
    ranges: set[tuple[int, int, int]] = set()
    for proposal in fixture.proposals:
        if proposal.candidate_id in seen:
            raise AuditError("duplicate_proposal", "A candidate may be proposed only once.")
        seen.add(proposal.candidate_id)
        claim = proposal.claim
        _readme_span(request, claim.span)
        # A byte-exact fragment can still drop a conditional or negation outside
        # its slice. Retain context conservatively until semantic decomposition
        # is independently validated; do not accept stronger clipped assertions.
        raw = request.packet.readme_text.encode("utf-8")
        from markdown_it import MarkdownIt
        from ..inventory.raw import RawDocument

        document = RawDocument.decode(raw)
        context = None
        for token in MarkdownIt("commonmark").parse(document.text):
            if token.type != "inline" or token.map is None:
                continue
            start, end = document.block_bytes(*token.map)
            if start <= claim.span.start_byte < claim.span.end_byte <= end:
                context = (start, end)
                break
        if context is None:
            raise AuditError("invalid_assertion_context", "Proposed atom must be in original assertion prose, not code or HTML.")
        outside = (raw[context[0]:claim.span.start_byte] + b" " + raw[claim.span.end_byte:context[1]]).decode("utf-8")
        if re.search(r"\b(?:if|when|unless|provided|only|except|not|never|always|may|might|must|and|or)\b", outside, re.I):
            raise AuditError("clipped_proposal_qualifier", "Proposed span drops potentially material surrounding qualifiers.")
        parent = stable_id("sentence", request.packet.snapshot_id, claim.span.path,
                           claim.span.start_byte, claim.span.end_byte)
        if (claim.parent_id != parent or claim.claim_id != stable_id("claim", parent, claim.atom_ordinal)
                or proposal.candidate_id != claim.claim_id):
            raise AuditError("invalid_proposal_identity", "Claim IDs must derive from original source coordinates.")
        key = (claim.span.start_byte, claim.span.end_byte, claim.atom_ordinal)
        if key in ranges:
            raise AuditError("duplicate_proposal", "Duplicate source atom.")
        ranges.add(key)
        # Validate a newly proposed exact span, never a rule inventory list.
        # Unsupported semantics must remain explicit unknown-kind atoms. The
        # bounded static grammar cannot justify a stronger paraphrase or dropped
        # negation/condition/qualifier. Future semantic mapping needs its own arm.
        from ..inventory import _predicate

        fields, uncertainty = _predicate(claim.span.quote, {})
        if (len(claim.predicates) != 1 or claim.kind != fields["kind"]
                or claim.normalized != " ".join(claim.span.quote.split())
                or claim.uncertainty != uncertainty):
            raise AuditError("unsupported_proposal_semantics", "Atom kind/qualifiers/uncertainty must match exact quoted assertion.")
        predicate = claim.predicates[0]
        actual = predicate.model_dump(mode="json")
        actual.pop("predicate_id")
        if (actual != fields or predicate.predicate_id != stable_id("predicate", claim.claim_id, fields)):
            raise AuditError("invalid_proposal_predicate", "Predicate changes source meaning or qualifiers.")
        if request.arm == "extraction" and (proposal.relation is not None or proposal.evidence_spans):
            raise AuditError("invalid_proposal", "Extraction cannot provide semantic evidence or verdicts.")
        if request.arm == "single_pass" and proposal.relation is None:
            raise AuditError("invalid_proposal", "Single-pass proposal requires an explicit relation.")
        evidence_keys: set[tuple[str, int, int]] = set()
        for span in proposal.evidence_spans:
            key = (span.path, span.start_byte, span.end_byte)
            if key in evidence_keys:
                raise AuditError("duplicate_evidence", "Repeated evidence pointer.")
            evidence_keys.add(key)
            if span.snapshot_id != request.packet.snapshot_id:
                raise AuditError("invalid_evidence_span", "Evidence snapshot differs.")
            found = False
            for excerpt in request.packet.excerpts:
                if (span.path == excerpt.path and span.file_sha256 == excerpt.file_sha256
                        and excerpt.start_byte <= span.start_byte < span.end_byte <= excerpt.end_byte):
                    raw = excerpt.quote.encode("utf-8")
                    start = span.start_byte - excerpt.start_byte
                    end = span.end_byte - excerpt.start_byte
                    found = raw[start:end] == span.quote.encode("utf-8")
                    if found:
                        break
            if not found:
                raise AuditError("invalid_evidence_span", "Evidence must reopen within an admitted excerpt.")
            # Full file line/identity reopening remains the sole resolver's job.


def produce(request: ProviderRequest, *, transport: FixtureTransport, ledger: BudgetLedger) -> ProviderResponse:
    """One bounded logical request, at most one explicit retry; never a live call.

    Fake/replay observations remain null in Attempt; only current external spend
    is zero. SimulatedUsage is separately persisted for fixture budget behavior.
    """
    # Frozen models still contain mutable lists and unchecked model_copy exists.
    request = ProviderRequest.model_validate_json(canonical_json(request))
    mode = transport.mode
    if mode not in {"fake", "replay"} or type(transport) not in {FakeTransport, ReplayTransport}:
        raise AuditError("live_not_authorized", "Only the built-in inert fixture transports are admitted.")
    digest = request_digest(request)
    attempts: list[Attempt] = []
    usage = []

    def response(status: str, error: str | None, proposals: list | None = None) -> ProviderResponse:
        return ProviderResponse(request_digest=digest, status=status, proposals=proposals or [],
                                attempts=attempts, simulated_usage=usage, error=error,
                                mode=mode, comparative_complete=False)

    try:
        _validate_request(request)
        # Screen original strings, before JSON escapes could hide whitespace.
        if screen_original_strings(request.packet):
            result = response("abstention_screened", "abstention_screened")
            ledger.record_event({"phase": "held", "response": result})
            return result
        caps = request.caps
        initial = BudgetState(remaining_input_tokens=caps.total_input_tokens,
                              remaining_output_tokens=caps.total_output_tokens,
                              remaining_cost_usd=caps.total_cost_usd,
                              remaining_seconds=caps.total_seconds, pending=None, unknown_settlement=False)
        ledger.begin_request(digest, request.packet.packet_digest, caps, initial,
                             treatment=f"{request.arm}:{mode}:{request.model}",
                             max_logical_requests=1 if request.arm == "single_pass" else caps.max_logical_requests)
        for index in range(caps.max_retries + 1):
            reservation = ledger.reserve(caps.request_input_tokens, caps.request_output_tokens,
                                         caps.request_cost_usd, caps.request_seconds)
            attempt = Attempt(attempt_id=stable_id("attempt", digest, reservation.reservation_id),
                              mode="replay", provider=mode, model=request.model,
                              input_digest=request.input_digest, prompt_digest=request.prompt_digest,
                              policy_version=request.policy_version, status="reserved",
                              input_tokens=None, output_tokens=None, cost_usd=0.0,
                              elapsed_seconds=None, error=None)
            ledger.record_event({"phase": "reserved", "attempt": attempt, "reservation": reservation})
            try:
                fixture = transport.propose(request, index)
                fixture = ProviderFixture.model_validate_json(canonical_json(fixture))
                _validate_fixture(request, fixture)
            except (AuditError, ValidationError, ValueError, OSError, ImportError) as exc:
                ledger.settle(reservation.reservation_id, input_tokens=None, output_tokens=None,
                              cost_usd=None, elapsed_seconds=None)
                reason = exc.reason if isinstance(exc, AuditError) else "invalid_output"
                attempt = attempt.model_copy(update={"status": "invalid_output", "error": reason})
                attempts.append(attempt)
                ledger.record_event({"phase": "closed", "attempt": attempt})
                return response("invalid_output", reason)
            usage.append(fixture.simulated_usage)
            try:
                settled = ledger.settle(reservation.reservation_id, **fixture.simulated_usage.model_dump())
            except AuditError as exc:
                attempt = attempt.model_copy(update={"status": "incomplete", "error": exc.reason})
                attempts.append(attempt)
                ledger.record_event({"phase": "closed", "attempt": attempt,
                                     "simulated_usage": fixture.simulated_usage})
                return response("incomplete", exc.reason)
            status = "execution_failure" if fixture.error is not None else "proposed"
            attempt = attempt.model_copy(update={"status": status, "error": fixture.error})
            attempts.append(attempt)
            ledger.record_event({"phase": "closed", "attempt": attempt, "simulated_usage": fixture.simulated_usage})
            if settled.unknown_settlement:
                return response("incomplete", "unsettled_liability")
            if fixture.error is None:
                return response("proposed", None, fixture.proposals)
            if not fixture.retryable or index == caps.max_retries:
                return response("execution_failure", fixture.error)
    except AuditError as exc:
        result = response("incomplete", exc.reason)
        ledger.record_event({"phase": "refused", "response": result})
        return result
    return response("incomplete", "attempt_limit")
