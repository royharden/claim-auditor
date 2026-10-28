"""Dormant authorized provider adapters. Source only; not exercised in Dirty Mode."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import os
import re
import time

from pydantic import ValidationError

from ..accounting import BudgetLedger, budget_admission_id, ledger_root_identity
from ..accounting.pricing import derive_cost, worst_case_cost
from ..contracts import (
    Attempt, AuditError, BudgetState, Claim, CostResult, DatedRateCard, LiveAuthorization, LiveProposalPayload,
    LiveProviderResponse, LiveUsage, Predicate, ProviderFixture, ProviderProposal, SettlementContext, SettlementObservation,
    ProviderRequest, SimulatedUsage, Span, canonical_json, sha256, stable_id,
)
from ..screen import screen_original_strings
from .http_json import BoundedJSONTransport, JSONReply, validate_endpoint
from .port import _validate_fixture, _validate_request, request_digest
from .settlement import validate_settlement_observation


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _json(raw: bytes) -> dict:
    def invalid_constant(value: str) -> None:
        raise ValueError("nonfinite JSON value")

    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique,
                       parse_constant=invalid_constant)
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def _usage(value: dict, reply: JSONReply, *, provider: str, origin: str,
           card: DatedRateCard | None, at: datetime) -> LiveUsage:
    raw = value.get("usage")
    model = value.get("model") if isinstance(value.get("model"), str) else None
    tier = value.get("service_tier") if provider == "openai_compatible" else (raw.get("service_tier") if isinstance(raw, dict) else None)
    pricing = derive_cost(card, provider=provider, resolved_model=model, raw_usage=raw,
                          service_tier=tier if isinstance(tier, str) else None, at=at)
    cost = reply.settled_cost_usd
    receipt = reply.cost_receipt
    if cost is not None and (type(cost) not in {float, int} or not math.isfinite(cost) or cost < 0):
        raise AuditError("invalid_provider_usage", "Invalid cost observation.")
    if cost is not None and not (receipt or "").strip():
        raise AuditError("unreceipted_provider_cost", "A cost observation requires an external settlement receipt.")
    bill = float(cost) if cost is not None else None
    if origin == "fixture":
        basis = "fixture" if bill is not None else "unknown"
    else:
        # A derived calculation is not owner-enabled settlement. The optional
        # bound observer below must explicitly admit it; absence stays unknown.
        cost = None
        basis = "unknown"
    return LiveUsage(origin=origin, resolved_model=model,
                     response_id=value.get("id") if isinstance(value.get("id"), str) else None,
                     input_tokens=pricing.input_tokens, output_tokens=pricing.output_tokens,
                     cost_usd=float(cost) if cost is not None else None, cost_receipt=receipt,
                     elapsed_seconds=reply.elapsed_seconds, raw_usage=raw, cost_basis=basis,
                     reported_bill_usd=bill, pricing=pricing, settlement_context=None,
                     settlement_observation=None, cost_error=None)


def _observe(request: ProviderRequest, payload: bytes, authorization: LiveAuthorization,
             reply: JSONReply, usage: LiveUsage, *, adapter: object,
             transport: BoundedJSONTransport, at: datetime,
             reservation_id: str, attempt_id: str) -> LiveUsage:
    if usage.origin == "fixture":
        return usage  # Explicit simulation remains separate; no live receipt hook.
    if usage.pricing is None:
        return usage.model_copy(update={"cost_usd": None, "cost_basis": "unknown", "cost_error": "pricing_unavailable"})
    context = SettlementContext(authorization_id=authorization.authorization_id,
                                 reservation_id=reservation_id, attempt_id=attempt_id,
                                 request_digest=request_digest(request), payload_digest=sha256(payload),
                                 response_digest=sha256(reply.body), provider=adapter.provider,
                                 requested_model=request.model, resolved_model=usage.resolved_model,
                                 response_id=usage.response_id, origin=usage.origin, raw_usage=usage.raw_usage,
                                 service_tier=usage.pricing.service_tier, requested_at=at.isoformat(), pricing=usage.pricing)
    # Callback gets a separate frozen copy; validation uses the original bytes.
    sealed = canonical_json(context)
    usage = usage.model_copy(update={"settlement_context": context})
    observer = getattr(transport, "settlement_observer", None)
    if observer is None:
        return usage.model_copy(update={"cost_error": "settlement_observer_absent"})
    try:
        if not callable(observer):
            raise AuditError("invalid_settlement_observer", "Explicit trusted callable required.")
        observation = observer(SettlementContext.model_validate_json(sealed))
        if observation is None:
            return usage.model_copy(update={"cost_error": "settlement_observer_unknown"})
        observation = SettlementObservation.model_validate_json(canonical_json(observation))
        observation = validate_settlement_observation(SettlementContext.model_validate_json(sealed), observation,
                                                       rate_card=adapter.rate_card)
        if observation.basis == "provider_bill" and usage.reported_bill_usd is not None and observation.cost_usd != usage.reported_bill_usd:
            raise AuditError("settlement_bill_mismatch", "Supplied provider bill observations disagree.", 4)
        return usage.model_copy(update={"cost_usd": observation.cost_usd, "cost_basis": observation.basis,
                                       "cost_receipt": observation.receipt_reference,
                                       "reported_bill_usd": observation.cost_usd if observation.basis == "provider_bill" else usage.reported_bill_usd,
                                       "settlement_observation": observation, "cost_error": None})
    except Exception as exc:
        reason = exc.reason if isinstance(exc, AuditError) else "settlement_observer_failure"
        return usage.model_copy(update={"cost_usd": None, "cost_basis": "unknown", "cost_error": reason})


class OpenAICompatibleAdapter:
    provider = "openai_compatible"
    route = "/v1/chat/completions"

    def __init__(self, *, rate_card: DatedRateCard | None = None) -> None:
        self.rate_card = rate_card

    def build_request(self, request: ProviderRequest, system_prompt: str, version: str | None) -> bytes:
        if version is not None:
            raise AuditError("invalid_provider_version", "OpenAI-compatible requests do not carry an Anthropic version.")
        fields = {
            "model": request.model, "stream": False, "store": False, "n": 1,
            "max_completion_tokens": request.caps.request_output_tokens,
            "messages": [{"role": "system", "content": system_prompt},
                         {"role": "user", "content": canonical_json(request.packet).decode("utf-8")}],
            "tools": [], "tool_choice": "none",
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "claim_proposals", "strict": True, "schema": LiveProposalPayload.model_json_schema()}},
        }
        if self.rate_card is not None:
            fields["service_tier"] = "default"
        return canonical_json(fields)

    def parse_response(self, value: dict) -> tuple[str | None, str | None]:
        choices = value.get("choices")
        if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
            return None, "invalid_provider_choices"
        choice = choices[0]
        message = choice.get("message")
        if not isinstance(message, dict):
            return None, "invalid_provider_message"
        if message.get("refusal"):
            return None, "provider_refusal"
        if choice.get("finish_reason") != "stop" or message.get("tool_calls") or message.get("function_call"):
            return None, "provider_incomplete_or_tool_call"
        text = message.get("content")
        return (text, None) if isinstance(text, str) else (None, "invalid_provider_content")


class AnthropicAdapter:
    provider = "anthropic"
    route = "/v1/messages"

    def __init__(self, *, rate_card: DatedRateCard | None = None) -> None:
        self.rate_card = rate_card

    def build_request(self, request: ProviderRequest, system_prompt: str, version: str | None) -> bytes:
        if not version or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", version):
            raise AuditError("invalid_provider_version", "Owner must pin the Anthropic API version.")
        # JSON is validated locally; no unsupported structured-output option or
        # tool call is silently assumed to work on an owner-selected model.
        instruction = system_prompt + "\nReturn only JSON conforming to this schema:\n" + canonical_json(LiveProposalPayload.model_json_schema()).decode("utf-8")
        fields = {"model": request.model, "stream": False,
                               "max_tokens": request.caps.request_output_tokens,
                               "system": instruction,
                               "messages": [{"role": "user", "content": canonical_json(request.packet).decode("utf-8")} ]}
        if self.rate_card is not None:
            fields["service_tier"] = "standard_only"
        return canonical_json(fields)

    def parse_response(self, value: dict) -> tuple[str | None, str | None]:
        if value.get("stop_reason") == "refusal":
            return None, "provider_refusal"
        if value.get("stop_reason") != "end_turn":
            return None, "provider_incomplete_or_tool_call"
        content = value.get("content")
        if (not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict)
                or content[0].get("type") != "text" or not isinstance(content[0].get("text"), str)):
            return None, "invalid_provider_content"
        return content[0]["text"], None


def _admit(request: ProviderRequest, payload: bytes, authorization: LiveAuthorization,
           transport: BoundedJSONTransport, adapter: object) -> CostResult | None:
    if not authorization.enabled:
        raise AuditError("live_not_authorized", "Explicit future owner activation is required.")
    try:
        expires = datetime.fromisoformat(authorization.expires_at.replace("Z", "+00:00"))
        if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
            raise ValueError("authorization expired or timezone absent")
    except ValueError as exc:
        raise AuditError("live_not_authorized", "Current timezone-aware owner authorization required.") from exc
    _, _, route = validate_endpoint(authorization.endpoint)
    if authorization.provider != adapter.provider or route != adapter.route:
        raise AuditError("provider_identity_mismatch", "Owner provider identity/route differs from adapter.")
    if (authorization.request_digest != request_digest(request)
            or authorization.payload_digest != sha256(payload)
            or authorization.snapshot_manifest_digest != request.packet.snapshot_manifest_digest):
        raise AuditError("live_admission_identity", "Owner grant must bind exact request, payload and snapshot bytes.")
    # Scope metadata paths/hashes are model-bound data too, not just excerpts.
    paths = {request.packet.readme_path, *(excerpt.path for excerpt in request.packet.excerpts),
             *(entry.path for entry in request.packet.scope_entries),
             *(gap.path for gap in request.packet.exclusions if gap.path is not None)}
    if not paths <= set(authorization.allowed_paths):
        raise AuditError("live_data_scope_denied", "A packet source path is not authorized for this provider.")
    if (authorization.input_token_upper_bound > request.caps.request_input_tokens
            or len(payload) > authorization.max_request_bytes):
        raise AuditError("live_input_liability", "Token/byte admission exceeds reserved request liability.")
    if (transport.authorization_id != authorization.authorization_id
            or transport.hidden_retries != 0 or transport.follows_redirects
            or transport.execution_kind not in {"fixture", "live"}):
        raise AuditError("invalid_transport_policy", "Owner-bound no-retry/no-redirect transport required.")
    if not all(value.strip() for value in (authorization.authorized_by, authorization.authorization_id,
                                           authorization.tokenizer_receipt, authorization.worst_case_cost_receipt)):
        raise AuditError("live_not_authorized", "Admission receipts must be explicit, never inferred.")
    if transport.execution_kind == "live":
        admission = getattr(transport, "budget_admission", None)
        root = getattr(transport, "ledger_root", None)
        if admission is None or root is None:
            raise AuditError("durable_budget_admission_required", "Real transport requires the explicit durable owner budget binding.", 3)
        if (admission.admission_id != budget_admission_id(admission)
                or admission.ledger_root_identity != ledger_root_identity(root)
                or admission.packet_digest != request.packet.packet_digest
                or admission.authorization_ids.get(request.arm) != authorization.authorization_id):
            raise AuditError("budget_admission_mismatch", "Durable budget belongs to a different root/packet/owner role.", 4)
        liability = worst_case_cost(adapter.rate_card, provider=adapter.provider, model=request.model,
                                    input_tokens=request.caps.request_input_tokens,
                                    output_tokens=request.caps.request_output_tokens, at=datetime.now(timezone.utc))
        if liability.amount_usd is None or liability.amount_usd > request.caps.request_cost_usd:
            raise AuditError("pricing_liability_exceeds_cap", "Declared request reserve is below admitted dated-rate worst case.", 3)
        return liability
    return None


def _proposals(request: ProviderRequest, text: str) -> list[ProviderProposal]:
    # Reject duplicate object keys before Pydantic's closed-schema parse.
    payload = LiveProposalPayload.model_validate_json(canonical_json(_json(text.encode("utf-8"))))
    from ..inventory import _predicate

    proposals = []
    raw = request.packet.readme_text.encode("utf-8")
    from ..inventory.raw import RawDocument

    document = RawDocument.decode(raw)
    entries = {entry.path: entry for entry in request.packet.scope_entries}
    for atom in payload.atoms:
        if not 0 <= atom.start_byte < atom.end_byte <= len(raw) or raw[atom.start_byte:atom.end_byte] != atom.quote.encode("utf-8"):
            raise AuditError("invalid_proposal_span", "Provider atom does not reopen original UTF-8 bytes.")
        first_line, last_line = document.line_bounds(atom.start_byte, atom.end_byte)
        span = Span(snapshot_id=request.packet.snapshot_id, path=request.packet.readme_path,
                    file_sha256=request.packet.readme_sha256, start_byte=atom.start_byte,
                    end_byte=atom.end_byte, start_line=first_line, end_line=last_line,
                    quote=atom.quote, quote_sha256=sha256(atom.quote.encode("utf-8")))
        parent = stable_id("sentence", span.snapshot_id, span.path, span.start_byte, span.end_byte)
        claim_id = stable_id("claim", parent, 0)
        fields, uncertainty = _predicate(atom.quote, {})
        if atom.kind != fields["kind"]:
            raise AuditError("unsupported_proposal_semantics", "Proposed kind differs from code-owned source interpretation.")
        predicate = Predicate(predicate_id=stable_id("predicate", claim_id, fields), **fields)
        claim = Claim(claim_id=claim_id, parent_id=parent, atom_ordinal=0, kind=atom.kind,
                      normalized=" ".join(atom.quote.split()), span=span, predicates=[predicate],
                      extraction_method="provider_proposal", extraction_version="exact-span-provider/1",
                      uncertainty=uncertainty)
        evidence = []
        for pointer in atom.evidence:
            entry = entries.get(pointer.path)
            if entry is None:
                raise AuditError("invalid_evidence_span", "Provider evidence path is not admitted.")
            evidence.append(Span(snapshot_id=request.packet.snapshot_id, path=pointer.path,
                                 file_sha256=entry.sha256, start_byte=pointer.start_byte, end_byte=pointer.end_byte,
                                 start_line=pointer.start_line, end_line=pointer.end_line, quote=pointer.quote,
                                 quote_sha256=sha256(pointer.quote.encode("utf-8"))))
        proposals.append(ProviderProposal(candidate_id=claim_id, claim=claim,
                                          relation=atom.relation, evidence_spans=evidence))
    # Reuse the fake/replay producer's exact semantic/span authority. No synthetic
    # fixture usage is treated as an actual provider observation.
    fixture = ProviderFixture(request_digest=request_digest(request), proposals=proposals,
                              simulated_usage=SimulatedUsage(input_tokens=None, output_tokens=None,
                                                             cost_usd=None, elapsed_seconds=None),
                              error=None, retryable=False)
    _validate_fixture(request, fixture)
    return proposals


def produce_live(request: ProviderRequest, *, system_prompt: str,
                 adapter: OpenAICompatibleAdapter | AnthropicAdapter,
                 ledger: BudgetLedger, authorization: LiveAuthorization | None = None,
                 transport: BoundedJSONTransport | None = None) -> LiveProviderResponse:
    """Future owner-activated path. Default refuses before transport/key activity.

    No CLI enables this path in Dirty Mode. HTTPJSONTransport is dormant source;
    caller-supplied fixture transport remains labeled fake. No live measurements
    or comparative acceptance are inferred from source authoring or API output.
    """
    if authorization is None or transport is None or not authorization.enabled:
        raise AuditError("live_not_authorized", "No current owner activation and bounded transport supplied.")
    request = ProviderRequest.model_validate_json(canonical_json(request))
    authorization = LiveAuthorization.model_validate_json(canonical_json(authorization))
    if type(adapter) not in {OpenAICompatibleAdapter, AnthropicAdapter}:
        raise AuditError("invalid_provider_adapter", "Only the two source-owned adapters are admitted.")
    _validate_request(request)
    if sha256(system_prompt.encode("utf-8")) != request.prompt_digest:
        raise AuditError("prompt_digest_mismatch", "Owner prompt differs from request identity.")
    payload = adapter.build_request(request, system_prompt, authorization.anthropic_version)
    _admit(request, payload, authorization, transport, adapter)
    mode = "fake" if transport.execution_kind == "fixture" else "live"
    if mode == "live":
        from pathlib import Path

        root = Path(os.path.abspath(transport.ledger_root))
        if root not in Path(os.path.abspath(ledger.root)).parents:
            raise AuditError("budget_ledger_outside_admission", "Producer leaf must remain inside the owner-selected durable root.", 4)
    attempts = []
    observations = []

    def ledger_error(exc: Exception) -> str:
        return exc.reason if isinstance(exc, AuditError) else "attempt_storage_failure"

    def response(status: str, error: str | None, proposals: list | None = None) -> LiveProviderResponse:
        result = LiveProviderResponse(request_digest=request_digest(request), payload_digest=sha256(payload),
                                      authorization_id=authorization.authorization_id, status=status,
                                      proposals=proposals or [], attempts=attempts, usage=observations,
                                      error=error, mode=mode, comparative_complete=False)
        try:
            ledger.record_event({"phase": "live_source_response", "response": result})
        except (AuditError, OSError, ValueError, TypeError):
            # A typed response must survive a broken event store. Preserve all
            # observations and explicitly report that persistence did not succeed.
            result = result.model_copy(update={"status": "incomplete",
                                                "error": f"{error or status};response_event_persistence_failed"})
        return result

    if screen_original_strings(request.packet):
        return response("abstention_screened", "abstention_screened")
    caps = request.caps
    initial = BudgetState(remaining_input_tokens=caps.total_input_tokens,
                          remaining_output_tokens=caps.total_output_tokens,
                          remaining_cost_usd=caps.total_cost_usd, remaining_seconds=caps.total_seconds,
                          pending=None, unknown_settlement=False)
    try:
        ledger.begin_request(request_digest(request), request.packet.packet_digest, caps, initial,
                             treatment=f"{request.arm}:{mode}:{adapter.provider}:{request.model}",
                             max_logical_requests=1 if request.arm == "single_pass" else caps.max_logical_requests)
        total_started = time.monotonic()
    except (AuditError, OSError, ValueError, TypeError) as exc:
        return response("incomplete", ledger_error(exc))
    for index in range(caps.max_retries + 1):
        try:
            liability = _admit(request, payload, authorization, transport, adapter)
            if time.monotonic() - total_started + caps.request_seconds > caps.total_seconds:
                return response("incomplete", "provider_total_deadline")
            reservation = ledger.reserve(caps.request_input_tokens, caps.request_output_tokens,
                                         caps.request_cost_usd, caps.request_seconds)
        except (AuditError, OSError, ValueError, TypeError) as exc:
            # Especially on retry, never discard already completed attempt/usage
            # rows merely because admission expired or remaining budget ran out.
            return response("incomplete", ledger_error(exc))
        attempt = Attempt(attempt_id=stable_id("attempt", request_digest(request), reservation.reservation_id),
                          mode="replay" if mode == "fake" else "live", provider=f"{mode}:{adapter.provider}",
                          model=request.model, input_digest=request.input_digest, prompt_digest=request.prompt_digest,
                          policy_version=request.policy_version, status="reserved", input_tokens=None,
                          output_tokens=None, cost_usd=0.0 if mode == "fake" else None,
                          elapsed_seconds=None, error=None)
        position = len(attempts)
        attempts.append(attempt)
        try:
            ledger.record_event({"phase": "reserved", "attempt": attempt, "reservation": reservation,
                                 "authorization_id": authorization.authorization_id, "payload_digest": sha256(payload),
                                 "request_digest": request_digest(request), "rate_card": adapter.rate_card,
                                 "budget_admission": getattr(transport, "budget_admission", None),
                                 "pricing_liability": liability})
        except (AuditError, OSError, ValueError, TypeError) as exc:
            attempts[position] = attempt.model_copy(update={"status": "incomplete", "error": ledger_error(exc)})
            return response("incomplete", ledger_error(exc))
        observed = None
        reason = None
        proposals = []
        retryable = False
        try:
            started = time.monotonic()
            requested_at = datetime.now(timezone.utc)
            headers = {"anthropic-version": authorization.anthropic_version} if adapter.provider == "anthropic" else {}
            reply = transport.post_json(endpoint=authorization.endpoint, body=payload, headers=headers,
                                        timeout_seconds=caps.request_seconds, max_response_bytes=authorization.max_response_bytes,
                                        max_attempts=1, follow_redirects=False)
            if (reply.endpoint != authorization.endpoint or reply.physical_attempts != 1
                    or type(reply.status_code) is not int or len(reply.body) > authorization.max_response_bytes
                    or time.monotonic() - started > caps.request_seconds):
                raise AuditError("invalid_transport_reply", "Transport endpoint/attempt/byte/deadline contract failed.")
            if reply.elapsed_seconds is not None and (not math.isfinite(reply.elapsed_seconds)
                                                       or not 0 <= reply.elapsed_seconds <= caps.request_seconds):
                raise AuditError("invalid_transport_reply", "Transport elapsed observation exceeds bounded contract.")
            value = _json(reply.body)
            observed = _usage(value, reply, provider=adapter.provider,
                              origin="fixture" if mode == "fake" else "provider_reported",
                              card=adapter.rate_card, at=requested_at)
            observed = _observe(request, payload, authorization, reply, observed,
                                adapter=adapter, transport=transport, at=requested_at,
                                reservation_id=reservation.reservation_id, attempt_id=attempt.attempt_id)
            observations.append(observed)
            if not 200 <= reply.status_code < 300:
                reason = "provider_http_error"
                retryable = reply.status_code == 429 or 500 <= reply.status_code < 600
            elif observed.resolved_model != request.model:
                reason = "provider_model_mismatch"
            else:
                text, reason = adapter.parse_response(value)
                if reason is None:
                    proposals = _proposals(request, text)
        except (AuditError, ValidationError, ValueError, OSError, ImportError, TypeError, RecursionError, MemoryError) as exc:
            reason = exc.reason if isinstance(exc, AuditError) else "invalid_provider_output"
        try:
            state = ledger.settle(reservation.reservation_id,
                                  input_tokens=observed.input_tokens if observed else None,
                                  output_tokens=observed.output_tokens if observed else None,
                                  cost_usd=observed.cost_usd if observed else None,
                                  elapsed_seconds=observed.elapsed_seconds if observed else None)
        except (AuditError, OSError, ValueError, TypeError) as exc:
            reason = ledger_error(exc)
            state = None
        status = "invalid_output" if reason else "proposed"
        if state is None or state.unknown_settlement:
            status = "incomplete"
        attempt = attempt.model_copy(update={"status": status, "error": reason or ("unsettled_liability" if status == "incomplete" else None),
                                             "input_tokens": observed.input_tokens if observed and mode == "live" else None,
                                             "output_tokens": observed.output_tokens if observed and mode == "live" else None,
                                             "cost_usd": observed.cost_usd if observed and mode == "live" else (0.0 if mode == "fake" else None),
                                             "elapsed_seconds": observed.elapsed_seconds if observed and mode == "live" else None})
        attempts[position] = attempt
        try:
            ledger.record_event({"phase": "closed", "attempt": attempt, "usage": observed})
        except (AuditError, OSError, ValueError, TypeError) as exc:
            attempts[position] = attempt.model_copy(update={"status": "incomplete", "error": ledger_error(exc)})
            return response("incomplete", ledger_error(exc), proposals)
        if status == "incomplete":
            return response("incomplete", reason or (observed.cost_error if observed else None) or "unsettled_liability", proposals)
        if reason is None:
            return response("proposed", None, proposals)
        if not retryable or index == caps.max_retries:
            return response("execution_failure" if reason == "provider_http_error" else "invalid_output", reason)
    return response("incomplete", "attempt_limit")
