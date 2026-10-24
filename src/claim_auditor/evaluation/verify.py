"""Offline paired-artifact verification and post-closure descriptive scoring."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from claim_auditor.citations import validate_span, verify_report
from claim_auditor.accounting import budget_admission_id
from claim_auditor.accounting.pricing import derive_cost, worst_case_cost
from claim_auditor.contracts import (
    Attempt, AuditError, AuditReport, BudgetState, CostResult, EvaluationLock, EvaluationPacket, EvaluationResult, Evidence, GoldAtom,
    DatedRateCard, Inventory, LiveAuthorization, LiveBudgetAdmission, LiveProviderResponse, LiveUsage,
    PredictionRow, ProviderCaps, ProviderRequest, ProviderResponse, Reservation,
    canonical_json, sha256, stable_id,
)
from claim_auditor.evaluation.arms import (
    assemble_provider_rows, failure_row, packet_inventory, resolve_packet_claims, settlement_unknown, validate_packet,
)
from claim_auditor.evaluation.baseline import run_packet_grep
from claim_auditor.evaluation.packet import _check_lock, _source_metadata, code_digest
from claim_auditor.evaluation.packet_facts import PACKET_FACT_VERSION, build_packet_facts
from claim_auditor.evaluation.runner import PAIRED_ARMS, RUNNER_VERSION, _packet_screened, _status, _write
from claim_auditor.evaluation.scoring import score_rows
from claim_auditor.index import PARSER_VERSION
from claim_auditor.snapshot import load_snapshot
from claim_auditor.snapshot.safeio import bounded_scandir, read_ordinary
from claim_auditor.providers.settlement import validate_settlement_observation

_CAP = 32 * 1024 * 1024
_TOP = {"runner_version", "run_id", "code_digest", "parser_version", "packet_fact_version",
        "snapshot_id", "packet_digest", "input_digest", "mode", "state", "started_at", "completed_at",
        "source_only", "runtime_validation", "comparative_complete", "human_adjudicated",
        "caps", "arms", "artifacts", "limitations", "experiment", "execution_summary", "dispatch_halt"}
_INFO = {"status", "rows", "failure_rows", "input_digest", "packet_digest", "treatment"}
_PROVIDER_INFO = {"request", "response", "attempts", "simulated_usage", "provider_observations",
                  "usage", "provider_protocol", "authorization", "execution_kind"}
_PROVIDER_INFO |= {"producer_invoked", "response_bound", "rate_card"}


def _validate_usage(usage: LiveUsage, request: ProviderRequest, grant: LiveAuthorization,
                     response: LiveProviderResponse, attempt: Attempt, reservation: Reservation,
                     card: DatedRateCard | None) -> None:
    """Replay the one D4 pricing/observation authority; no local rate math."""
    expected_origin = "provider_reported" if response.mode == "live" else "fixture"
    if usage.origin != expected_origin or usage.pricing is None:
        raise AuditError("paired_attempt_integrity", "usage origin/pricing observation differs", 4)
    priced = datetime.fromisoformat(usage.pricing.priced_at.replace("Z", "+00:00"))
    calculated = derive_cost(card, provider=grant.provider, resolved_model=usage.resolved_model,
                             raw_usage=usage.raw_usage, service_tier=usage.pricing.service_tier, at=priced)
    if (canonical_json(calculated) != canonical_json(usage.pricing)
            or (usage.input_tokens, usage.output_tokens) != (calculated.input_tokens, calculated.output_tokens)):
        raise AuditError("paired_attempt_integrity", "usage/pricing does not reproduce through the sole authority", 4)
    if expected_origin == "fixture":
        if usage.cost_basis not in {"fixture", "unknown"} or usage.settlement_observation is not None:
            raise AuditError("paired_attempt_integrity", "fixture data acquired real settlement provenance", 4)
        return
    context = usage.settlement_context
    if context is not None and (
            context.authorization_id != grant.authorization_id or context.request_digest != response.request_digest
            or context.payload_digest != response.payload_digest or context.reservation_id != reservation.reservation_id
            or context.attempt_id != attempt.attempt_id or context.provider != grant.provider
            or context.requested_model != request.model or context.resolved_model != usage.resolved_model
            or context.response_id != usage.response_id or context.origin != usage.origin
            or canonical_json(context.raw_usage) != canonical_json(usage.raw_usage)
            or canonical_json(context.pricing) != canonical_json(usage.pricing)):
        raise AuditError("paired_attempt_integrity", "settlement context belongs to another physical response", 4)
    if usage.cost_usd is None:
        if usage.cost_basis != "unknown" or usage.settlement_observation is not None:
            raise AuditError("paired_attempt_integrity", "unknown settlement was promoted to a known amount", 4)
        return
    if context is None or usage.settlement_observation is None:
        raise AuditError("paired_attempt_integrity", "known live settlement lacks a bound observation", 4)
    observed = validate_settlement_observation(context, usage.settlement_observation, rate_card=card)
    if (observed.cost_usd != usage.cost_usd or observed.basis != usage.cost_basis
            or observed.receipt_reference != usage.cost_receipt or usage.cost_error is not None
            or usage.cost_basis == "provider_bill" and usage.reported_bill_usd != usage.cost_usd):
        raise AuditError("paired_attempt_integrity", "derived cost/bill/receipt attribution differs", 4)


def _json(raw: bytes):
    try:
        value = json.loads(raw)
        # Source writers are canonical. Reject duplicate keys, nonfinite values,
        # trailing payload and alternate encodings instead of parsing ambiguity.
        if raw not in {canonical_json(value), canonical_json(value) + b"\n"}:
            raise ValueError("noncanonical artifact")
        return value
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise AuditError("paired_invalid_artifact", "artifact is not bounded canonical JSON", 4) from exc


def _models(raw: bytes, model: type) -> list:
    lines = raw.splitlines()
    if len(lines) > 20000 or any(not line for line in lines):
        raise AuditError("paired_row_integrity", "blank or excessive artifact rows", 4)
    return [model.model_validate(_json(line)) for line in lines]


def _check_rows(rows: list[PredictionRow], packet: EvaluationPacket, snapshot, source: Path, arm: str) -> None:
    seen: set[str] = set()
    successes = sum(row.status == "prediction" for row in rows)
    for position, row in enumerate(rows):
        if row.prediction_id in seen or row.family_id != packet.snapshot_id:
            raise AuditError("paired_row_integrity", "duplicate row or wrong snapshot/family", 4)
        seen.add(row.prediction_id)
        if row.status != "prediction":
            if row.finding is not None or row.accused_predicate_ids or not row.error:
                raise AuditError("paired_row_integrity", "failure row cannot carry a finding/accusation", 4)
            # Failure IDs must bind this arm, snapshot, reason and an explicit
            # bounded ordinal (zero final, physical index+1, inventory, fact gap).
            if not any(row.prediction_id == failure_row(packet.snapshot_id, arm, row.status, row.error, i).prediction_id
                       for i in {0, 1, 2, 1000, max(0, position - successes)}):
                raise AuditError("paired_row_integrity", "failure identity differs", 4)
            continue
        if row.finding is None or row.error is not None:
            raise AuditError("paired_row_integrity", "prediction needs one finding and no pipeline error", 4)
        claim = row.finding.claim
        span = claim.span
        if (span.path, span.file_sha256, span.snapshot_id) != (packet.readme_path, packet.readme_sha256, packet.snapshot_id):
            raise AuditError("paired_identity_mismatch", "claim is outside packet README", 4)
        validate_span(snapshot, source, span)
        parent = stable_id("sentence", packet.snapshot_id, span.path, span.start_byte, span.end_byte)
        if (claim.parent_id != parent or claim.claim_id != stable_id("claim", parent, claim.atom_ordinal)
                or row.prediction_id != claim.claim_id or row.accused_predicate_ids != row.finding.accused_predicate_ids):
            raise AuditError("paired_row_integrity", "claim/row identities differ", 4)
        ids: set[str] = set()
        for predicate in claim.predicates:
            fields = predicate.model_dump(mode="json", exclude={"predicate_id"})
            if predicate.predicate_id in ids or predicate.predicate_id != stable_id("predicate", claim.claim_id, fields):
                raise AuditError("paired_row_integrity", "predicate identity differs", 4)
            ids.add(predicate.predicate_id)


def _ledger(root: Path, arm: str, request: ProviderRequest, response: ProviderResponse | LiveProviderResponse,
            artifacts: dict[str, bytes], authorization: LiveAuthorization | None = None,
            started_at: datetime | None = None, rate_card: DatedRateCard | None = None,
            budget_admission: LiveBudgetAdmission | None = None) -> None:
    live_protocol = isinstance(response, LiveProviderResponse)
    if live_protocol and authorization is None:
        raise AuditError("paired_identity_mismatch", "live protocol requires an explicit owner grant", 4)
    prefix = f"{arm}-budget/"
    events_raw = artifacts.get(prefix + "attempts.jsonl")
    if events_raw is None:
        raise AuditError("paired_attempt_integrity", "typed provider response has no durable events", 4)
    events = [_json(line) for line in events_raw.splitlines()]
    if len(events) > 8:
        raise AuditError("paired_attempt_integrity", "event count exceeds the explicit two-attempt envelope", 4)
    reserved: dict[str, tuple[Attempt, Reservation]] = {}
    closed: list[Attempt] = []
    reported: list[dict] = []
    response_markers = 0
    for event in events:
        if type(event) is not dict:
            raise AuditError("paired_attempt_integrity", "invalid event", 4)
        phase = event.get("phase")
        reserved_keys = {"phase", "attempt", "reservation"} | ({"authorization_id", "payload_digest", "request_digest",
                         "rate_card", "budget_admission", "pricing_liability"} if live_protocol else set())
        if phase == "reserved" and set(event) == reserved_keys:
            attempt = Attempt.model_validate(event["attempt"])
            reservation = Reservation.model_validate(event["reservation"])
            if (len(reserved) != len(closed) or attempt.attempt_id in reserved or attempt.status != "reserved"
                    or attempt.attempt_id != stable_id("attempt", response.request_digest, reservation.reservation_id)):
                raise AuditError("paired_attempt_integrity", "duplicate or wrong reservation identity", 4)
            if (reservation.input_tokens, reservation.output_tokens, reservation.seconds, reservation.cost_usd) != (
                    request.caps.request_input_tokens, request.caps.request_output_tokens,
                    request.caps.request_seconds, request.caps.request_cost_usd):
                raise AuditError("paired_attempt_integrity", "physical liability differs from caps", 4)
            reserved[attempt.attempt_id] = (attempt, reservation)
            if live_protocol and (event["authorization_id"] != response.authorization_id
                                  or event["payload_digest"] != response.payload_digest
                                  or event["request_digest"] != response.request_digest
                                  or canonical_json(event["rate_card"]) != canonical_json(rate_card)):
                raise AuditError("paired_attempt_integrity", "reservation lost live authorization/payload binding", 4)
            if live_protocol:
                if response.mode == "live":
                    if canonical_json(event["budget_admission"]) != canonical_json(budget_admission):
                        raise AuditError("paired_attempt_integrity", "reservation budget admission differs", 4)
                    liability = CostResult.model_validate(event["pricing_liability"])
                    recomputed = worst_case_cost(rate_card, provider=authorization.provider, model=request.model,
                                                  input_tokens=request.caps.request_input_tokens,
                                                  output_tokens=request.caps.request_output_tokens,
                                                  at=datetime.fromisoformat(liability.priced_at.replace("Z", "+00:00")))
                    if canonical_json(liability) != canonical_json(recomputed) or liability.amount_usd > request.caps.request_cost_usd:
                        raise AuditError("paired_attempt_integrity", "request liability does not replay through the sole rate authority", 4)
                elif event["pricing_liability"] is not None:
                    raise AuditError("paired_attempt_integrity", "fixture reservation invented actual liability pricing", 4)
                expiry = datetime.fromisoformat(authorization.expires_at.replace("Z", "+00:00"))
                reserved_at = datetime.fromtimestamp(reservation.reserved_at, timezone.utc)
                if started_at is None or not started_at <= reserved_at < expiry:
                    raise AuditError("paired_attempt_integrity", "physical attempt fell outside recorded owner authorization", 4)
        elif phase == "closed" and set(event) in (
                ({"phase", "attempt", "usage"},) if live_protocol else
                ({"phase", "attempt"}, {"phase", "attempt", "simulated_usage"})):
            attempt = Attempt.model_validate(event["attempt"])
            original = reserved.get(attempt.attempt_id)
            if original is None or any(a.attempt_id == attempt.attempt_id for a in closed):
                raise AuditError("paired_attempt_integrity", "unreserved/duplicate closed attempt", 4)
            mutable = {"status", "error"} | ({"input_tokens", "output_tokens", "cost_usd", "elapsed_seconds"} if live_protocol else set())
            if original[0].model_dump(exclude=mutable) != attempt.model_dump(exclude=mutable):
                raise AuditError("paired_attempt_integrity", "attempt changed identity/observations", 4)
            closed.append(attempt)
            observation = event.get("usage" if live_protocol else "simulated_usage")
            if observation is not None:
                reported.append(observation)
            if live_protocol:
                usage = LiveUsage.model_validate(observation) if observation is not None else None
                if usage is not None:
                    _validate_usage(usage, request, authorization, response, attempt, original[1], rate_card)
                if response.mode == "live":
                    values = (usage.input_tokens, usage.output_tokens, usage.cost_usd, usage.elapsed_seconds) if usage else (None,) * 4
                    if (attempt.input_tokens, attempt.output_tokens, attempt.cost_usd, attempt.elapsed_seconds) != values:
                        raise AuditError("paired_attempt_integrity", "live Attempt differs from nullable reported usage", 4)
                elif any(v is not None for v in (attempt.input_tokens, attempt.output_tokens, attempt.elapsed_seconds)) or attempt.cost_usd != 0.0:
                    raise AuditError("paired_attempt_integrity", "fixture observations were promoted to actual live usage", 4)
                if usage and (usage.origin != ("provider_reported" if response.mode == "live" else "fixture")
                              or usage.cost_usd is not None and not usage.cost_receipt):
                    raise AuditError("paired_attempt_integrity", "usage origin/cost receipt differs", 4)
        elif not live_protocol and phase in {"held", "refused"} and set(event) == {"phase", "response"}:
            recorded = ProviderResponse.model_validate(event["response"])
            if recorded.request_digest != response.request_digest:
                raise AuditError("paired_attempt_integrity", "held/refused response identity differs", 4)
        elif live_protocol and phase == "live_source_response" and set(event) == {"phase", "response"}:
            if LiveProviderResponse.model_validate(event["response"]) != response:
                raise AuditError("paired_attempt_integrity", "terminal live response record differs", 4)
            response_markers += 1
        else:
            raise AuditError("paired_attempt_integrity", "unknown/extra event fields", 4)
    observations = response.usage if live_protocol else response.simulated_usage
    if (closed != response.attempts or len(reserved) != len(closed)
            or reported != [u.model_dump(mode="json") for u in observations]
            or len(closed) > request.caps.max_retries + 1):
        raise AuditError("paired_attempt_integrity", "hidden/missing/extra attempts or usage", 4)
    if live_protocol and response_markers != 1:
        raise AuditError("paired_attempt_integrity", "one durable terminal live response is mandatory", 4)
    if not closed:
        return
    request_raw, budget_raw = artifacts.get(prefix + "requests.json"), artifacts.get(prefix + "budget.json")
    if request_raw is None or budget_raw is None:
        raise AuditError("paired_attempt_integrity", "physical attempts need budget/request closure", 4)
    journal, state = _json(request_raw), BudgetState.model_validate(_json(budget_raw))
    maximum = 1 if request.arm == "single_pass" else request.caps.max_logical_requests
    treatment = f"{request.arm}:{response.mode}:{authorization.provider}:{request.model}" if live_protocol and authorization else f"{request.arm}:{response.mode}:{request.model}"
    identity = sha256(canonical_json(dict(packet=request.packet.packet_digest, caps=request.caps,
                                         treatment=treatment, maximum=maximum)))
    if journal != {"identity": identity, "requests": [response.request_digest]}:
        raise AuditError("paired_attempt_integrity", "logical request journal differs", 4)
    remaining = [request.caps.total_input_tokens, request.caps.total_output_tokens,
                 request.caps.total_cost_usd, request.caps.total_seconds]
    unknown = False
    for index, usage in enumerate(observations):
        values = [usage.input_tokens, usage.output_tokens, usage.cost_usd, usage.elapsed_seconds]
        if any(value is None for value in values) or any(value > liability for value, liability in zip(values, (
                request.caps.request_input_tokens, request.caps.request_output_tokens,
                request.caps.request_cost_usd, request.caps.request_seconds)) if value is not None):
            unknown = True
            if index != len(closed) - 1:
                raise AuditError("paired_attempt_integrity", "an attempt followed unknown settlement", 4)
            break
        remaining = [left - used for left, used in zip(remaining, values)]
    unknown |= len(observations) < len(closed)
    actual = [state.remaining_input_tokens, state.remaining_output_tokens, state.remaining_cost_usd, state.remaining_seconds]
    if any(abs(left - right) > 1e-9 for left, right in zip(actual, remaining)):
        raise AuditError("paired_attempt_integrity", "remaining simulated liability differs", 4)
    if state.unknown_settlement != unknown or (state.pending is not None) != unknown:
        raise AuditError("paired_attempt_integrity", "unknown/pending settlement was hidden", 4)
    if unknown and state.pending != reserved[closed[-1].attempt_id][1]:
        raise AuditError("paired_attempt_integrity", "pending reservation identity differs", 4)
    if unknown and response.status == "proposed":
        raise AuditError("paired_attempt_integrity", "unsettled liability cannot report success", 4)


def _experiment_controls(manifest: dict, artifacts: dict[str, bytes], packet: EvaluationPacket,
                         caps: ProviderCaps, started: datetime) -> EvaluationLock | None:
    context = manifest["experiment"]
    if context is None:
        if manifest["mode"] != "fake_or_replay_only" or manifest["state"] not in {"closed_source_only", "failed_input"}:
            raise AuditError("paired_identity_mismatch", "fixture port was relabeled as a locked live experiment", 4)
        return None
    keys = {"protocol_digest", "protocol_id", "source_manifest_digest", "execution_kind", "status",
            "required_arms", "receipt_checks", "human_adjudicated", "comparative_complete", "budget_admission"}
    if type(context) is not dict or set(context) != keys or manifest["mode"] != "locked_live_or_fixture":
        raise AuditError("paired_identity_mismatch", "experiment provenance shape differs", 4)
    if (context["execution_kind"] not in {"fixture", "live"}
            or context["status"] != "owner_enabled_unaccepted"
            or context["human_adjudicated"] is not False or context["comparative_complete"] is not False
            or context["receipt_checks"] != "owner_pinned_presence_only_external_controls_unverified"):
        raise AuditError("paired_identity_mismatch", "dormant/fixture/live or acceptance provenance was invented", 4)
    raw_lock = artifacts["protocol-copy.json"]
    if sha256(raw_lock) != context["protocol_digest"]:
        raise AuditError("paired_artifact_integrity", "original locked protocol bytes differ", 4)
    lock = EvaluationLock.model_validate_json(raw_lock)
    _check_lock(lock)
    admission = LiveBudgetAdmission.model_validate(context["budget_admission"]) if context["budget_admission"] is not None else None
    if context["execution_kind"] == "live":
        if (admission is None or admission.admission_id != budget_admission_id(admission)
                or admission.protocol_digest != context["protocol_digest"] or admission.packet_digest != packet.packet_digest
                or admission.caps_digest != sha256(canonical_json(caps))
                or datetime.fromisoformat(admission.admitted_at.replace("Z", "+00:00")) > started):
            raise AuditError("paired_identity_mismatch", "real mode lacks its content-bound durable budget admission", 4)
    if (lock.protocol_id != context["protocol_id"] or lock.source_seal_digest != packet.snapshot_manifest_digest
            or context["source_manifest_digest"] != lock.source_seal_digest
            or set(context["required_arms"]) != set(lock.arm_names) or set(manifest["arms"]) != set(lock.arm_names)
            or (caps.total_input_tokens, caps.total_output_tokens, caps.total_seconds, caps.total_cost_usd) != (
                lock.max_input_tokens, lock.max_output_tokens, lock.max_remote_seconds, lock.max_cost_usd)):
        raise AuditError("paired_identity_mismatch", "locked required arms/source/model/budget scope differs", 4)
    closing = "closed_live_unaccepted" if context["execution_kind"] == "live" else "closed_fixture_unaccepted"
    if manifest["state"] not in {closing, "failed_input"}:
        raise AuditError("paired_identity_mismatch", "execution class was relabeled", 4)
    if manifest["state"] == "failed_input":
        # Input closure fails before any producer exists: no grant/request was
        # recorded, so none can be checked. Fail closed if one is present.
        for arm in ("live_extraction", "live_single_pass"):
            info = manifest["arms"][arm]
            if (type(info) is not dict or info.get("status") != "failed_input" or not _INFO >= set(info)
                    or any(path.startswith(f"{arm}-budget/") for path in artifacts)):
                raise AuditError("paired_attempt_integrity", "failed input cannot carry provider dispatch records", 4)
        return lock
    from claim_auditor.providers import AnthropicAdapter, OpenAICompatibleAdapter

    paths = {packet.readme_path, *(entry.path for entry in packet.scope_entries),
             *(e.path for e in packet.excerpts), *(g.path for g in packet.exclusions if g.path is not None)}
    for role, arm in (("extraction", "live_extraction"), ("single_pass", "live_single_pass")):
        info = manifest["arms"][arm]
        grant = LiveAuthorization.model_validate(info["authorization"])
        request = ProviderRequest.model_validate(info["request"])
        prompt = artifacts[f"prompts/{role}.txt"].decode("utf-8", "strict")
        expires = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00"))
        if (not grant.enabled or expires.tzinfo is None or expires <= started
                or grant.snapshot_manifest_digest != lock.source_seal_digest or not paths <= set(grant.allowed_paths)
                or request.model != lock.provider_models[arm] or request.prompt_digest != sha256(prompt.encode("utf-8"))
                or grant.request_digest != sha256(canonical_json(request))):
            raise AuditError("paired_identity_mismatch", "owner grant/source/prompt/model/data scope differs", 4)
        if admission is not None and admission.authorization_ids.get(role) != grant.authorization_id:
            raise AuditError("paired_identity_mismatch", "budget admission authorizes another role", 4)
        card = DatedRateCard.model_validate(info["rate_card"]) if info["rate_card"] is not None else None
        adapter = OpenAICompatibleAdapter(rate_card=card) if grant.provider == "openai_compatible" else AnthropicAdapter(rate_card=card)
        from claim_auditor.providers.http_json import validate_endpoint

        _, _, route = validate_endpoint(grant.endpoint)
        payload = adapter.build_request(request, prompt, grant.anthropic_version)
        if (route != adapter.route or sha256(payload) != grant.payload_digest or len(payload) > grant.max_request_bytes
                or not all(value.strip() for value in (grant.authorized_by, grant.tokenizer_receipt, grant.worst_case_cost_receipt))):
            raise AuditError("paired_identity_mismatch", "exact provider payload differs from owner grant", 4)
        if grant.input_token_upper_bound > request.caps.request_input_tokens:
            raise AuditError("paired_identity_mismatch", "token liability exceeds reserved cap", 4)
    return lock


def verify_paired(run_root: Path, snapshot_root: Path, *, manifest_digest: str | None = None) -> dict:
    """Verify source-only closure without provider execution or reading any gold.

    Returns manifest/digest, packet, per-arm PredictionRow lists and Attempt
    lists. An optional external manifest digest pins origin; without it this is
    self-consistency/integrity, not proof of authorship, quality or acceptance.
    """
    try:
        return _verify(run_root, snapshot_root, manifest_digest)
    except (ValidationError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise AuditError("paired_invalid_artifact", "closed paired schema/shape is invalid", 4) from exc


def _verify(root: Path, source: Path, expected_digest: str | None) -> dict:
    raw = read_ordinary(root, "PAIRED.json", cap=_CAP)
    digest = sha256(raw)
    if expected_digest is not None and digest != expected_digest:
        raise AuditError("paired_artifact_integrity", "externally pinned manifest differs", 4)
    manifest = _json(raw)
    if type(manifest) is not dict or set(manifest) != _TOP:
        raise AuditError("paired_invalid_artifact", "manifest fields differ", 4)
    if manifest["state"] not in {"closed_source_only", "closed_fixture_unaccepted", "closed_live_unaccepted", "failed_input"} or not manifest["completed_at"]:
        raise AuditError("paired_not_closed", "paired run is unfinished", 4)
    started = datetime.fromisoformat(manifest["started_at"])
    completed = datetime.fromisoformat(manifest["completed_at"])
    if started.tzinfo is None or completed.tzinfo is None or started > completed:
        raise AuditError("paired_not_closed", "closure timestamps are invalid", 4)
    if (manifest["runner_version"] != RUNNER_VERSION or manifest["packet_fact_version"] != PACKET_FACT_VERSION
            or manifest["parser_version"] != PARSER_VERSION or manifest["code_digest"] != code_digest()
            or manifest["source_only"] is not True or manifest["comparative_complete"] is not False
            or manifest["human_adjudicated"] is not False or manifest["runtime_validation"] != "unverified"
            or manifest["mode"] not in {"fake_or_replay_only", "locked_live_or_fixture"}):
        raise AuditError("paired_identity_mismatch", "source versions/mode/acceptance identity differs", 4)
    arms = manifest["arms"]
    if type(arms) is not dict or set(arms) not in (set(PAIRED_ARMS), {*PAIRED_ARMS, "product_full_index"}):
        raise AuditError("paired_row_integrity", "all four paired roles must remain present", 4)
    allowed = {"packet.json", "packet-facts.json", "inventory.json"}
    if manifest["experiment"] is not None:
        allowed.update({"protocol-copy.json", "prompts/extraction.txt", "prompts/single_pass.txt"})
    for arm in arms:
        allowed.update(f"{arm}/{name}" for name in ("ARM.json", "predictions.jsonl", "evidence.json"))
        if arm in {"live_extraction", "live_single_pass"}:
            allowed.update(f"{arm}-budget/{name}" for name in ("budget.json", "requests.json", "attempts.jsonl"))
    hashes = manifest["artifacts"]
    required = {"packet.json", *(f"{arm}/{name}" for arm in arms for name in ("ARM.json", "predictions.jsonl", "evidence.json"))}
    if type(hashes) is not dict or not required <= set(hashes) <= allowed:
        raise AuditError("paired_artifact_integrity", "missing/extra artifact closure", 4)
    if manifest["experiment"] is not None and not {"protocol-copy.json", "prompts/extraction.txt", "prompts/single_pass.txt"} <= set(hashes):
        raise AuditError("paired_artifact_integrity", "locked mode needs exact protocol and prompt controls", 4)
    artifacts: dict[str, bytes] = {}
    remaining_bytes = 64 * 1024 * 1024
    for path in hashes:
        artifacts[path] = read_ordinary(root, path, cap=min(_CAP, remaining_bytes))
        remaining_bytes -= len(artifacts[path])
    top_names = {"PAIRED.json", *(path.split("/", 1)[0] for path in hashes)}
    if "product_full_index" in arms and (root / "full-index-run").exists():
        top_names.add("full-index-run")
    if {entry.name for entry in bounded_scandir(root, 64)} != top_names:
        raise AuditError("paired_artifact_integrity", "hidden/unlisted root artifact", 4)
    for directory in sorted({path.split("/", 1)[0] for path in hashes if "/" in path}):
        expected_files = {path.split("/", 1)[1] for path in hashes if path.startswith(directory + "/")}
        if {entry.name for entry in bounded_scandir(root / directory, 16)} != expected_files:
            raise AuditError("paired_artifact_integrity", "hidden/unlisted arm or ledger artifact", 4)
    if any(sha256(value) != hashes[path] for path, value in artifacts.items()):
        raise AuditError("paired_artifact_integrity", "artifact hash differs", 4)
    packet = EvaluationPacket.model_validate(_json(artifacts["packet.json"]))
    caps = ProviderCaps.model_validate(manifest["caps"])
    lock = _experiment_controls(manifest, artifacts, packet, caps, started)
    if lock is not None:
        source_control = _source_metadata(source)
        if (source_control.manifest_digest != lock.source_seal_digest
                or canonical_json(source_control.entries) != canonical_json(packet.scope_entries)):
            raise AuditError("paired_identity_mismatch", "source control scope differs before raw-byte access", 4)
        control_paths = {entry.path for entry in source_control.entries} | {gap.path for gap in source_control.exclusions if gap.path is not None}
        # A failed-input run has no grant; _experiment_controls proved none was recorded.
        for arm in (() if manifest["state"] == "failed_input" else ("live_extraction", "live_single_pass")):
            if not control_paths <= set(manifest["arms"][arm]["authorization"]["allowed_paths"]):
                raise AuditError("paired_identity_mismatch", "unapproved control scope before source-byte access", 4)
    snapshot = load_snapshot(source)
    validate_packet(packet, snapshot, source)
    if (manifest["input_digest"] != sha256(canonical_json(packet)) or manifest["packet_digest"] != packet.packet_digest
            or manifest["snapshot_id"] != packet.snapshot_id):
        raise AuditError("paired_identity_mismatch", "packet/input/snapshot identity differs", 4)
    facts = None
    if manifest["state"] != "failed_input":
        if "packet-facts.json" not in artifacts:
            raise AuditError("paired_artifact_integrity", "valid source closure needs fact diagnostics", 4)
        facts = build_packet_facts(packet)
        if _json(artifacts["packet-facts.json"]) != facts.diagnostics():
            raise AuditError("paired_proof_mismatch", "packet fact diagnostics do not replay", 4)
    inventory = None
    if "inventory.json" in artifacts:
        inventory = Inventory.model_validate(_json(artifacts["inventory.json"]))
        if inventory != packet_inventory(packet, snapshot, source):
            raise AuditError("paired_proof_mismatch", "candidate inventory was omitted/altered", 4)
    predictions: dict[str, list[PredictionRow]] = {}
    attempts: dict[str, list[Attempt]] = {}
    derived_halt = None
    for arm in [*PAIRED_ARMS, *(["product_full_index"] if "product_full_index" in arms else [])]:
        info = arms[arm]
        provider = arm in {"live_extraction", "live_single_pass"}
        if type(info) is not dict or set(info) not in (_INFO, _INFO | _PROVIDER_INFO if provider else _INFO):
            raise AuditError("paired_invalid_artifact", "arm metadata fields differ", 4)
        if type(info["rows"]) is not int or type(info["failure_rows"]) is not int:
            raise AuditError("paired_invalid_artifact", "row counts must be explicit integers", 4)
        if provider and manifest["state"] != "failed_input" and not _PROVIDER_INFO <= set(info):
            raise AuditError("paired_attempt_integrity", "provider arm lost its request/response record", 4)
        if arm == "packet_candidate" and info["status"] == "complete_source" and inventory is None:
            raise AuditError("paired_artifact_integrity", "complete candidate lost its inventory", 4)
        if info["status"] not in {"complete_source", "incomplete", "failed_input", "proposed",
                                  "abstention_screened", "invalid_output", "execution_failure"}:
            raise AuditError("paired_not_closed", "arm has not reached a recorded outcome", 4)
        if _json(artifacts[f"{arm}/ARM.json"]) != info:
            raise AuditError("paired_artifact_integrity", "arm metadata copy differs", 4)
        paired = arm in PAIRED_ARMS
        if (info["input_digest"] != (manifest["input_digest"] if paired else None)
                or info["packet_digest"] != (packet.packet_digest if paired else None)
                or info["treatment"] != ("equal_packet" if paired else "full_index_utility")):
            raise AuditError("paired_identity_mismatch", "paired/full-index scope was relabeled", 4)
        rows = _models(artifacts[f"{arm}/predictions.jsonl"], PredictionRow)
        evidence = [Evidence.model_validate(item) for item in _json(artifacts[f"{arm}/evidence.json"])]
        _check_rows(rows, packet, snapshot, source, arm)
        if info["rows"] != len(rows) or info["failure_rows"] != sum(r.status != "prediction" for r in rows):
            raise AuditError("paired_row_integrity", "row denominators differ", 4)
        predictions[arm], attempts[arm] = rows, []
        successes = [row for row in rows if row.status == "prediction"]
        if not paired:
            if successes or info["status"] == "complete_source":
                full_manifest = verify_report(root / "full-index-run")
                attempts[arm] = full_manifest.attempts
                report = AuditReport.model_validate_json(read_ordinary(root / "full-index-run", "report.json", cap=_CAP))
                if [r.finding for r in successes] != report.findings or evidence != report.evidence:
                    raise AuditError("paired_proof_mismatch", "full-index results differ from separate report", 4)
                expected = [PredictionRow(prediction_id=f.claim.claim_id, family_id=packet.snapshot_id, finding=f,
                                          accused_predicate_ids=f.accused_predicate_ids, status="prediction", error=None)
                            for f in report.findings]
                expected.extend(failure_row(packet.snapshot_id, arm, _status(e.reason), e.reason, n)
                                for n, e in enumerate(report.errors))
                if rows != expected:
                    raise AuditError("paired_row_integrity", "full-index error rows were dropped", 4)
            elif not rows or evidence:
                raise AuditError("paired_row_integrity", "failed full-index treatment lost its row", 4)
            continue
        if provider and "request" in info:
            live_protocol = info["provider_protocol"] == "live_protocol"
            if info["provider_protocol"] not in {"live_protocol", "fixture_port"} or live_protocol != (lock is not None):
                raise AuditError("paired_identity_mismatch", "fixture/live protocol discriminator differs", 4)
            grant = LiveAuthorization.model_validate(info["authorization"]) if live_protocol else None
            rate_card = DatedRateCard.model_validate(info["rate_card"]) if info["rate_card"] is not None else None
            if not live_protocol and rate_card is not None:
                raise AuditError("paired_identity_mismatch", "fixture port cannot claim a real price card", 4)
            if not live_protocol and info["authorization"] is not None:
                raise AuditError("paired_identity_mismatch", "fixture port cannot borrow real authorization", 4)
            request = ProviderRequest.model_validate(info["request"]) if info["request"] is not None else None
            response_type = LiveProviderResponse if live_protocol else ProviderResponse
            response = response_type.model_validate(info["response"]) if info["response"] is not None else None
            if type(info["producer_invoked"]) is not bool or type(info["response_bound"]) is not bool:
                raise AuditError("paired_invalid_artifact", "dispatch/binding observations must be explicit booleans", 4)
            if info["producer_invoked"] and not info["response_bound"]:
                raise AuditError("paired_attempt_integrity", "unbound producer return cannot certify closed attempt evidence", 4)
            if response is not None and (not info["producer_invoked"] or not info["response_bound"]):
                raise AuditError("paired_attempt_integrity", "response invents dispatch/binding observations", 4)
            if live_protocol and derived_halt:
                blocked = failure_row(packet.snapshot_id, arm, "execution_failure", "experiment_unsettled_liability")
                if response is not None or rows != [blocked] or info["status"] != "incomplete":
                    raise AuditError("paired_attempt_integrity", "dispatch continued after experiment settlement became unknown", 4)
            if request is not None:
                role = "extraction" if arm == "live_extraction" else "single_pass"
                expected_caps = caps.model_copy(update={"max_logical_requests": 1}) if role == "single_pass" else caps
                if (request.arm != role or canonical_json(request.packet) != canonical_json(packet)
                        or request.input_digest != manifest["input_digest"] or request.caps != expected_caps):
                    raise AuditError("paired_identity_mismatch", "provider saw a different packet/caps", 4)
            if response is not None:
                if request is None or response.request_digest != sha256(canonical_json(request)):
                    raise AuditError("paired_identity_mismatch", "provider request/response binding differs", 4)
                if (response.status == "proposed" and response.error is not None
                        or response.status not in {"proposed", "incomplete"} and response.proposals
                        or not live_protocol and response.status != "proposed" and response.proposals):
                    raise AuditError("paired_attempt_integrity", "provider terminal payload contradicts its status", 4)
                simulated = [] if live_protocol else [u.model_dump(mode="json") for u in response.simulated_usage]
                usage = [u.model_dump(mode="json") for u in response.usage] if live_protocol else []
                if (info["attempts"] != [a.model_dump(mode="json") for a in response.attempts]
                        or info["simulated_usage"] != simulated or info["usage"] != usage
                        or info["execution_kind"] != response.mode):
                    raise AuditError("paired_attempt_integrity", "response attempts/usage were hidden", 4)
                if live_protocol and (response.authorization_id != grant.authorization_id
                                      or response.payload_digest != grant.payload_digest
                                      or response.mode != ("live" if manifest["experiment"]["execution_kind"] == "live" else "fake")):
                    raise AuditError("paired_identity_mismatch", "fixture observations were relabeled as live", 4)
                for attempt in response.attempts:
                    expected_provider = f"{response.mode}:{grant.provider}" if live_protocol else response.mode
                    expected_mode = "live" if live_protocol and response.mode == "live" else "replay"
                    if (attempt.input_digest != request.input_digest or attempt.prompt_digest != request.prompt_digest
                            or attempt.model != request.model or attempt.policy_version != request.policy_version
                            or attempt.provider != expected_provider or attempt.mode != expected_mode
                            or attempt.status not in {"proposed", "invalid_output", "execution_failure", "incomplete"}):
                        raise AuditError("paired_attempt_integrity", "attempt execution/identity was fabricated", 4)
                    if not live_protocol and (any(v is not None for v in (attempt.input_tokens, attempt.output_tokens, attempt.elapsed_seconds))
                                              or attempt.cost_usd != 0.0):
                        raise AuditError("paired_attempt_integrity", "fixture observations were promoted to live", 4)
                terminal = "invalid_output" if live_protocol and response.status == "execution_failure" else response.status
                if response.status in {"proposed", "invalid_output", "execution_failure"} and (
                        not response.attempts or response.attempts[-1].status != terminal):
                    raise AuditError("paired_attempt_integrity", "response hides the terminal physical outcome", 4)
                admission = LiveBudgetAdmission.model_validate(manifest["experiment"]["budget_admission"]) if live_protocol and manifest["experiment"]["budget_admission"] is not None else None
                _ledger(root, arm, request, response, artifacts, grant, started, rate_card, admission)
                attempts[arm] = response.attempts
                if live_protocol:
                    budget_raw = artifacts.get(f"{arm}-budget/budget.json")
                    state = BudgetState.model_validate(_json(budget_raw)) if budget_raw is not None else None
                    if settlement_unknown(response, state):
                        derived_halt = "experiment_unsettled_liability"
                if facts is None:
                    raise AuditError("paired_artifact_integrity", "provider closure lost packet fact authority", 4)
                expected, proof, arm_status = assemble_provider_rows(packet, snapshot, source, facts, response, role=request.arm)
                if rows != expected or evidence != proof or info["status"] != arm_status:
                    raise AuditError("paired_proof_mismatch", "provider/code-owned rows, status or failure denominators differ", 4)
            elif successes or info["attempts"] or info["simulated_usage"] or info["usage"] or evidence:
                raise AuditError("paired_attempt_integrity", "no response may not invent observations/findings", 4)
            elif not rows:
                raise AuditError("paired_row_integrity", "failed or held provider arm lost its denominator", 4)
            if response is None and info["execution_kind"] != "not_attempted":
                raise AuditError("paired_attempt_integrity", "no-response arm invented execution provenance", 4)
            if response is None and info["status"] == "abstention_screened" and not _packet_screened(packet):
                raise AuditError("paired_proof_mismatch", "screened outcome does not replay against original packet strings", 4)
            if response is None and any(path.startswith(f"{arm}-budget/") for path in artifacts):
                raise AuditError("paired_attempt_integrity", "ledger activity has no closed response", 4)
        elif arm == "packet_candidate" and (successes or inventory is not None):
            if inventory is None or facts is None:
                raise AuditError("paired_artifact_integrity", "candidate findings need inventory and packet facts", 4)
            expected, proof = resolve_packet_claims(packet, snapshot, source, inventory.claims, facts=facts)
            expected.extend(failure_row(packet.snapshot_id, arm, _status(e.reason), e.reason, n)
                            for n, e in enumerate(inventory.errors))
            if rows != expected or evidence != proof:
                raise AuditError("paired_proof_mismatch", "candidate findings/denominators differ", 4)
        elif arm == "packet_grep" and (successes or info["status"] == "complete_source"):
            baseline = run_packet_grep(packet, snapshot, source)
            if rows != baseline.predictions or evidence != baseline.evidence:
                raise AuditError("paired_proof_mismatch", "independent baseline differs", 4)
        elif successes or evidence:
            raise AuditError("paired_proof_mismatch", "failure-only arm has invented findings/evidence", 4)
        elif not rows and info["status"] != "complete_source":
            raise AuditError("paired_row_integrity", "failure-only arm lost its denominator", 4)
    provider_attempts = [a for arm in ("live_extraction", "live_single_pass") for a in attempts[arm]]
    summary = dict(attempt_records=len(provider_attempts), live_attempt_records=sum(a.mode == "live" for a in provider_attempts),
                   fixture_replay_attempt_records=sum(a.mode == "replay" for a in provider_attempts))
    if manifest["execution_summary"] != summary:
        raise AuditError("paired_attempt_integrity", "execution provenance summary hides attempts", 4)
    if manifest["dispatch_halt"] != derived_halt:
        raise AuditError("paired_attempt_integrity", "experiment-wide liability halt was hidden", 4)
    return dict(manifest=manifest, manifest_digest=digest, packet=packet, predictions=predictions, attempts=attempts)


def score_paired(run_root: Path, snapshot_root: Path, gold_path: Path, out: Path,
                 *, manifest_digest: str | None = None) -> dict[str, EvaluationResult]:
    """Read labels only after verified inference closure; produce descriptive rows.

    All gold must belong to this one snapshot and one unambiguous curator family.
    Fake/replay results never certify live/human/comparative acceptance.
    """
    verified = verify_paired(run_root, snapshot_root, manifest_digest=manifest_digest)
    # Hash the exact bytes scored, without a second read that could bind a
    # replacement label file. This material is opened only after closure.
    gold_raw = read_ordinary(gold_path.parent, gold_path.name, cap=10 * 1024 * 1024)
    context = verified["manifest"]["experiment"]
    if context is not None:
        protocol_raw = read_ordinary(run_root, "protocol-copy.json", cap=128 * 1024)
        if sha256(protocol_raw) != context["protocol_digest"]:
            raise AuditError("paired_artifact_integrity", "protocol changed after verification", 4)
        lock = EvaluationLock.model_validate_json(protocol_raw)
        if sha256(gold_raw) != lock.gold_seal_digest:
            raise AuditError("paired_gold_seal_mismatch", "single-packet locked scoring requires the exact admitted gold JSONL bytes")
    gold_lines = gold_raw.splitlines()
    if len(gold_lines) > 5000 or any(not line.strip() for line in gold_lines):
        raise AuditError("paired_gold_scope_mismatch", "gold must be bounded nonblank JSONL")
    try:
        gold = [GoldAtom.model_validate_json(line) for line in gold_lines]
    except ValidationError as exc:
        raise AuditError("paired_gold_scope_mismatch", "gold failed closed-schema validation") from exc
    if not gold or any(row.claim.span.snapshot_id != verified["packet"].snapshot_id for row in gold):
        raise AuditError("paired_gold_scope_mismatch", "score only this closed snapshot's complete gold family")
    families = {row.family_id for row in gold}
    if len(families) != 1:
        raise AuditError("ambiguous_family", "snapshot must map to exactly one curator family")
    family = next(iter(families))
    source = load_snapshot(snapshot_root)
    if source.manifest_digest != verified["packet"].snapshot_manifest_digest:
        raise AuditError("paired_identity_mismatch", "source changed before label binding", 4)
    for atom in gold:
        if (atom.claim.span.path, atom.claim.span.file_sha256) != (
                verified["packet"].readme_path, verified["packet"].readme_sha256):
            raise AuditError("paired_gold_scope_mismatch", "gold atom is outside this packet README")
        validate_span(source, snapshot_root, atom.claim.span)
    if out.exists() or out.is_symlink():
        raise AuditError("output_exists", "paired score output must be fresh")
    if out.resolve() == run_root.resolve() or run_root.resolve() in out.resolve().parents:
        raise AuditError("output_inside_paired_run", "scoring must preserve the closed inference directory")
    if out.resolve() == snapshot_root.resolve() or snapshot_root.resolve() in out.resolve().parents:
        raise AuditError("output_inside_snapshot", "scoring must preserve source snapshot bytes")
    # Remap pipeline failures as well as findings. They remain in denominators.
    results = {}
    for arm, rows in verified["predictions"].items():
        remapped = [row.model_copy(update={"family_id": family}) for row in rows]
        result = score_rows(remapped, gold, include_intervals=False)
        from claim_auditor.evaluation.measurements import summarize_attempts

        results[arm] = result.model_copy(update={
            "comparative_complete": False, "human_adjudicated": False,
            "attempt_summary": summarize_attempts(verified["attempts"][arm]) if verified["attempts"][arm] else None,
            "limitations": [*result.limitations, "Single-packet descriptive scoring has no family interval or independent custody/human/comparative acceptance. Attempt cost_usd is the admitted settlement amount, not necessarily a provider bill; inspect ARM usage cost_basis, reported_bill_usd and pricing."],
        })
    out.mkdir(parents=True, exist_ok=False)
    for arm, result in results.items():
        arm_out = out / arm
        arm_out.mkdir()
        _write(arm_out / "RESULTS.json", result)
        _write(arm_out / "items.json", result.items)
    _write(out / "SCORED.json", dict(source_manifest_digest=verified["manifest_digest"],
                                    gold_sha256=sha256(gold_raw), gold_atoms=len(gold), family_id=family,
                                    arms=list(results), comparative_complete=False, human_adjudicated=False,
                                    status="descriptive_live_unaccepted" if context and context["execution_kind"] == "live" else "descriptive_fixture_unaccepted"))
    return results
