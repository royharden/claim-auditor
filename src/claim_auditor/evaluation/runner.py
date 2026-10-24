"""Future fake/replay paired assembly. Importing this module runs no experiment."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from pydantic import ValidationError

from claim_auditor.accounting import BudgetLedger
from claim_auditor.contracts import (
    AuditError, AuditReport, BudgetState, DatedRateCard, EvaluationPacket, LiveAuthorization, LiveProviderResponse, POLICY_VERSION,
    PredictionRow, ProviderCaps, ProviderRequest, ProviderResponse, ScopeGap, canonical_json, sha256,
)
from claim_auditor.evaluation.arms import (
    assemble_provider_rows, failure_row, failure_status as _status,
    packet_inventory, resolve_packet_claims, settlement_unknown, validate_packet,
)
from claim_auditor.evaluation.baseline import run_packet_grep
from claim_auditor.evaluation.packet import code_digest
from claim_auditor.evaluation.packet_facts import PACKET_FACT_VERSION, PacketFacts, build_packet_facts
from claim_auditor.index import PARSER_VERSION
from claim_auditor.screen import screen_original_strings
from claim_auditor.snapshot import load_snapshot
from claim_auditor.snapshot.safeio import read_ordinary
from claim_auditor.providers.port import FixtureTransport

RUNNER_VERSION = "paired-source/3"
PAIRED_ARMS = ("packet_candidate", "packet_grep", "live_extraction", "live_single_pass")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write(path: Path, value: object) -> None:
    with path.open("xb") as stream:
        stream.write(canonical_json(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def _publish(root: Path, value: dict) -> None:
    temp = root / f".PAIRED-{uuid.uuid4().hex}.tmp"
    _write(temp, value)
    os.replace(temp, root / "PAIRED.json")


def _packet_screened(packet: EvaluationPacket) -> bool:
    """Reuse D4's sole original-wire traversal and unchanged screening policy."""
    return bool(screen_original_strings(packet))


def run_paired(
    packet: EvaluationPacket, snapshot_root: Path, out: Path, *,
    transports: Mapping[str, FixtureTransport], caps: ProviderCaps,
    prompts: Mapping[str, str], models: Mapping[str, str],
    include_full_index: bool = False,
) -> dict:
    """Assemble only the explicit built-in fake/replay port; never enables live."""
    return _run_paired(packet, snapshot_root, out, transports=transports, caps=caps,
                       prompts=prompts, models=models, include_full_index=include_full_index)


def _run_paired(
    packet: EvaluationPacket, snapshot_root: Path, out: Path, *,
    transports: Mapping[str, object], caps: ProviderCaps,
    prompts: Mapping[str, str], models: Mapping[str, str], include_full_index: bool,
    dispatch: Callable[[ProviderRequest, BudgetLedger], LiveProviderResponse] | None = None,
    authorizations: Mapping[str, LiveAuthorization] | None = None,
    experiment: dict | None = None, controls: Mapping[str, bytes] | None = None,
    ledger_roots: Mapping[str, Path] | None = None,
    rate_cards: Mapping[str, DatedRateCard | None] | None = None,
) -> dict:
    """Shared packet/artifact engine; live entrypoint owns prior admission guards.

    Keys for transports/prompts/models are exactly ``extraction`` and
    ``single_pass``. Each arm receives an isolated ledger with equal total caps;
    retries share that arm's ledger. No labels or rule candidates enter requests.
    ``live_*`` are required experiment role names, never execution mode claims.
    The function is source for later activation; it has not been run in W2.
    """
    from claim_auditor.providers import produce

    keys = {"extraction", "single_pass"}
    if set(transports) != keys or set(prompts) != keys or set(models) != keys:
        raise AuditError("paired_arm_configuration", "exact extraction and single_pass keys are required")
    # Revalidate frozen wire objects: nested lists are mutable even on frozen models.
    packet = EvaluationPacket.model_validate_json(canonical_json(packet))
    caps = ProviderCaps.model_validate_json(canonical_json(caps))
    if any(not value.strip() for value in models.values()):
        raise AuditError("unresolved_model_identity", "both arms require explicit model labels")
    source = Path(os.path.abspath(snapshot_root))
    destination = Path(os.path.abspath(out))
    if destination.resolve() == source.resolve() or source.resolve() in destination.resolve().parents:
        raise AuditError("output_inside_snapshot", "paired output must be separate from source snapshot")
    if destination.exists() or destination.is_symlink():
        raise AuditError("output_exists", "paired output must be a fresh directory")
    destination.mkdir(parents=True, exist_ok=False)
    packet_bytes = canonical_json(packet)
    input_digest = sha256(packet_bytes)
    arm_names = [*PAIRED_ARMS, *(["product_full_index"] if include_full_index else [])]
    metadata = dict(runner_version=RUNNER_VERSION, run_id=uuid.uuid4().hex,
                    code_digest=code_digest(), parser_version=PARSER_VERSION, packet_fact_version=PACKET_FACT_VERSION,
                    snapshot_id=packet.snapshot_id, packet_digest=packet.packet_digest,
                    input_digest=input_digest, mode="locked_live_or_fixture" if dispatch else "fake_or_replay_only", state="created",
                    experiment=experiment,
                    dispatch_halt=None,
                    execution_summary={"attempt_records": 0, "live_attempt_records": 0, "fixture_replay_attempt_records": 0},
                    started_at=_now(), completed_at=None, source_only=True,
                    runtime_validation="unverified", comparative_complete=False,
                    human_adjudicated=False, caps=caps.model_dump(mode="json"),
                    arms={name: {"status": "not_run", "input_digest": input_digest if name in PAIRED_ARMS else None}
                          for name in arm_names}, artifacts={},
                    limitations=["Assembly never by itself certifies a live/human comparative benchmark.",
                                 "Packet facts use complete admitted files only; partial windows and ambiguous scopes abstain.",
                                 "No packet arm receives full-index queries, absence certificates, gold or rationale.",
                                 "Full-index utility is a separate treatment, excluded from equal-packet comparison.",
                                 "Locked/live/human corpus integration and normal-mode execution remain outstanding."])
    _publish(destination, metadata)
    used_ledgers: dict[str, Path] = {}

    def record(arm: str, rows: list[PredictionRow], evidence: list, status: str,
               *, details: dict | None = None) -> None:
        arm_root = destination / arm
        arm_root.mkdir(exist_ok=False)
        with (arm_root / "predictions.jsonl").open("xb") as stream:
            for row in rows:
                stream.write(canonical_json(row) + b"\n")
        _write(arm_root / "evidence.json", evidence)
        info = dict(status=status, rows=len(rows), failure_rows=sum(r.status != "prediction" for r in rows),
                    input_digest=input_digest if arm in PAIRED_ARMS else None,
                    packet_digest=packet.packet_digest if arm in PAIRED_ARMS else None,
                    treatment="equal_packet" if arm in PAIRED_ARMS else "full_index_utility",
                    **(details or {}))
        _write(arm_root / "ARM.json", info)
        metadata["arms"][arm] = info
        for artifact in arm_root.iterdir():
            if artifact.is_file():
                metadata["artifacts"][artifact.relative_to(destination).as_posix()] = sha256(artifact.read_bytes())
        # Ledger bytes are part of closure: response metadata cannot hide an
        # extra physical attempt or silently drop an unresolved reservation.
        ledger_root = destination / f"{arm}-budget"
        producer_root = used_ledgers.get(arm)
        if producer_root is not None and producer_root.resolve() != ledger_root.resolve():
            ledger_root.mkdir(exist_ok=False)
            for name in ("budget.json", "requests.json", "attempts.jsonl"):
                if (producer_root / name).exists():
                    with (ledger_root / name).open("xb") as stream:
                        stream.write(read_ordinary(producer_root, name, cap=16 * 1024 * 1024))
        if ledger_root.exists():
            for name in ("budget.json", "requests.json", "attempts.jsonl"):
                artifact = ledger_root / name
                if artifact.is_file():
                    metadata["artifacts"][artifact.relative_to(destination).as_posix()] = sha256(artifact.read_bytes())
        _publish(destination, metadata)

    try:
        for name, raw in (controls or {}).items():
            if name not in {"protocol-copy.json", "prompts/extraction.txt", "prompts/single_pass.txt"}:
                raise AuditError("undeclared_experiment_control", "undeclared experiment control artifact")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(raw)
            metadata["artifacts"][name] = sha256(raw)
        _write(destination / "packet.json", packet)
        metadata["artifacts"]["packet.json"] = sha256((destination / "packet.json").read_bytes())
        snapshot = load_snapshot(source)
        validate_packet(packet, snapshot, source)
    except (AuditError, ValidationError, OSError, ValueError) as exc:
        reason = exc.reason if isinstance(exc, AuditError) else "invalid_packet_input"
        for arm in arm_names:
            record(arm, [failure_row(packet.snapshot_id, arm, _status(reason), reason)], [], "failed_input")
        metadata.update(state="failed_input", completed_at=_now())
        _publish(destination, metadata)
        return metadata

    # Packet inference may reopen README/admitted spans for integrity only.
    facts_error = None
    try:
        facts = build_packet_facts(packet)
    except (AuditError, ValueError, OSError) as exc:
        facts_error = exc.reason if isinstance(exc, AuditError) else "packet_fact_parse_failure"
        facts = PacketFacts(packet.packet_digest, gaps=[ScopeGap(path=None, reason=facts_error)])
    _write(destination / "packet-facts.json", facts.diagnostics())
    metadata["artifacts"]["packet-facts.json"] = sha256((destination / "packet-facts.json").read_bytes())
    inventory = None
    try:
        inventory = packet_inventory(packet, snapshot, source)
        _write(destination / "inventory.json", inventory)
        metadata["artifacts"]["inventory.json"] = sha256((destination / "inventory.json").read_bytes())
        candidate_rows, candidate_evidence = resolve_packet_claims(packet, snapshot, source, inventory.claims,
                                                                  facts=facts)
        candidate_rows.extend(failure_row(snapshot.snapshot_id, "packet_candidate", _status(e.reason), e.reason, i)
                              for i, e in enumerate(inventory.errors))
        if facts_error:
            candidate_rows.append(failure_row(snapshot.snapshot_id, "packet_candidate", _status(facts_error), facts_error, 1000))
        record("packet_candidate", candidate_rows, candidate_evidence,
               "complete_source" if inventory.complete and not facts_error else "incomplete")
    except (AuditError, ValidationError, OSError, ValueError) as exc:
        reason = exc.reason if isinstance(exc, AuditError) else "candidate_execution_failure"
        record("packet_candidate", [failure_row(snapshot.snapshot_id, "packet_candidate", _status(reason), reason)], [], "incomplete")

    try:
        baseline = run_packet_grep(packet, snapshot, source)
        if len(baseline.predictions) > 200:
            raise AuditError("input_too_large", "baseline atom count exceeds shared packet policy")
        record("packet_grep", baseline.predictions, baseline.evidence, "complete_source")
    except (AuditError, ValidationError, OSError, ValueError) as exc:
        reason = exc.reason if isinstance(exc, AuditError) else "grep_execution_failure"
        record("packet_grep", [failure_row(snapshot.snapshot_id, "packet_grep", _status(reason), reason)], [], "incomplete")

    held = _packet_screened(packet)
    for role, arm in (("extraction", "live_extraction"), ("single_pass", "live_single_pass")):
        rows: list[PredictionRow] = []
        evidence: list = []
        response = None
        request = None
        producer_root = None
        producer_invoked = False
        response_bound = False
        try:
            # Independent pristine decoding prevents mutation by another consumer.
            arm_packet = EvaluationPacket.model_validate_json(packet_bytes)
            request = ProviderRequest(arm=role, packet=arm_packet, input_digest=input_digest,
                                      prompt_digest=prompts[role], model=models[role],
                                      policy_version=POLICY_VERSION,
                                      caps=caps.model_copy(update={"max_logical_requests": 1}) if role == "single_pass" else caps)
            if dispatch and metadata["dispatch_halt"]:
                rows.append(failure_row(snapshot.snapshot_id, arm, "execution_failure", "experiment_unsettled_liability"))
                arm_status = "incomplete"
            elif held:
                rows.append(failure_row(snapshot.snapshot_id, arm, "abstention_screened", "abstention_screened"))
                arm_status = "abstention_screened"
            else:
                producer_root = ledger_roots[role] if ledger_roots else destination / f"{arm}-budget"
                used_ledgers[arm] = producer_root
                ledger = BudgetLedger(producer_root, BudgetState(
                    remaining_input_tokens=caps.total_input_tokens, remaining_output_tokens=caps.total_output_tokens,
                    remaining_cost_usd=caps.total_cost_usd, remaining_seconds=caps.total_seconds,
                    pending=None, unknown_settlement=False))
                producer_invoked = True
                raw_response = dispatch(request, ledger) if dispatch else produce(request, transport=transports[role], ledger=ledger)
                response_type = LiveProviderResponse if dispatch else ProviderResponse
                response = response_type.model_validate_json(canonical_json(raw_response))
                if response.request_digest != sha256(canonical_json(request)) or response.comparative_complete:
                    raise AuditError("invalid_output", "provider response request identity differs")
                response_bound = True
                rows, evidence, arm_status = assemble_provider_rows(packet, snapshot, source, facts, response, role=role)
        except (AuditError, ValidationError, OSError, ValueError, TypeError) as exc:
            reason = exc.reason if isinstance(exc, AuditError) else "invalid_output"
            rows.append(failure_row(snapshot.snapshot_id, arm, _status(reason), reason))
            arm_status = "incomplete"
        finally:
            # A dispatch/response validation exception may follow a reservation
            # or a paid request. Always inspect the producer store; never let
            # that exception skip the experiment-wide unknown-liability halt.
            if dispatch and producer_invoked and producer_root is not None:
                try:
                    state = BudgetState.model_validate_json(read_ordinary(producer_root, "budget.json", cap=64 * 1024))
                except (OSError, ValueError, AuditError):
                    state = None
                unknown = not response_bound or state is None or state.pending is not None or state.unknown_settlement
                if isinstance(response, LiveProviderResponse):
                    unknown = unknown or settlement_unknown(response, state)
                if unknown:
                    metadata["dispatch_halt"] = "experiment_unsettled_liability"
        record(arm, rows, evidence, arm_status, details={
            "request": request.model_dump(mode="json") if request is not None else None,
            "response": response.model_dump(mode="json") if response is not None else None,
            "attempts": [a.model_dump(mode="json") for a in response.attempts] if response is not None else [],
            "simulated_usage": [u.model_dump(mode="json") for u in response.simulated_usage] if isinstance(response, ProviderResponse) else [],
            "usage": [u.model_dump(mode="json") for u in response.usage] if isinstance(response, LiveProviderResponse) else [],
            "provider_protocol": "live_protocol" if dispatch else "fixture_port",
            "producer_invoked": producer_invoked, "response_bound": response_bound,
            "authorization": authorizations[role].model_dump(mode="json") if authorizations else None,
            "rate_card": rate_cards[role].model_dump(mode="json") if rate_cards and rate_cards[role] is not None else None,
            "execution_kind": response.mode if response_bound and response is not None else "unknown" if producer_invoked else "not_attempted",
            "provider_observations": "per-attempt nullable LiveUsage; fixture origin stays fixture" if dispatch else "unknown; fixture usage is simulated",
        })

    if include_full_index:
        try:
            from claim_auditor.audit.service import audit_snapshot
            from claim_auditor.citations import verify_report

            full_root = destination / "full-index-run"
            audit_snapshot(source, packet.readme_path, "rules", full_root)
            verify_report(full_root)
            report = AuditReport.model_validate_json((full_root / "report.json").read_bytes())
            rows = [PredictionRow(prediction_id=f.claim.claim_id, family_id=snapshot.snapshot_id, finding=f,
                                  accused_predicate_ids=f.accused_predicate_ids, status="prediction", error=None)
                    for f in report.findings]
            rows.extend(failure_row(snapshot.snapshot_id, "product_full_index", _status(e.reason), e.reason, i)
                        for i, e in enumerate(report.errors))
            record("product_full_index", rows, report.evidence, "complete_source" if not report.errors else "incomplete")
        except (AuditError, ValidationError, OSError, ValueError) as exc:
            reason = exc.reason if isinstance(exc, AuditError) else "full_index_execution_failure"
            record("product_full_index", [failure_row(snapshot.snapshot_id, "product_full_index", _status(reason), reason)], [], "incomplete")

    attempt_rows = [attempt for info in metadata["arms"].values() for attempt in info.get("attempts", [])]
    metadata["execution_summary"] = dict(attempt_records=len(attempt_rows),
                                          live_attempt_records=sum(a["mode"] == "live" for a in attempt_rows),
                                          fixture_replay_attempt_records=sum(a["mode"] == "replay" for a in attempt_rows))
    closing = "closed_live_unaccepted" if experiment and experiment["execution_kind"] == "live" else "closed_fixture_unaccepted" if experiment else "closed_source_only"
    metadata.update(state=closing, completed_at=_now())
    _publish(destination, metadata)
    return metadata
