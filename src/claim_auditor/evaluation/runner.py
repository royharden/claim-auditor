"""Future fake/replay paired assembly. Importing this module runs no experiment."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from pydantic import ValidationError

from claim_auditor.accounting import BudgetLedger
from claim_auditor.contracts import (
    AuditError, AuditReport, BudgetState, EvaluationPacket, POLICY_VERSION,
    PredictionRow, ProviderCaps, ProviderRequest, ProviderResponse, canonical_json, sha256,
)
from claim_auditor.evaluation.arms import (
    failure_row, packet_inventory, resolve_packet_claims, validate_packet, validate_proposal_citations,
)
from claim_auditor.evaluation.baseline import run_packet_grep
from claim_auditor.screen import screen_text
from claim_auditor.snapshot import load_snapshot
from claim_auditor.providers.port import FixtureTransport

RUNNER_VERSION = "paired-source/1"
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


def _status(reason: str) -> str:
    if reason == "abstention_screened":
        return "abstention_screened"
    if reason in {"input_too_large", "readme_too_large", "packet_anchor_limit", "atom_limit"}:
        return "input_too_large"
    if any(part in reason for part in ("citation", "integrity", "snapshot_mismatch", "unadmitted")):
        return "citation_failure"
    if reason in {"invalid_output", "invalid_replay", "unvalidated_model_atom", "invalid_proposal"}:
        return "invalid_output"
    return "execution_failure"


def run_paired(
    packet: EvaluationPacket, snapshot_root: Path, out: Path, *,
    transports: Mapping[str, FixtureTransport], caps: ProviderCaps,
    prompts: Mapping[str, str], models: Mapping[str, str],
    include_full_index: bool = False,
) -> dict:
    """Assemble source-only arms via the single D4 provider port.

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
                    snapshot_id=packet.snapshot_id, packet_digest=packet.packet_digest,
                    input_digest=input_digest, mode="fake_or_replay_only", state="created",
                    started_at=_now(), completed_at=None, source_only=True,
                    runtime_validation="unverified", comparative_complete=False,
                    human_adjudicated=False, caps=caps.model_dump(mode="json"),
                    arms={name: {"status": "not_run", "input_digest": input_digest if name in PAIRED_ARMS else None}
                          for name in arm_names}, artifacts={},
                    limitations=["Fake/replay assembly is not a measured live comparison or human benchmark.",
                                 "Packet proof currently establishes positive paths only; other static/semantic kinds may abstain.",
                                 "No packet arm receives full-index queries, absence certificates, gold or rationale.",
                                 "Full-index utility is a separate treatment, excluded from equal-packet comparison.",
                                 "Locked/live/human corpus integration and normal-mode execution remain outstanding."])
    _publish(destination, metadata)

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
        _publish(destination, metadata)

    try:
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
    inventory = None
    try:
        inventory = packet_inventory(packet, snapshot, source)
        _write(destination / "inventory.json", inventory)
        metadata["artifacts"]["inventory.json"] = sha256((destination / "inventory.json").read_bytes())
        candidate_rows, candidate_evidence = resolve_packet_claims(packet, snapshot, source, inventory.claims,
                                                                  source_inventory=inventory)
        candidate_rows.extend(failure_row(snapshot.snapshot_id, "packet_candidate", _status(e.reason), e.reason, i)
                              for i, e in enumerate(inventory.errors))
        record("packet_candidate", candidate_rows, candidate_evidence,
               "complete_source" if inventory.complete else "incomplete")
    except (AuditError, ValidationError, OSError, ValueError) as exc:
        reason = exc.reason if isinstance(exc, AuditError) else "candidate_execution_failure"
        record("packet_candidate", [failure_row(snapshot.snapshot_id, "packet_candidate", _status(reason), reason)], [], "incomplete")

    try:
        baseline = run_packet_grep(packet, snapshot, source)
        record("packet_grep", baseline.predictions, baseline.evidence, "complete_source")
    except (AuditError, ValidationError, OSError, ValueError) as exc:
        reason = exc.reason if isinstance(exc, AuditError) else "grep_execution_failure"
        record("packet_grep", [failure_row(snapshot.snapshot_id, "packet_grep", _status(reason), reason)], [], "incomplete")

    held = bool(screen_text(packet.readme_text) or any(screen_text(e.quote) for e in packet.excerpts))
    for role, arm in (("extraction", "live_extraction"), ("single_pass", "live_single_pass")):
        rows: list[PredictionRow] = []
        evidence: list = []
        response = None
        request = None
        try:
            # Independent pristine decoding prevents mutation by another consumer.
            arm_packet = EvaluationPacket.model_validate_json(packet_bytes)
            request = ProviderRequest(arm=role, packet=arm_packet, input_digest=input_digest,
                                      prompt_digest=prompts[role], model=models[role],
                                      policy_version=POLICY_VERSION,
                                      caps=caps.model_copy(update={"max_logical_requests": 1}) if role == "single_pass" else caps)
            if held:
                rows.append(failure_row(snapshot.snapshot_id, arm, "abstention_screened", "abstention_screened"))
                arm_status = "abstention_screened"
            else:
                ledger = BudgetLedger(destination / f"{arm}-budget", BudgetState(
                    remaining_input_tokens=caps.total_input_tokens, remaining_output_tokens=caps.total_output_tokens,
                    remaining_cost_usd=caps.total_cost_usd, remaining_seconds=caps.total_seconds,
                    pending=None, unknown_settlement=False))
                response = produce(request, transport=transports[role], ledger=ledger)
                response = ProviderResponse.model_validate_json(canonical_json(response))
                if response.request_digest != sha256(canonical_json(request)) or response.comparative_complete:
                    raise AuditError("invalid_output", "provider response request identity differs")
                # Retain a failed physical retry even when the final attempt succeeds.
                for number, attempt in enumerate(response.attempts):
                    if attempt.status not in {"proposed", "complete", "success"}:
                        rows.append(failure_row(snapshot.snapshot_id, arm, _status(attempt.status),
                                                attempt.error or attempt.status, number + 1))
                arm_status = response.status
                if response.status == "proposed":
                    validate_proposal_citations(packet, snapshot, source, response.proposals)
                    claims = [p.claim for p in response.proposals]
                    resolved, evidence = resolve_packet_claims(packet, snapshot, source, claims,
                                                               source_inventory=inventory,
                                                               model_proposal=f"{response.mode}:{role}:proposal_only")
                    rows.extend(resolved)
                else:
                    rows.append(failure_row(snapshot.snapshot_id, arm, _status(response.status), response.error or response.status))
        except (AuditError, ValidationError, OSError, ValueError, TypeError) as exc:
            reason = exc.reason if isinstance(exc, AuditError) else "invalid_output"
            rows.append(failure_row(snapshot.snapshot_id, arm, _status(reason), reason))
            arm_status = "incomplete"
        record(arm, rows, evidence, arm_status, details={
            "request": request.model_dump(mode="json") if request is not None else None,
            "response": response.model_dump(mode="json") if response is not None else None,
            "attempts": [a.model_dump(mode="json") for a in response.attempts] if response is not None else [],
            "simulated_usage": [u.model_dump(mode="json") for u in response.simulated_usage] if response is not None else [],
            "provider_observations": "unknown; fixture usage is simulated",
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

    metadata.update(state="closed_source_only", completed_at=_now())
    _publish(destination, metadata)
    return metadata
