"""Dormant locked experiment orchestration. No clients, workers or keys at import."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from pydantic import ValidationError

from claim_auditor.accounting import BudgetLedger, admitted_case_leaf, bind_budget_admission
from claim_auditor.contracts import (
    AuditError, EvaluationLock, EvaluationPacket, LiveAuthorization, LiveBudgetAdmission, LiveProviderResponse,
    BudgetState, ProviderCaps, ProviderRequest, canonical_json, sha256,
)
from claim_auditor.evaluation.packet import _check_lock, _source_metadata, prepare_evaluation
from claim_auditor.evaluation.arms import failure_row, failure_status
from claim_auditor.evaluation.runner import _run_paired, _write
from claim_auditor.providers import AnthropicAdapter, OpenAICompatibleAdapter, produce_live
from claim_auditor.providers.http_json import BoundedJSONTransport, HTTPJSONTransport, validate_endpoint
from claim_auditor.providers.live import _admit
from claim_auditor.providers.settlement import SettlementObserver
from claim_auditor.snapshot.safeio import read_ordinary

_ROLES = {"extraction": "live_extraction", "single_pass": "live_single_pass"}


def _check_case_entry(ledger_roots: Mapping[str, Path]) -> None:
    """Read-only refusal; settled liability does not grant replay authority.

    A journal/state marker is conservatively a touched case, even if empty or
    reconciled. There is no artifact-preserving continuation contract here.
    Inspect both roles for unknown liability before reporting used history.
    """
    for root in ledger_roots.values():
        state_path = root / "budget.json"
        if state_path.exists() or state_path.is_symlink():
            state = BudgetState.model_validate_json(read_ordinary(root, state_path.name, cap=64 * 1024))
            if state.unknown_settlement or state.pending is not None:
                raise AuditError("unsettled_liability", "Prior experiment liability must be reconciled in the same producer ledger")
    if any((root / name).exists() or (root / name).is_symlink()
           for root in ledger_roots.values()
           for name in ("budget.json", "requests.json", "attempts.jsonl")):
        raise AuditError("case_continuation_not_supported", "Existing case history must be preserved; liability reconciliation does not authorize new inference")


def _preparation_failure(out: Path, lock: EvaluationLock, snapshot_id: str,
                         protocol_digest: str, error: AuditError) -> None:
    """Preserve locked-attempt denominators without inventing a valid packet.

    This is a failed-input receipt, not a verified paired run or scorable fake
    prediction. Corpus aggregation must retain it as a failed admitted attempt.
    """
    root = out / "failed-before-inference"
    root.mkdir(parents=True, exist_ok=False)
    artifacts = {}
    for arm in lock.arm_names:
        row = failure_row(snapshot_id, arm, failure_status(error.reason), error.reason)
        path = root / f"{arm}.jsonl"
        _write(path, row)
        artifacts[path.name] = sha256(path.read_bytes())
    _write(root / "FAILED.json", dict(status="failed_before_packet_or_dispatch", protocol_digest=protocol_digest,
                                      source_manifest_digest=lock.source_seal_digest, snapshot_id=snapshot_id,
                                      reason=error.reason, arms=lock.arm_names, artifacts=artifacts,
                                      packet_fabricated=False, provider_attempts=0,
                                      human_adjudicated=False, comparative_complete=False))


def run_live_experiment(
    protocol_path: Path, snapshot_root: Path, out: Path, *, protocol_digest: str,
    caps: ProviderCaps, system_prompts: Mapping[str, str], models: Mapping[str, str],
    authorizations: Mapping[str, LiveAuthorization] | None = None,
    transports: Mapping[str, BoundedJSONTransport] | None = None,
    adapters: Mapping[str, OpenAICompatibleAdapter | AnthropicAdapter] | None = None,
    ledger_root: Path | None = None,
    budget_admission: LiveBudgetAdmission | None = None,
    settlement_observers: Mapping[str, SettlementObserver | None] | None = None,
) -> dict:
    """Future owner-enabled required-arm assembly; performs no action by default.

    Missing/disabled authorization refuses before source/control access. Caller
    injects D4's already owner-bound HTTPJSONTransport or explicitly fixture-only
    transport and adapters; this function never constructs one or looks up keys.
    An external protocol byte pin and all locked admission/scope guards precede
    source reads. Gold/labels/rulings/custody directories are not inference inputs.
    Return keys: preparation_root, paired_root, manifest. No comparison acceptance
    or human review is granted by this operation, even if later run live.
    """
    if authorizations is None or transports is None or adapters is None:
        raise AuditError("live_not_authorized", "Explicit owner authorization, adapters and bounded transports are required")
    if any(set(mapping) != set(_ROLES) for mapping in (authorizations, transports, adapters, system_prompts, models)):
        raise AuditError("live_not_authorized", "Both required roles need explicit complete owner bindings")
    if settlement_observers is not None and set(settlement_observers) != set(_ROLES):
        raise AuditError("invalid_settlement_observer", "Explicit observer bindings require both roles")
    # Do not touch a supplied snapshot/protocol path before this default guard.
    if any(not grant.enabled for grant in authorizations.values()):
        raise AuditError("live_not_authorized", "Disabled authorization cannot access inference source")
    grants = {role: LiveAuthorization.model_validate_json(canonical_json(grant)) for role, grant in authorizations.items()}
    caps = ProviderCaps.model_validate_json(canonical_json(caps))
    kinds: set[str] = set()
    for role, grant in grants.items():
        try:
            expires = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuditError("live_not_authorized", "Owner grant has an invalid expiration") from exc
        if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
            raise AuditError("live_not_authorized", "Owner grant must be current before source access")
        if type(adapters[role]) not in {OpenAICompatibleAdapter, AnthropicAdapter}:
            raise AuditError("invalid_provider_adapter", "Use only the published D4 adapters")
        transport = transports[role]
        if settlement_observers is not None and getattr(transport, "settlement_observer", None) is not settlement_observers[role]:
            raise AuditError("invalid_settlement_observer", "Owner transport and supplied observer bindings differ")
        if transport.execution_kind == "live" and type(transport) is not HTTPJSONTransport:
            raise AuditError("invalid_transport_policy", "Real provenance requires the published owner-bound HTTP transport")
        if (transport.execution_kind not in {"fixture", "live"} or transport.hidden_retries != 0
                or transport.follows_redirects or transport.authorization_id != grant.authorization_id):
            raise AuditError("live_not_authorized", "Owner-bound no-retry/no-redirect transport required")
        validate_endpoint(grant.endpoint)
        if grant.provider != adapters[role].provider:
            raise AuditError("provider_identity_mismatch", "Declared provider and adapter differ")
        if not all(value.strip() for value in (grant.authorized_by, grant.tokenizer_receipt, grant.worst_case_cost_receipt)):
            raise AuditError("live_not_authorized", "Actual owner admission receipts must already exist")
        kinds.add(transport.execution_kind)
    if len(kinds) != 1:
        raise AuditError("mixed_experiment_provenance", "Do not mix fixture and real transports across paired roles")
    if "live" in kinds:
        if ledger_root is None or budget_admission is None:
            raise AuditError("live_not_authorized", "Real dispatch requires an explicit durable root and content-bound owner budget admission")
        budget_admission = LiveBudgetAdmission.model_validate_json(canonical_json(budget_admission))
        for transport in transports.values():
            if (getattr(transport, "ledger_root", None) is None
                    or Path(transport.ledger_root).absolute() != ledger_root.absolute()
                    or canonical_json(getattr(transport, "budget_admission", None)) != canonical_json(budget_admission)):
                raise AuditError("budget_admission_mismatch", "Owner transports must bind the same durable root and budget admission")
        if any(ledger_root.resolve() == path.resolve() or path.resolve() in ledger_root.resolve().parents for path in (out, snapshot_root)):
            raise AuditError("invalid_ledger_scope", "Durable liability store must be outside fresh outputs and preserved source")
    raw_lock = read_ordinary(protocol_path.parent, protocol_path.name, cap=128 * 1024)
    if sha256(raw_lock) != protocol_digest:
        raise AuditError("evaluation_lock_digest_mismatch", "External owner pin must match exact LOCK bytes")
    try:
        lock = EvaluationLock.model_validate_json(raw_lock)
    except ValidationError as exc:
        raise AuditError("invalid_evaluation_lock", "LOCK must satisfy the existing closed schema") from exc
    _check_lock(lock)  # unchanged rights/custody/admission/version/code checks
    if (caps.total_input_tokens, caps.total_output_tokens, caps.total_seconds, caps.total_cost_usd) != (
            lock.max_input_tokens, lock.max_output_tokens, lock.max_remote_seconds, lock.max_cost_usd):
        raise AuditError("evaluation_budget_mismatch", "Both roles must use the exact locked total ceilings")
    for role, arm in _ROLES.items():
        if models[role] != lock.provider_models[arm] or grants[role].snapshot_manifest_digest != lock.source_seal_digest:
            raise AuditError("live_admission_identity", "Locked model/source and owner authorization differ")
    # Manifest metadata is control data. load_snapshot would read every included
    # source file, so do not invoke it until all metadata/source paths are allowed.
    metadata = _source_metadata(snapshot_root)
    if metadata.manifest_digest != lock.source_seal_digest:
        raise AuditError("source_seal_mismatch", "Control manifest differs from admitted source")
    paths = {entry.path for entry in metadata.entries} | {gap.path for gap in metadata.exclusions if gap.path is not None}
    if "README.md" not in paths or any(not paths <= set(grant.allowed_paths) for grant in grants.values()):
        raise AuditError("live_data_scope_denied", "All source and scope-metadata paths must be authorized before reads")
    # Known label/control filenames are never promoted to source-only inference.
    if any(part.casefold().startswith(("gold", "labels", "rulings", "provenance", "review-prompts"))
           for path in paths for part in path.split("/")):
        raise AuditError("annotation_material_in_source", "Stage source separately from annotation/custody material")
    if out.exists() or out.is_symlink():
        raise AuditError("output_exists", "Experiment output must be fresh")
    if out.resolve() == snapshot_root.resolve() or snapshot_root.resolve() in out.resolve().parents:
        raise AuditError("output_inside_snapshot", "Experiment output must preserve source")
    # One shared raw packet builder, not a second live-specific retrieval path.
    prepared = out / "preparation"
    try:
        prepare_evaluation(protocol_path, snapshot_root, prepared)
    except AuditError as exc:
        _preparation_failure(out, lock, metadata.snapshot_id, protocol_digest, exc)
        raise
    packet = EvaluationPacket.model_validate_json(read_ordinary(prepared, "packet.json", cap=2 * 1024 * 1024))
    ledger_roots = None
    try:
        if ledger_root is not None:
            if budget_admission is None:
                raise AuditError("budget_admission_mismatch", "An explicit durable root requires its matching owner admission; fixtures may use output-local ledgers")
            ledger_roots = {
                role: admitted_case_leaf(ledger_root, budget_admission, protocol_digest=protocol_digest,
                                         packet_digest=packet.packet_digest, role=role)
                for role in _ROLES
            }
            _check_case_entry(ledger_roots)
    except AuditError as exc:
        _preparation_failure(out, lock, metadata.snapshot_id, protocol_digest, exc)
        raise
    if "live" in kinds:
        # D4 owns identity binding and durable admission; no alternate ledger,
        # price calculation, balance reset or receipt synthesis occurs here.
        try:
            bind_budget_admission(ledger_root, budget_admission, protocol_digest=protocol_digest,
                                  packet_digest=packet.packet_digest, caps=caps,
                                  authorization_ids={role: grant.authorization_id for role, grant in grants.items()})
        except AuditError as exc:
            _preparation_failure(out, lock, metadata.snapshot_id, protocol_digest, exc)
            raise
    prompt_digests = {role: sha256(text.encode("utf-8")) for role, text in system_prompts.items()}
    # Validate both exact request/payload grants without I/O before local parser
    # workers or provider dispatch. Shared D4 admission remains the authority.
    try:
        for role in _ROLES:
            request = ProviderRequest(arm=role, packet=packet, input_digest=sha256(canonical_json(packet)),
                                      prompt_digest=prompt_digests[role], model=models[role], policy_version=lock.taxonomy_version,
                                      caps=caps.model_copy(update={"max_logical_requests": 1}) if role == "single_pass" else caps)
            payload = adapters[role].build_request(request, system_prompts[role], grants[role].anthropic_version)
            _admit(request, payload, grants[role], transports[role], adapters[role])
    except AuditError as exc:
        _preparation_failure(out, lock, metadata.snapshot_id, protocol_digest, exc)
        raise

    def dispatch(request: ProviderRequest, ledger: BudgetLedger) -> LiveProviderResponse:
        role = request.arm
        return produce_live(request, system_prompt=system_prompts[role], adapter=adapters[role],
                            ledger=ledger, authorization=grants[role], transport=transports[role])

    experiment = dict(protocol_digest=protocol_digest, protocol_id=lock.protocol_id,
                      source_manifest_digest=lock.source_seal_digest, execution_kind=next(iter(kinds)),
                      status="owner_enabled_unaccepted", required_arms=sorted(lock.arm_names),
                      receipt_checks="owner_pinned_presence_only_external_controls_unverified",
                      human_adjudicated=False, comparative_complete=False,
                      budget_admission=budget_admission.model_dump(mode="json") if budget_admission is not None else None)
    controls = {"protocol-copy.json": raw_lock,
                **{f"prompts/{role}.txt": text.encode("utf-8") for role, text in system_prompts.items()}}
    paired = out / "paired"
    manifest = _run_paired(packet, snapshot_root, paired, transports=transports, caps=caps,
                           prompts=prompt_digests, models=models, include_full_index=True,
                           dispatch=dispatch, authorizations=grants, experiment=experiment, controls=controls,
                           ledger_roots=ledger_roots,
                           rate_cards={role: adapters[role].rate_card for role in _ROLES})
    return dict(preparation_root=str(prepared), paired_root=str(paired), manifest=manifest)
