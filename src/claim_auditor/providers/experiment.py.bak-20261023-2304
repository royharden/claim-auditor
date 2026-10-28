"""Future live factory source with explicit credential injection, no key lookup."""

from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Mapping

from ..contracts import AuditError, BudgetState, LiveBudgetAdmission, LiveExperimentConfig, ReservationReconciliation, canonical_json
from ..accounting import admitted_case_leaf, bind_budget_admission
from ..accounting.pricing import validate_rate_card, worst_case_cost
from .http_json import HTTPJSONTransport, validate_endpoint
from .live import AnthropicAdapter, OpenAICompatibleAdapter
from .settlement import SettlementObserver


@dataclass(frozen=True, repr=False)
class LiveOwnerContext:
    """In-memory trusted caller input; never loaded from a packet/config/ENV."""

    credential_headers: Mapping[str, Mapping[str, str]]
    activated: bool = False
    ledger_root: Path | None = None
    budget_admission: LiveBudgetAdmission | None = None
    settlement_observers: Mapping[str, SettlementObserver | None] | None = None


def reconcile_configured_budget(
    *, owner_context: LiveOwnerContext | None, config: LiveExperimentConfig, role: str,
    record: ReservationReconciliation, usage_receipt_data: bytes, pricing_receipt_data: bytes,
) -> BudgetState:
    """Future explicit owner action, without constructing any transport or dispatch.

    Only the admitted protocol/packet/role leaf is selectable. Existing expired
    dispatch authorizations do not prevent settling an already incurred liability.
    Receipt validation and the single state transition stay in BudgetLedger.
    """
    if (type(owner_context) is not LiveOwnerContext or not owner_context.activated
            or owner_context.ledger_root is None or owner_context.budget_admission is None):
        raise AuditError("live_not_authorized", "Trusted owner context required before reconciliation reads.")
    from ..accounting import BudgetLedger
    from ..snapshot.safeio import read_ordinary

    if role not in {"extraction", "single_pass"}:
        raise AuditError("invalid_reconciliation_role", "Choose one admitted producer role.")
    admission = LiveBudgetAdmission.model_validate_json(canonical_json(owner_context.budget_admission))
    config = LiveExperimentConfig.model_validate_json(canonical_json(config))
    record = ReservationReconciliation.model_validate_json(canonical_json(record))
    root = Path(os.path.abspath(owner_context.ledger_root))
    leaf = admitted_case_leaf(root, admission, protocol_digest=admission.protocol_digest,
                              packet_digest=admission.packet_digest, role=role)
    # Reconciliation may not initialize/adopt a fresh root to replace liability.
    stored = LiveBudgetAdmission.model_validate_json(read_ordinary(root, "ADMISSION.json", cap=64 * 1024))
    if canonical_json(stored) != canonical_json(admission) or record.owner_id != admission.owner_id:
        raise AuditError("reconciliation_owner_mismatch", "Existing root and record must match the injected admission.", 4)
    bind_budget_admission(root, admission, protocol_digest=admission.protocol_digest,
                          packet_digest=admission.packet_digest, caps=config.caps,
                          authorization_ids={name: grant.authorization_id for name, grant in config.authorizations.items()})
    initial = BudgetState(remaining_input_tokens=config.caps.total_input_tokens,
                          remaining_output_tokens=config.caps.total_output_tokens,
                          remaining_cost_usd=config.caps.total_cost_usd,
                          remaining_seconds=config.caps.total_seconds, pending=None, unknown_settlement=False)
    return BudgetLedger(leaf, initial).reconcile(
        record, rate_card=config.rate_cards[role], usage_receipt_data=usage_receipt_data,
        pricing_receipt_data=pricing_receipt_data, expected_admission=admission, expected_role=role,
    )


def validate_live_config(config: LiveExperimentConfig) -> LiveExperimentConfig:
    """Pure owner configuration inspection: no target bytes, clients or credentials."""
    config = LiveExperimentConfig.model_validate_json(canonical_json(config))
    for role, authorization in config.authorizations.items():
        if not authorization.enabled:
            raise AuditError("live_not_authorized", "Both future owner role authorizations must be explicitly enabled.")
        try:
            expires = datetime.fromisoformat(authorization.expires_at.replace("Z", "+00:00"))
            if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
                raise ValueError("expired")
        except ValueError as exc:
            raise AuditError("live_not_authorized", "Current aware owner expiry required for both roles.") from exc
        for endpoint in config.allowed_endpoints[role]:
            validate_endpoint(endpoint)
        route = validate_endpoint(authorization.endpoint)[2]
        expected_route = "/v1/messages" if authorization.provider == "anthropic" else "/v1/chat/completions"
        if route != expected_route:
            raise AuditError("provider_identity_mismatch", "Owner provider identity and route differ.")
        card = validate_rate_card(config.rate_cards[role], provider=authorization.provider,
                                   model=config.models[role], at=datetime.now(timezone.utc))
        liability = worst_case_cost(card, provider=authorization.provider, model=config.models[role],
                                    input_tokens=config.caps.request_input_tokens,
                                    output_tokens=config.caps.request_output_tokens, at=datetime.now(timezone.utc))
        if liability.amount_usd is None or liability.amount_usd > config.caps.request_cost_usd:
            raise AuditError("pricing_liability_exceeds_cap", "Owner reserve is below admitted dated rates.", 3)
    return config


def run_configured_live(
    protocol_path: Path, snapshot_root: Path, out: Path, *, protocol_digest: str,
    config: LiveExperimentConfig, credential_headers: Mapping[str, Mapping[str, str]] | None = None,
    owner_activation: bool = False, ledger_root: Path | None = None,
    budget_admission: LiveBudgetAdmission | None = None,
    settlement_observers: Mapping[str, SettlementObserver | None] | None = None,
) -> dict:
    """Inject owner credentials into built-in source adapters for future activation.

    Default refusal precedes target/protocol file reads and any transport factory.
    Nothing is instantiated/called during source construction. A future trusted
    operator controls credential acquisition independently; no file/env/packet
    supplies credentials, adapter class names or an arbitrary import destination.
    """
    roles = {"extraction", "single_pass"}
    if (not owner_activation or credential_headers is None
            or set(credential_headers) != roles or any(not credential_headers[role] for role in roles)):
        raise AuditError("live_not_authorized", "Future explicit owner activation and injected credentials for both roles required.")
    if ledger_root is None or budget_admission is None:
        raise AuditError("durable_budget_admission_required", "Owner-selected durable ledger root and exact budget admission required before source access.", 3)
    if settlement_observers is not None and (set(settlement_observers) != roles or any(observer is not None and not callable(observer) for observer in settlement_observers.values())):
        raise AuditError("invalid_settlement_observer", "Supply exactly both trusted role observers or None.")
    durable = Path(os.path.abspath(ledger_root))
    for protected in (Path(os.path.abspath(snapshot_root)), Path(os.path.abspath(out))):
        if durable == protected or durable in protected.parents or protected in durable.parents:
            raise AuditError("invalid_ledger_scope", "Durable owner liability must be disjoint from source and fresh output before any root write.", 4)
    config = validate_live_config(config)
    bind_budget_admission(ledger_root, budget_admission, protocol_digest=protocol_digest,
                           caps=config.caps, authorization_ids={role: grant.authorization_id for role, grant in config.authorizations.items()})
    adapters = {}
    transports = {}
    for role in sorted(roles):
        authorization = config.authorizations[role]
        adapters[role] = (AnthropicAdapter(rate_card=config.rate_cards[role]) if authorization.provider == "anthropic"
                          else OpenAICompatibleAdapter(rate_card=config.rate_cards[role]))
        transports[role] = HTTPJSONTransport(authorization=authorization, owner_activation=True,
                                              allowed_endpoints=tuple(config.allowed_endpoints[role]),
                                              credential_headers=credential_headers[role],
                                              settlement_observer=settlement_observers[role] if settlement_observers is not None else None,
                                              ledger_root=ledger_root, budget_admission=budget_admission)
    # The consumer retains original external LOCK pin/rights/custody/code checks,
    # packet construction and the single producer/accounting/artifact authority.
    from ..evaluation import run_live_experiment

    return run_live_experiment(protocol_path, snapshot_root, out, protocol_digest=protocol_digest,
                               caps=config.caps, system_prompts=config.system_prompts,
                               models=config.models, authorizations=config.authorizations,
                               transports=transports, adapters=adapters, ledger_root=ledger_root,
                               budget_admission=budget_admission, settlement_observers=settlement_observers)
