"""Optional trusted observation source. No callback or pricing runs at import."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Callable

from ..accounting.pricing import derive_cost, money_bound, validate_rate_card
from ..contracts import (
    AuditError, DatedRateCard, SettlementContext, SettlementObservation,
    canonical_json, sha256, stable_id,
)

SettlementObserver = Callable[[SettlementContext], SettlementObservation | None]


def validate_settlement_observation(context: SettlementContext, observation: SettlementObservation,
                                    *, rate_card: DatedRateCard | None,
                                    allow_bill_reconciliation: bool = False) -> SettlementObservation:
    """Check exact frozen local bindings, not authenticity of an external bill."""
    context = SettlementContext.model_validate_json(canonical_json(context))
    observation = SettlementObservation.model_validate_json(canonical_json(observation))
    if context.origin != "provider_reported" or not context.response_id or context.resolved_model != context.requested_model:
        raise AuditError("settlement_identity_incomplete", "Actual matching provider/model/response identities required.", 3)
    if (observation.context_digest != sha256(canonical_json(context))
            or observation.provider != context.provider or observation.resolved_model != context.resolved_model
            or observation.response_id != context.response_id
            or observation.usage_digest != sha256(canonical_json(context.raw_usage))):
        raise AuditError("settlement_binding_mismatch", "Settlement must bind exact authorization/request/payload/response/usage context.", 4)
    at = datetime.fromisoformat(context.requested_at.replace("Z", "+00:00"))
    price = derive_cost(rate_card, provider=context.provider, resolved_model=context.resolved_model,
                        raw_usage=context.raw_usage, service_tier=context.service_tier, at=at)
    if canonical_json(price) != canonical_json(context.pricing):
        raise AuditError("settlement_pricing_unknown", "Missing/stale/unadmitted/ambiguous pricing cannot clear liability.", 3)
    if price.status != "derived":
        # Only a separately receipted owner reconciliation can resolve an actual
        # final bill when category pricing was ambiguous. Never automatic/hook
        # fallback, and never a missing/stale/unadmitted rate/model or token total.
        validate_rate_card(rate_card, provider=context.provider, model=context.resolved_model, at=at)
        if (not allow_bill_reconciliation or observation.basis != "provider_bill"
                or price.input_tokens is None or price.output_tokens is None):
            raise AuditError("settlement_pricing_unknown", "Unknown categories remain blocked pending actual owner bill/usage receipts.", 3)
    if observation.rate_card_digest != price.rate_card_digest:
        raise AuditError("settlement_rate_card_mismatch", "Settlement uses a different admitted rate card.", 4)
    _, cost = money_bound(Decimal(observation.amount_decimal))
    if observation.cost_usd != cost:
        raise AuditError("settlement_amount_mismatch", "Dollar field must match the conservative decimal amount.", 4)
    if observation.basis == "rate_card_derived":
        if price.amount_decimal is None or Decimal(observation.amount_decimal) != Decimal(price.amount_decimal):
            raise AuditError("settlement_amount_mismatch", "Derived cost must equal the sole rate-card calculation.", 4)
    observed = datetime.fromisoformat(observation.observed_at.replace("Z", "+00:00"))
    if observed > datetime.now(timezone.utc) or observed < at:
        raise AuditError("invalid_settlement_date", "Observation cannot precede its request or be future dated.", 4)
    return observation


class DatedRateSettlementObserver:
    """Future explicitly injected derived-cost observer; never claims a bill.

    No values or receipts exist until a later authorized request supplies actual
    usage and a real owner-admitted card. Fixture/unadmitted/unknown returns None.
    """

    def __init__(self, *, observer_id: str, rate_card: DatedRateCard) -> None:
        if not observer_id.strip():
            raise AuditError("settlement_observer_identity", "Actual owner observer identity required.")
        self.observer_id = observer_id
        self.rate_card = rate_card

    def __call__(self, context: SettlementContext) -> SettlementObservation | None:
        if context.origin != "provider_reported" or not context.response_id or context.resolved_model != context.requested_model:
            return None
        price = derive_cost(self.rate_card, provider=context.provider, resolved_model=context.resolved_model,
                            raw_usage=context.raw_usage, service_tier=context.service_tier,
                            at=datetime.fromisoformat(context.requested_at.replace("Z", "+00:00")))
        if price.status != "derived":
            return None
        digest = sha256(canonical_json(context))
        result = SettlementObservation(
            context_digest=digest, provider=context.provider, resolved_model=context.resolved_model,
            response_id=context.response_id, rate_card_digest=price.rate_card_digest,
            usage_digest=price.usage_digest, basis="rate_card_derived", amount_decimal=price.amount_decimal,
            cost_usd=price.amount_usd, receipt_kind="derived_calculation",
            receipt_reference=stable_id("derived-calculation", digest, price),
            observer_id=self.observer_id, observed_at=datetime.now(timezone.utc).isoformat(),
        )
        return validate_settlement_observation(context, result, rate_card=self.rate_card)
