"""Synthetic future pricing inputs; no current rates, receipts or calculations."""

from datetime import datetime, timezone

from claim_auditor.accounting.pricing import derive_cost, rate_card_digest
from claim_auditor.contracts import DatedRateCard, SettlementContext


def synthetic_card(*, provider="openai_compatible", **changes):
    # Called only by later test bodies. These numbers and references grant no
    # operator authority and are unrelated to any provider's actual prices.
    anthropic = provider == "anthropic"
    fields = dict(
        rate_card_id="SYNTHETIC-NOT-CURRENT-RATES", provider=provider,
        resolved_model="fixture-model/1", valid_from="2020-01-01T00:00:00+00:00",
        valid_until="2050-01-01T00:00:00+00:00", currency="USD",
        units="USD_per_million_tokens", service_tier="standard",
        usage_semantics="anthropic-cache-split/1" if anthropic else "openai-chat-inclusive/1",
        rates=({"input_uncached": "2", "input_cached_read": "1",
                "input_cache_write_5m": "3", "input_cache_write_1h": "5", "output": "4"}
               if anthropic else {"input_uncached": "2", "input_cached": "1", "output": "4"}),
        source_reference="SYNTHETIC-TEST-NOT-A-PRICE-SOURCE", admitted=True,
        admitted_by="SYNTHETIC-NOT-AN-OWNER", admitted_at="2020-01-01T00:00:00+00:00",
        admission_receipt="SYNTHETIC-NOT-A-REAL-RECEIPT", card_digest="0" * 64,
    )
    fields.update(changes)
    card = DatedRateCard(**fields)
    return card.model_copy(update={"card_digest": rate_card_digest(card)})


def synthetic_usage():
    return {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13,
            "prompt_tokens_details": {"cached_tokens": 4},
            "completion_tokens_details": {"reasoning_tokens": 2}}


def synthetic_context(card):
    at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    raw = synthetic_usage()
    pricing = derive_cost(card, provider="openai_compatible", resolved_model="fixture-model/1",
                          raw_usage=raw, service_tier="default", at=at)
    # A synthetic provider-shaped context for validation only, never observed
    # billing/provider evidence. It is not sent to a provider or a real ledger.
    return SettlementContext(
        authorization_id="SYNTHETIC-AUTH", reservation_id="SYNTHETIC-RESERVATION",
        attempt_id="SYNTHETIC-ATTEMPT", request_digest="a" * 64,
        payload_digest="b" * 64, response_digest="c" * 64,
        provider="openai_compatible", requested_model="fixture-model/1",
        resolved_model="fixture-model/1", response_id="SYNTHETIC-RESPONSE",
        origin="provider_reported", raw_usage=raw, service_tier="default",
        requested_at=at.isoformat(), pricing=pricing,
    )
