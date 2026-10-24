"""Future offline pricing/binding probes. Source only until normal activation."""

from datetime import datetime, timezone
from decimal import Decimal
import unittest

from claim_auditor.accounting.pricing import derive_cost, worst_case_cost
from claim_auditor.contracts import AuditError
from claim_auditor.providers.settlement import (
    DatedRateSettlementObserver, validate_settlement_observation,
)

from .pricing_support import synthetic_card, synthetic_context, synthetic_usage


class PricingSettlementTests(unittest.TestCase):
    def test_inclusive_cache_and_reasoning_are_not_double_charged(self):
        """what_bug_this_catches: charging cached input and reasoning again above inclusive totals."""
        card = synthetic_card()
        price = derive_cost(card, provider="openai_compatible", resolved_model="fixture-model/1",
                            raw_usage=synthetic_usage(), service_tier="default",
                            at=datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual((price.status, price.purpose), ("derived", "usage"))
        self.assertEqual((price.input_tokens, price.output_tokens), (10, 3))
        self.assertEqual(price.categories, {"input_uncached": 6, "input_cached": 4, "output": 3})
        # Hand control: (6*2 + 4*1 + 3*4) / 1,000,000. No parallel calculator.
        self.assertEqual(price.amount_decimal, "0.000028000000")

    def test_split_cache_ttls_and_thinking_preserve_one_output_total(self):
        """what_bug_this_catches: treating Anthropic cache creation or thinking as extra inclusive input/output."""
        card = synthetic_card(provider="anthropic")
        raw = dict(input_tokens=5, cache_read_input_tokens=3, cache_creation_input_tokens=3,
                   cache_creation={"ephemeral_5m_input_tokens": 2, "ephemeral_1h_input_tokens": 1},
                   output_tokens=4, output_tokens_details={"thinking_tokens": 3}, inference_geo="global")
        at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        price = derive_cost(card, provider="anthropic", resolved_model="fixture-model/1",
                            raw_usage=raw, service_tier="standard", at=at)
        self.assertEqual((price.status, price.input_tokens, price.output_tokens), ("derived", 11, 4))
        self.assertEqual(price.amount_decimal, "0.000040000000")  # 10+3+6+5+16 microdollars
        raw["cache_creation"]["ephemeral_1h_input_tokens"] = 2
        ambiguous = derive_cost(card, provider="anthropic", resolved_model="fixture-model/1",
                                raw_usage=raw, service_tier="standard", at=at)
        self.assertEqual((ambiguous.status, ambiguous.error), ("unknown", "unknown_cache_ttl_categories"))
        self.assertIsNone(ambiguous.amount_usd)

    def test_stale_unadmitted_and_wrong_model_cards_cannot_price_or_reserve(self):
        """what_bug_this_catches: fallback prices or zero liability when exact dated admission is absent."""
        at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        cases = [
            (synthetic_card(valid_until=at.isoformat()), "rate_card_stale"),
            (synthetic_card(admitted=False, admitted_by=None, admitted_at=None, admission_receipt=None),
             "rate_card_unadmitted"),
            (synthetic_card(resolved_model="foreign-model"), "rate_card_model_mismatch"),
        ]
        for card, reason in cases:
            with self.subTest(reason=reason):
                price = derive_cost(card, provider="openai_compatible", resolved_model="fixture-model/1",
                                    raw_usage=synthetic_usage(), service_tier="default", at=at)
                self.assertEqual((price.status, price.error), ("unknown", reason))
                self.assertIsNone(price.amount_decimal)
                self.assertIsNone(price.amount_usd)
                with self.assertRaises(AuditError) as caught:
                    worst_case_cost(card, provider="openai_compatible", model="fixture-model/1",
                                    input_tokens=1, output_tokens=1, at=at)
                self.assertEqual(caught.exception.reason, reason)

    def test_worst_case_chooses_expensive_category_and_rounds_outward(self):
        """what_bug_this_catches: optimistic cache mix or float conversion under-reserving decimal liability."""
        card = synthetic_card(provider="anthropic", rates={
            "input_uncached": "0.00000001", "input_cached_read": "0",
            "input_cache_write_5m": "0.00000002", "input_cache_write_1h": "0.0000001", "output": "0",
        })
        bound = worst_case_cost(card, provider="anthropic", model="fixture-model/1",
                                input_tokens=1, output_tokens=0,
                                at=datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual((bound.status, bound.purpose), ("derived", "liability"))
        self.assertEqual(bound.categories["input_cache_write_1h"], 1)
        self.assertEqual(sum(bound.categories.values()), 1)
        self.assertEqual(bound.amount_decimal, "0.000000000001")
        self.assertGreaterEqual(Decimal.from_float(bound.amount_usd), Decimal(bound.amount_decimal))

    def test_derived_observer_is_bound_calculation_never_a_provider_bill(self):
        """what_bug_this_catches: a local derived calculation being upgraded to billed or fixture spend proof."""
        card = synthetic_card()
        context = synthetic_context(card)
        observer = DatedRateSettlementObserver(observer_id="SYNTHETIC-OBSERVER", rate_card=card)
        observation = observer(context)
        self.assertIsNotNone(observation)
        self.assertEqual((observation.basis, observation.receipt_kind),
                         ("rate_card_derived", "derived_calculation"))
        self.assertEqual(validate_settlement_observation(context, observation, rate_card=card), observation)
        self.assertIsNone(observer(context.model_copy(update={"origin": "fixture"})))
        self.assertIsNone(observer(context.model_copy(update={"resolved_model": "foreign-model"})))

    def test_observation_cannot_move_to_other_authorization_response_or_usage(self):
        """what_bug_this_catches: a valid settlement receipt clearing another frozen request's liability."""
        card = synthetic_card()
        context = synthetic_context(card)
        observation = DatedRateSettlementObserver(observer_id="SYNTHETIC-OBSERVER", rate_card=card)(context)
        for changes in ({"authorization_id": "OTHER-SYNTHETIC-AUTH"},
                        {"response_digest": "d" * 64}, {"raw_usage": {"prompt_tokens": 99}}):
            with self.subTest(changes=changes), self.assertRaises(AuditError) as caught:
                validate_settlement_observation(context.model_copy(update=changes), observation, rate_card=card)
            self.assertEqual(caught.exception.reason, "settlement_binding_mismatch")

    def test_unknown_categories_and_repriced_context_cannot_clear_liability(self):
        """what_bug_this_catches: an unbound observer amount or ambiguous category silently settling known totals."""
        card = synthetic_card()
        context = synthetic_context(card)
        observation = DatedRateSettlementObserver(observer_id="SYNTHETIC-OBSERVER", rate_card=card)(context)
        changed_card = synthetic_card(rates={"input_uncached": "3", "input_cached": "1", "output": "4"})
        with self.assertRaises(AuditError) as caught:
            validate_settlement_observation(context, observation, rate_card=changed_card)
        self.assertEqual(caught.exception.reason, "settlement_pricing_unknown")
        altered = observation.model_copy(update={"amount_decimal": "0", "cost_usd": 0.0})
        with self.assertRaises(AuditError) as caught:
            validate_settlement_observation(context, altered, rate_card=card)
        self.assertEqual(caught.exception.reason, "settlement_amount_mismatch")
        raw = synthetic_usage()
        raw["prompt_tokens_details"] = {}  # known total does not imply known cached share
        unknown = derive_cost(card, provider="openai_compatible", resolved_model="fixture-model/1",
                              raw_usage=raw, service_tier="default",
                              at=datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual((unknown.status, unknown.error), ("unknown", "unknown_cached_prompt_category"))
        self.assertIsNone(unknown.amount_usd)
