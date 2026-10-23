"""One offline Decimal authority. No rates, receipts or usage are generated here."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, DecimalException, ROUND_CEILING, localcontext
import math

from ..contracts import AuditError, CostResult, DatedRateCard, canonical_json, sha256

_INPUTS = {
    "openai_compatible": {"input_uncached", "input_cached"},
    "anthropic": {"input_uncached", "input_cached_read", "input_cache_write_5m", "input_cache_write_1h"},
}
_SEMANTICS = {"openai_compatible": "openai-chat-inclusive/1", "anthropic": "anthropic-cache-split/1"}


def rate_card_digest(card: DatedRateCard) -> str:
    return sha256(canonical_json(card.model_dump(mode="json", exclude={"card_digest"})))


def validate_rate_card(card: DatedRateCard | None, *, provider: str, model: str | None, at: datetime) -> DatedRateCard:
    if card is None:
        raise AuditError("rate_card_missing", "An owner-admitted dated resolved-model card is required.", 3)
    card = DatedRateCard.model_validate_json(canonical_json(card))
    if at.tzinfo is None or not card.admitted:
        raise AuditError("rate_card_unadmitted", "Actual owner admission and aware request time required.", 3)
    if rate_card_digest(card) != card.card_digest:
        raise AuditError("rate_card_digest_mismatch", "Rate bytes/admission metadata changed.", 4)
    if provider not in _INPUTS or (card.provider, card.resolved_model) != (provider, model):
        raise AuditError("rate_card_model_mismatch", "Provider/resolved model must match exactly.", 3)
    first = datetime.fromisoformat(card.valid_from.replace("Z", "+00:00"))
    last = datetime.fromisoformat(card.valid_until.replace("Z", "+00:00"))
    assert card.admitted_at is not None
    admitted = datetime.fromisoformat(card.admitted_at.replace("Z", "+00:00"))
    if not first <= at < last or admitted > at:
        raise AuditError("rate_card_stale", "Card is stale/not yet valid/admitted for request start.", 3)
    if card.usage_semantics != _SEMANTICS[provider] or set(card.rates) != _INPUTS[provider] | {"output"}:
        raise AuditError("unsupported_rate_categories", "Exact supported inclusive/split token semantics required.", 3)
    return card


def _count(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _normalize(provider: str, raw: object) -> tuple[int | None, int | None, dict[str, int], str | None]:
    counts: dict[str, int] = {}
    if not isinstance(raw, dict):
        return None, None, counts, "invalid_usage_shape"
    if provider == "openai_compatible":
        inputs, outputs = _count(raw.get("prompt_tokens")), _count(raw.get("completion_tokens"))
        if set(raw) - {"prompt_tokens", "completion_tokens", "total_tokens", "prompt_tokens_details", "completion_tokens_details"}:
            return inputs, outputs, counts, "unsupported_usage_fields"
        if "total_tokens" in raw and (inputs is None or outputs is None or _count(raw["total_tokens"]) != inputs + outputs):
            return inputs, outputs, counts, "ambiguous_usage_total"
        details = raw.get("prompt_tokens_details")
        details = details if isinstance(details, dict) else {}
        if set(details) - {"cached_tokens", "cache_write_tokens", "audio_tokens", "image_tokens", "text_tokens"}:
            return inputs, outputs, counts, "unsupported_input_categories"
        cached = _count(details.get("cached_tokens"))
        if inputs is not None and cached is not None and cached <= inputs:
            counts.update(input_uncached=inputs - cached, input_cached=cached)
        else:
            return inputs, outputs, counts, "unknown_cached_prompt_category"
        # Completion total already includes reasoning/prediction subcategories.
        output_details = raw.get("completion_tokens_details")
        if isinstance(output_details, dict):
            if set(output_details) - {"reasoning_tokens", "audio_tokens", "accepted_prediction_tokens", "rejected_prediction_tokens", "text_tokens"}:
                return inputs, outputs, counts, "unsupported_output_categories"
            for key in ("reasoning_tokens", "accepted_prediction_tokens", "rejected_prediction_tokens"):
                if key in output_details and (_count(output_details[key]) is None or outputs is None or output_details[key] > outputs):
                    return inputs, outputs, counts, "ambiguous_output_subcategory"
        for group in (details, output_details if isinstance(output_details, dict) else {}):
            if "audio_tokens" in group and _count(group["audio_tokens"]) != 0:
                return inputs, outputs, counts, "unsupported_audio_pricing"
        if "image_tokens" in details and _count(details["image_tokens"]) != 0:
            return inputs, outputs, counts, "unsupported_image_pricing"
        if "cache_write_tokens" in details and (_count(details["cache_write_tokens"]) is None or details["cache_write_tokens"] > counts["input_uncached"]):
            return inputs, outputs, counts, "ambiguous_cache_write_category"
    elif provider == "anthropic":
        uncached = _count(raw.get("input_tokens"))
        read = _count(raw.get("cache_read_input_tokens"))
        creation = _count(raw.get("cache_creation_input_tokens"))
        outputs = _count(raw.get("output_tokens"))
        inputs = uncached + read + creation if all(value is not None for value in (uncached, read, creation)) else None
        if inputs is None:
            return inputs, outputs, counts, "unknown_anthropic_input_categories"
        assert uncached is not None and read is not None and creation is not None
        if set(raw) - {"input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens",
                       "cache_creation", "output_tokens_details", "service_tier", "inference_geo", "server_tool_use", "speed"}:
            return inputs, outputs, counts, "unsupported_usage_fields"
        if raw.get("inference_geo") != "global" or ("speed" in raw and raw["speed"] != "standard"):
            return inputs, outputs, counts, "unknown_geography_or_speed_pricing"
        counts.update(input_uncached=uncached, input_cached_read=read)
        breakdown = raw.get("cache_creation")
        if creation == 0 and breakdown is None:
            # Explicit zero total mathematically determines both TTL counts;
            # an absent/unknown positive total is never coerced to zero.
            five, hour = 0, 0
        else:
            breakdown = breakdown if isinstance(breakdown, dict) else {}
            if set(breakdown) - {"ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"}:
                return inputs, outputs, counts, "unsupported_cache_ttl_categories"
            five = _count(breakdown.get("ephemeral_5m_input_tokens"))
            hour = _count(breakdown.get("ephemeral_1h_input_tokens"))
        if five is None or hour is None or five + hour != creation:
            return inputs, outputs, counts, "unknown_cache_ttl_categories"
        counts.update(input_cache_write_5m=five, input_cache_write_1h=hour)
        thinking = raw.get("output_tokens_details")
        if isinstance(thinking, dict) and set(thinking) - {"thinking_tokens"}:
            return inputs, outputs, counts, "unsupported_output_categories"
        if isinstance(thinking, dict) and "thinking_tokens" in thinking:
            if _count(thinking["thinking_tokens"]) is None or outputs is None or thinking["thinking_tokens"] > outputs:
                return inputs, outputs, counts, "ambiguous_output_subcategory"
        tools = raw.get("server_tool_use")
        if tools is not None and (not isinstance(tools, dict) or any(_count(value) != 0 for value in tools.values())):
            return inputs, outputs, counts, "unsupported_additional_tool_charges"
    else:
        return None, None, counts, "unsupported_provider_usage"
    if outputs is None:
        return inputs, outputs, counts, "unknown_output_total"
    counts["output"] = outputs
    return inputs, outputs, counts, None


def money_bound(amount: Decimal) -> tuple[str, float]:
    """Conservative legacy-ledger representation, never an invoice assertion."""
    with localcontext() as context:
        context.prec = 64
        if not amount.is_finite() or amount < 0:
            raise AuditError("invalid_derived_cost", "Money must be finite and nonnegative.", 3)
        rounded = amount.quantize(Decimal("0.000000000001"), rounding=ROUND_CEILING)
        value = float(rounded)
        # Preserve a conservative upper bound across the legacy float ledger seam.
        if Decimal.from_float(value) < rounded:
            value = math.nextafter(value, math.inf)
        if not math.isfinite(value):
            raise AuditError("invalid_derived_cost", "Derived liability is not finite.", 3)
        return format(rounded, "f"), value


def _amount(card: DatedRateCard, categories: dict[str, int]) -> tuple[str, float]:
    with localcontext() as context:
        context.prec = 64
        amount = sum((Decimal(count) * Decimal(card.rates[name]) for name, count in categories.items()), Decimal(0)) / Decimal(1000000)
        return money_bound(amount)


def derive_cost(card: DatedRateCard | None, *, provider: str, resolved_model: str | None,
                raw_usage: object, service_tier: str | None, at: datetime) -> CostResult:
    if provider not in _INPUTS:
        raise AuditError("unsupported_provider_usage", "No implicit provider pricing semantics exist.", 3)
    inputs, outputs, categories, error = _normalize(provider, raw_usage)
    fields = dict(purpose="usage", provider=provider, resolved_model=resolved_model,
                  rate_card_id=card.rate_card_id if card else None,
                  rate_card_digest=card.card_digest if card else None,
                  usage_digest=sha256(canonical_json(raw_usage)), priced_at=at.isoformat(),
                  service_tier=service_tier, currency=card.currency if card else None,
                  input_tokens=inputs, output_tokens=outputs, categories=categories,
                  method="decimal64-ceil-usd-1e-12/1")
    try:
        card = validate_rate_card(card, provider=provider, model=resolved_model, at=at)
        expected_tier = "default" if provider == "openai_compatible" else "standard"
        if service_tier != expected_tier:
            raise AuditError("unknown_service_tier_pricing", "Resolved standard tier must match the admitted card.", 3)
        if error is not None:
            raise AuditError(error, "Usage categories are missing/ambiguous; cost remains unknown.", 3)
        amount, value = _amount(card, categories)
        return CostResult(status="derived", amount_decimal=amount, amount_usd=value, error=None, **fields)
    except (AuditError, ValueError, TypeError, DecimalException, OverflowError) as exc:
        reason = exc.reason if isinstance(exc, AuditError) else "invalid_rate_or_usage"
        return CostResult(status="unknown", amount_decimal=None, amount_usd=None, error=reason, **fields)


def worst_case_cost(card: DatedRateCard | None, *, provider: str, model: str,
                    input_tokens: int, output_tokens: int, at: datetime) -> CostResult:
    card = validate_rate_card(card, provider=provider, model=model, at=at)
    if type(input_tokens) is not int or type(output_tokens) is not int or min(input_tokens, output_tokens) < 0:
        raise AuditError("invalid_token_liability", "Worst-case bounds must be nonnegative integers.")
    largest = max(sorted(_INPUTS[provider]), key=lambda name: Decimal(card.rates[name]))
    categories = {name: input_tokens if name == largest else 0 for name in sorted(_INPUTS[provider])}
    categories["output"] = output_tokens
    try:
        amount, value = _amount(card, categories)
    except (DecimalException, OverflowError, ValueError) as exc:
        raise AuditError("invalid_derived_cost", "Liability cannot be represented conservatively.", 3) from exc
    return CostResult(status="derived", purpose="liability", provider=provider, resolved_model=model,
                      rate_card_id=card.rate_card_id, rate_card_digest=card.card_digest,
                      usage_digest=sha256(canonical_json({"maximum_input": input_tokens, "maximum_output": output_tokens})),
                      priced_at=at.isoformat(), service_tier="default" if provider == "openai_compatible" else "standard",
                      currency=card.currency, input_tokens=input_tokens, output_tokens=output_tokens,
                      categories=categories, amount_decimal=amount, amount_usd=value,
                      method="decimal64-ceil-usd-1e-12/1", error=None)
