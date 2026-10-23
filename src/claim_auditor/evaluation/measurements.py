"""Unknown-aware attempt accounting and exploratory whole-family intervals."""

from __future__ import annotations

import math
import random
import statistics
from collections import Counter, defaultdict

from claim_auditor.contracts import (
    Attempt, AttemptSummary, AuditError, BootstrapInterval, GoldAtom,
    PredictionRow,
)


def summarize_attempts(attempts: list[Attempt]) -> AttemptSummary:
    for attempt in attempts:
        values = (attempt.input_tokens, attempt.output_tokens, attempt.cost_usd, attempt.elapsed_seconds)
        if any(value is not None and (value < 0 or not math.isfinite(value)) for value in values):
            raise AuditError("invalid_attempt_measurement", "reported usage/cost/latency must be finite and nonnegative")

    def total(field: str) -> int | float | None:
        values = [getattr(attempt, field) for attempt in attempts]
        return sum(values) if values and all(value is not None for value in values) else None

    known_costs = [attempt.cost_usd for attempt in attempts if attempt.cost_usd is not None]
    latencies = sorted(attempt.elapsed_seconds for attempt in attempts if attempt.elapsed_seconds is not None)
    latency_complete = bool(attempts) and len(latencies) == len(attempts)
    return AttemptSummary(
        attempts=len(attempts), input_tokens=total("input_tokens"), output_tokens=total("output_tokens"),
        cost_usd=total("cost_usd"), reported_known_cost_usd=sum(known_costs),
        known_cost_attempts=len(known_costs), unknown_cost_attempts=len(attempts) - len(known_costs),
        median_seconds=statistics.median(latencies) if latency_complete else None,
        p95_seconds=latencies[max(0, math.ceil(.95 * len(latencies)) - 1)] if latency_complete else None,
        unknown_latency_attempts=len(attempts) - len(latencies), mode_counts=dict(Counter(attempt.mode for attempt in attempts)),
    )


def family_bootstrap(
    predictions: list[PredictionRow], gold: list[GoldAtom], *, resamples: int = 500,
    seed: int = 20261023,
) -> dict[str, BootstrapInterval]:
    """Resample complete families, retaining failures, omissions and extras."""
    from claim_auditor.evaluation.scoring import score_rows

    if not 1 <= resamples <= 2000:
        raise AuditError("bootstrap_limit", "resamples must be between 1 and 2000")
    gold_families: dict[str, list[GoldAtom]] = defaultdict(list)
    predicted_families: dict[str, list[PredictionRow]] = defaultdict(list)
    for row in gold:
        gold_families[row.family_id].append(row)
    for row in predictions:
        predicted_families[row.family_id].append(row)
    families = sorted(set(gold_families) | set(predicted_families))
    metric_names = (
        "extraction_precision", "extraction_recall", "accusation_precision",
        "defect_recall", "verified_precision", "false_accusation_rate",
        "false_reassurance_rate", "unknown_overuse", "answerability_coverage",
    )
    if len(families) < 6:
        return {name: BootstrapInterval(metric=name, low=None, high=None, families=len(families), resamples=0, seed=seed, status="inconclusive") for name in metric_names}
    generator = random.Random(seed)
    distributions: dict[str, list[float | None]] = {name: [] for name in metric_names}
    for _ in range(resamples):
        sample_gold: list[GoldAtom] = []
        sample_predictions: list[PredictionRow] = []
        for sample_index in range(len(families)):
            family = generator.choice(families)
            # A repeated draw is a distinct cluster instance, with all its rows
            # preserved together. Source spans and predicates stay unchanged.
            alias = f"bootstrap-{sample_index}:{family}"
            sample_gold.extend(row.model_copy(update={"family_id": alias, "gold_id": f"{sample_index}:{row.gold_id}"}) for row in gold_families[family])
            sample_predictions.extend(row.model_copy(update={"family_id": alias, "prediction_id": f"{sample_index}:{row.prediction_id}"}) for row in predicted_families[family])
        sample_result = score_rows(sample_predictions, sample_gold, include_intervals=False)
        for name in metric_names:
            distributions[name].append(sample_result.metrics[name])
    intervals: dict[str, BootstrapInterval] = {}
    for name, values in distributions.items():
        if any(value is None for value in values):
            intervals[name] = BootstrapInterval(metric=name, low=None, high=None, families=len(families), resamples=resamples, seed=seed, status="inconclusive")
            continue
        ordered = sorted(value for value in values if value is not None)
        low = ordered[max(0, math.floor(.025 * (len(ordered) - 1)))]
        high = ordered[min(len(ordered) - 1, math.ceil(.975 * (len(ordered) - 1)))]
        intervals[name] = BootstrapInterval(metric=name, low=low, high=high, families=len(families), resamples=resamples, seed=seed, status="exploratory")
    return intervals
