"""One-to-one all-atom scoring; labels enter only after prediction closure."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import TypeVar

from pydantic import ValidationError

from claim_auditor.contracts import (
    AuditError, Claim, EvaluationResult, GoldAtom, Predicate, PredictionRow,
    ScoredItem, WireModel, canonical_json,
)

MATCHER_VERSION = "raw-span-predicate/1"
_VERDICTS = ("verified", "partial", "missing", "unknown")
_SUPPORTED = {"path_exists", "symbol_declared", "config_literal", "dependency_declared", "metadata_declared", "cli_entry_declared", "env_reference", "bounded_code_fact"}
T = TypeVar("T", bound=WireModel)


def read_jsonl(path: Path, model: type[T]) -> list[T]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 10 * 1024 * 1024:
        raise AuditError("invalid_evaluation_input", "JSONL must be an ordinary file no larger than 10 MiB")
    rows: list[T] = []
    with path.open("rb") as source:
        for number, line in enumerate(source, 1):
            if number > 5000:
                raise AuditError("evaluation_row_limit", "at most 5000 rows are admitted")
            if not line.strip():
                raise AuditError("invalid_evaluation_input", f"blank JSONL row {number}")
            try:
                rows.append(model.model_validate_json(line))
            except (ValidationError, UnicodeDecodeError) as exc:
                raise AuditError("invalid_evaluation_input", f"closed-schema validation failed at row {number}") from exc
    return rows


def _predicate_key(predicate: Predicate) -> bytes:
    data = predicate.model_dump(mode="json", exclude={"predicate_id"})
    if predicate.kind == "dependency_declared":
        data["subject"] = re.sub(r"[-_.]+", "-", predicate.subject).lower()
    return canonical_json(data)


def _claim_key(claim: Claim) -> bytes:
    span = claim.span
    return canonical_json([
        span.snapshot_id, span.path, span.file_sha256, span.start_byte,
        span.end_byte, span.quote_sha256, claim.kind,
        sorted(_predicate_key(p).decode("utf-8") for p in claim.predicates),
    ])


def _subset(claim: Claim, identifiers: list[str]) -> set[bytes]:
    by_id = {p.predicate_id: p for p in claim.predicates}
    if len(by_id) != len(claim.predicates) or len(set(identifiers)) != len(identifiers) or not set(identifiers) <= by_id.keys():
        raise AuditError("invalid_predicate_identity", "predicate partition has duplicate or unknown IDs")
    return {_predicate_key(by_id[item]) for item in identifiers}


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def score_rows(predictions: list[PredictionRow], gold: list[GoldAtom], *, include_intervals: bool = True) -> EvaluationResult:
    if len({row.gold_id for row in gold}) != len(gold) or len({row.prediction_id for row in predictions}) != len(predictions):
        raise AuditError("duplicate_item_identity", "row IDs must be unique; duplicated predictions need distinct IDs and remain extras")
    gold_keys: dict[tuple[str, bytes], list[GoldAtom]] = defaultdict(list)
    for row in gold:
        _subset(row.claim, row.supported_predicate_ids)
        _subset(row.claim, row.unresolved_predicate_ids)
        accused = _subset(row.claim, row.accused_predicate_ids)
        if row.verdict in {"verified", "unknown"} and accused:
            raise AuditError("invalid_gold", "verified/unknown gold cannot accuse predicates")
        if row.verdict == "missing" and not accused:
            raise AuditError("invalid_gold", "missing gold must identify accused predicates")
        if row.annotator_type == "human" and (not row.annotator_id.strip() or row.adjudicated_at is None):
            raise AuditError("invalid_gold", "human row requires real annotator attribution and adjudication date")
        gold_keys[(row.family_id, _claim_key(row.claim))].append(row)
    confusion = {expected: {actual: 0 for actual in _VERDICTS} for expected in _VERDICTS}
    counts: Counter[str] = Counter({
        "gold_atoms": len(gold), "prediction_rows": len(predictions), "matched_atoms": 0,
        "omitted_atoms": 0, "extra_predictions": 0, "ambiguous_predictions": 0,
        "accusations": 0, "correct_accusations": 0, "gold_defects": 0,
        "identified_defects": 0, "gold_nondefects": 0, "falsely_accused_nondefects": 0,
        "gold_unknowable": 0, "accused_unknowable": 0, "verified_predictions": 0,
        "correct_verified": 0, "false_reassurances": 0, "partial_predictions": 0,
        "correct_partial": 0, "appropriate_unknown": 0, "answerable_atoms": 0,
        "unknown_answerable": 0, "supported_kind_atoms": 0, "correct_answerable": 0,
        "nonunknown_predictions": 0, "valid_predictions": 0, "atom_predictions": 0, "valid_matched_atoms": 0, "citation_open": 0,
        "citation_rejected": 0, "families": len({row.family_id for row in gold}),
    })
    for status in ("invalid_output", "abstention_screened", "input_too_large", "citation_failure", "execution_failure"):
        counts[status] = 0
    for row in gold:
        counts["gold_defects"] += bool(row.accused_predicate_ids)
        counts["gold_nondefects"] += row.answerable and not row.accused_predicate_ids
        counts["gold_unknowable"] += not row.answerable
        counts["answerable_atoms"] += row.answerable
        counts["supported_kind_atoms"] += row.claim.kind in _SUPPORTED
    used: set[str] = set()
    gold_kinds = Counter(row.claim.kind for row in gold)
    predicted_kinds: Counter[str] = Counter()
    matched_kinds: Counter[str] = Counter()
    items: list[ScoredItem] = []
    failures: dict[str, list[str]] = defaultdict(list)
    for row in predictions:
        if row.status != "prediction":
            counts[row.status] += 1
            failures[row.family_id].append(row.status)
        finding = row.finding
        if row.status == "prediction" and finding is None:
            raise AuditError("invalid_prediction", "prediction status requires finding")
        if finding is None:
            if row.accused_predicate_ids:
                raise AuditError("invalid_prediction", "failure without finding cannot accuse")
            items.append(ScoredItem(gold_id=None, prediction_id=row.prediction_id, family_id=row.family_id, status=row.status, expected=None, actual=None))
            continue
        counts["atom_predictions"] += 1
        predicted_kinds[finding.claim.kind] += 1
        accused = _subset(finding.claim, row.accused_predicate_ids)
        if set(row.accused_predicate_ids) != set(finding.accused_predicate_ids):
            raise AuditError("invalid_prediction", "prediction and finding accusation observations differ")
        supported = _subset(finding.claim, finding.supported_predicate_ids)
        unresolved = _subset(finding.claim, finding.unresolved_predicate_ids)
        if finding.verdict in {"verified", "unknown"} and accused:
            raise AuditError("invalid_prediction", "verified/unknown finding cannot accuse")
        if finding.verdict == "missing" and not accused:
            raise AuditError("invalid_prediction", "missing finding must expose accused predicates")
        citation_invalid = finding.citation_validation == "failed" or (finding.verdict != "unknown" and finding.citation_validation != "valid")
        valid = row.status == "prediction" and not citation_invalid
        if citation_invalid:
            counts["citation_rejected"] += 1
        elif finding.citation_validation == "valid":
            counts["citation_open"] += 1
        if valid:
            counts["valid_predictions"] += 1
            counts["accusations"] += len(accused)
            counts["verified_predictions"] += finding.verdict == "verified"
            counts["partial_predictions"] += finding.verdict == "partial"
            counts["nonunknown_predictions"] += finding.verdict != "unknown"
        candidates = gold_keys.get((row.family_id, _claim_key(finding.claim)), [])
        eligible = [item for item in candidates if item.gold_id not in used]
        if len(candidates) != 1 or not eligible:
            ambiguous = len(candidates) > 1
            counts["ambiguous_predictions" if ambiguous else "extra_predictions"] += 1
            items.append(ScoredItem(gold_id=None, prediction_id=row.prediction_id, family_id=row.family_id, status="ambiguous_match" if ambiguous else "extra_prediction", expected=None, actual=finding.verdict if valid else row.status))
            continue
        expected = eligible[0]
        used.add(expected.gold_id)
        counts["matched_atoms"] += 1
        gold_accused = _subset(expected.claim, expected.accused_predicate_ids)
        exact_partial = supported == _subset(expected.claim, expected.supported_predicate_ids) and unresolved == _subset(expected.claim, expected.unresolved_predicate_ids) and accused == gold_accused
        relation_correct = finding.support_relation == expected.support_relation
        correct = valid and finding.verdict == expected.verdict and relation_correct and (finding.verdict != "partial" or exact_partial)
        if valid:
            counts["valid_matched_atoms"] += 1
            matched_kinds[expected.claim.kind] += 1
            confusion[expected.verdict][finding.verdict] += 1
            counts["correct_accusations"] += len(accused & gold_accused) if expected.answerable else 0
            counts["identified_defects"] += bool(gold_accused) and gold_accused <= accused and accused <= gold_accused
            counts["falsely_accused_nondefects"] += expected.answerable and not gold_accused and bool(accused)
            counts["accused_unknowable"] += not expected.answerable and bool(accused)
            counts["correct_verified"] += finding.verdict == "verified" and correct
            counts["false_reassurances"] += bool(gold_accused) and finding.verdict == "verified"
            counts["correct_partial"] += finding.verdict == "partial" and correct
            counts["appropriate_unknown"] += not expected.answerable and finding.verdict == "unknown"
            counts["unknown_answerable"] += expected.answerable and finding.verdict == "unknown"
            counts["correct_answerable"] += expected.answerable and expected.claim.kind in _SUPPORTED and correct and finding.verdict != "unknown"
        items.append(ScoredItem(gold_id=expected.gold_id, prediction_id=row.prediction_id, family_id=row.family_id, status="matched" if valid else row.status if row.status != "prediction" else "citation_failure", expected=expected.verdict, actual=finding.verdict if valid else None))
    for row in gold:
        if row.gold_id in used:
            continue
        counts["omitted_atoms"] += 1
        family_failures = sorted(set(failures[row.family_id]))
        status = family_failures[0] if len(family_failures) == 1 else "execution_failure" if family_failures else "omitted"
        items.append(ScoredItem(gold_id=row.gold_id, prediction_id=None, family_id=row.family_id, status=status, expected=row.verdict, actual=None))
    supported_answerable = sum(row.answerable and row.claim.kind in _SUPPORTED for row in gold)
    metrics = {
        "extraction_precision": _rate(counts["valid_matched_atoms"], counts["atom_predictions"]),
        "extraction_recall": _rate(counts["valid_matched_atoms"], len(gold)),
        "accusation_precision": _rate(counts["correct_accusations"], counts["accusations"]),
        "defect_recall": _rate(counts["identified_defects"], counts["gold_defects"]),
        "verified_precision": _rate(counts["correct_verified"], counts["verified_predictions"]),
        "false_accusation_rate": _rate(counts["falsely_accused_nondefects"], counts["gold_nondefects"]),
        "unknowable_accusation_rate": _rate(counts["accused_unknowable"], counts["gold_unknowable"]),
        "false_reassurance_rate": _rate(counts["false_reassurances"], counts["gold_defects"]),
        "partial_correctness": _rate(counts["correct_partial"], counts["partial_predictions"]),
        "unknown_appropriateness": _rate(counts["appropriate_unknown"], counts["gold_unknowable"]),
        "unknown_overuse": _rate(counts["unknown_answerable"], counts["answerable_atoms"]),
        "addressable_share": _rate(counts["supported_kind_atoms"], len(gold)),
        "answerability_coverage": _rate(counts["correct_answerable"], supported_answerable),
        "nonunknown_rate": _rate(counts["nonunknown_predictions"], counts["valid_predictions"]),
        "citation_open_rate": _rate(counts["citation_open"], counts["citation_open"] + counts["citation_rejected"]),
    }
    for kind in sorted(set(gold_kinds) | set(predicted_kinds)):
        metrics[f"extraction_precision:{kind}"] = _rate(matched_kinds[kind], predicted_kinds[kind])
        metrics[f"extraction_recall:{kind}"] = _rate(matched_kinds[kind], gold_kinds[kind])
    per_kind = Counter(row.claim.kind for row in gold if row.claim.kind in _SUPPORTED)
    minima = len(gold) >= 120 and counts["families"] >= 12 and counts["gold_defects"] >= 30 and counts["gold_nondefects"] >= 30 and counts["accusations"] >= 30 and counts["verified_predictions"] >= 30 and bool(per_kind) and all(n >= 15 for n in per_kind.values())
    thresholds = {"extraction_precision": .95, "extraction_recall": .90, "accusation_precision": .95, "verified_precision": .95, "defect_recall": .80, "answerability_coverage": .70}
    counts["dev_targets_met"] = int(minima and all(metrics[name] is not None and metrics[name] >= limit for name, limit in thresholds.items()) and metrics["unknown_overuse"] is not None and metrics["unknown_overuse"] <= .20 and not counts["citation_rejected"])
    from claim_auditor.evaluation.measurements import family_bootstrap

    intervals = family_bootstrap(predictions, gold) if include_intervals else {}
    return EvaluationResult(matcher_version=MATCHER_VERSION, human_adjudicated=bool(gold) and all(row.annotator_type == "human" and row.adjudicated_at is not None for row in gold), comparative_complete=False, counts=dict(counts), metrics=metrics, confusion=confusion, items=items, intervals=intervals, attempt_summary=None, limitations=[
        "Descriptive item scoring only; no comparative or product acceptance is granted.",
        "Human attribution fields are operator-supplied provenance, not independently verified custody.",
        "No live extraction/single-pass arms or comparative acceptance are supplied by this scorer.",
        "Whole-family percentile bootstrap intervals are exploratory; fewer than six families or any undefined replicate makes the interval inconclusive.",
        "Exact raw-span/predicate matching is frozen at raw-span-predicate/1; ambiguous matches remain unmatched.",
        "Zero denominators are undefined; small samples are inconclusive. Agent-authored labels are development proposals, never human gold.",
    ])


def score_predictions(predictions_path: Path, gold_path: Path, out: Path) -> EvaluationResult:
    closed_run = predictions_path.is_dir()
    manifest = None
    if closed_run:
        from claim_auditor.citations import verify_report

        manifest = verify_report(predictions_path)
        predictions_path = predictions_path / "predictions.jsonl"
    predictions = read_jsonl(predictions_path, PredictionRow)
    gold = read_jsonl(gold_path, GoldAtom)
    if closed_run:
        # Family assignment is scorer-only. No label or family metadata is made
        # available to the already closed inference run.
        families: dict[str, set[str]] = defaultdict(set)
        for row in gold:
            families[row.claim.span.snapshot_id].add(row.family_id)
        remapped: list[PredictionRow] = []
        for row in predictions:
            options = families.get(row.finding.claim.span.snapshot_id, set()) if row.finding is not None else set()
            if len(options) != 1:
                raise AuditError("ambiguous_family", "closed-run snapshot must map to exactly one curator family")
            remapped.append(row.model_copy(update={"family_id": next(iter(options))}))
        predictions = remapped
    result = score_rows(predictions, gold)
    if manifest is not None:
        from claim_auditor.evaluation.measurements import summarize_attempts

        result = result.model_copy(update={"attempt_summary": summarize_attempts(manifest.attempts)})
    if out.exists() or out.is_symlink():
        raise AuditError("output_exists", "score output must be a fresh directory")
    out.mkdir(parents=True, exist_ok=False)
    artifacts = {
        "RESULTS.json": canonical_json(result) + b"\n",
        "items.jsonl": b"".join(canonical_json(item) + b"\n" for item in result.items),
        "results.md": ("# Descriptive scoring results\n\nComparative acceptance incomplete.\n\n" + "\n".join(f"- {name}: {value if value is not None else 'undefined / inconclusive'}" for name, value in result.metrics.items()) + "\n").encode("utf-8"),
    }
    for name, raw in artifacts.items():
        with (out / name).open("xb") as handle:
            handle.write(raw)
    return result
