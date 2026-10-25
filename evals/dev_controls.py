"""Handcomputed public controls for the production scorer. No provider calls."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from claim_auditor.contracts import (
    Claim, Finding, GoldAtom, Predicate, PredictionRow, Span, canonical_json, sha256,
)
from claim_auditor.evaluation.scoring import score_predictions, score_rows


def control_rows():
    """Four distinct synthetic atoms: two supported, one defect, one unknowable."""
    raw = b"The function `alpha` is declared.\nThe function `beta` is declared.\nThe function `absent` is declared.\nUptime is guaranteed.\n"
    expected = ("verified", "verified", "missing", "unknown")
    actual = ("verified", "missing", "verified", "unknown")
    gold_rows, predictions = [], []
    offset = 0
    for index, (line, truth, observed) in enumerate(zip(raw.splitlines(keepends=True), expected, actual)):
        kind = "operational" if index == 3 else "symbol_declared"
        subject = ("alpha", "beta", "absent", "uptime")[index]
        predicate = Predicate(predicate_id=f"p:{index}", kind=kind, subject=subject,
                              module=None if index == 3 else "tiny", path=None, key=None,
                              expected=None, negated=False, condition=None, qualifiers=[], pattern=None)
        span = Span(snapshot_id="fixture:public-scorer-controls", file_sha256=sha256(raw),
                    path="README.md", start_byte=offset, end_byte=offset + len(line),
                    start_line=index + 1, end_line=index + 1, quote=line.decode(), quote_sha256=sha256(line))
        atom = Claim(claim_id=f"claim:{index}", parent_id=f"sentence:{index}", atom_ordinal=0,
                     kind=kind, normalized=span.quote, span=span, predicates=[predicate],
                     extraction_method="rules", extraction_version="public-dev-controls/1", uncertainty=[])
        truth_finding = synthetic_finding(atom, truth)
        gold_rows.append(GoldAtom(gold_id=f"gold:{index}", family_id="public:synthetic-control",
                                 claim=atom, verdict=truth, support_relation=truth_finding.support_relation,
                                 answerable=index != 3,
                                 supported_predicate_ids=truth_finding.supported_predicate_ids,
                                 unresolved_predicate_ids=truth_finding.unresolved_predicate_ids,
                                 accused_predicate_ids=truth_finding.accused_predicate_ids,
                                 annotator_type="agent", annotator_id="RV2-public-control",
                                 rationale="Synthetic arithmetic control; no human review claimed.",
                                 adjudicated_at=None, disagreements=[]))
        predictions.append(synthetic_prediction(atom, observed, index))
        offset += len(line)
    return predictions, gold_rows


def synthetic_finding(atom, verdict):
    identifiers = [predicate.predicate_id for predicate in atom.predicates]
    return Finding(claim=atom, verdict=verdict,
                   support_relation={"verified": "supports", "missing": "contradicts", "unknown": "no_evidence"}[verdict],
                   reason="synthetic_scorer_control", supported_predicate_ids=identifiers if verdict == "verified" else [],
                   unresolved_predicate_ids=[] if verdict == "verified" else identifiers,
                   accused_predicate_ids=identifiers if verdict == "missing" else [],
                   evidence_ids=[] if verdict == "unknown" else ["synthetic:not-a-real-citation"],
                   complete=True, citation_validation="not_applicable" if verdict == "unknown" else "valid",
                   model_proposal=None)


def synthetic_prediction(atom, verdict, index):
    finding = synthetic_finding(atom, verdict)
    return PredictionRow(prediction_id=f"prediction:{index}", family_id="public:synthetic-control",
                         finding=finding, status="prediction", error=None,
                         accused_predicate_ids=finding.accused_predicate_ids)


def check_controls():
    rows, gold = control_rows()
    mixed = score_rows(rows, gold, include_intervals=False)
    expected = {"accusation_precision": 0.0, "defect_recall": 0.0, "verified_precision": 0.5,
                "false_accusation_rate": 0.5, "false_reassurance_rate": 1.0,
                "unknown_appropriateness": 1.0, "unknown_overuse": 0.0,
                "answerability_coverage": 1 / 3, "extraction_recall": 1.0}
    for metric, value in expected.items():
        if mixed.metrics[metric] != value:
            raise AssertionError(f"handcomputed {metric}: {mixed.metrics[metric]} != {value}")
    adversaries = {}
    for verdict in ("unknown", "missing"):
        result = score_rows([synthetic_prediction(row.claim, verdict, i) for i, row in enumerate(gold)],
                            gold, include_intervals=False)
        if result.counts["dev_targets_met"] or result.comparative_complete or result.human_adjudicated:
            raise AssertionError(f"all-{verdict} must not pass or imply benchmark acceptance")
        adversaries[f"all_{verdict}"] = result.model_dump(mode="json")
    return {"designation": "PUBLIC_DEV_SYNTHETIC_CONTROLS", "human_adjudicated": False,
            "comparative_complete": False, "heldout_accessed": False, "provider_calls": 0,
            "mixed": mixed.model_dump(mode="json"), "adversaries": adversaries,
            "not_measured": ["human-adjudicated evaluation", "live extraction", "live single-pass", "heldout", "Action"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = check_controls()
    args.out.mkdir(parents=True, exist_ok=False)
    rows, gold = control_rows()
    for name, records in (("predictions.jsonl", rows), ("synthetic-labels.jsonl", gold)):
        (args.out / name).write_bytes(b"".join(canonical_json(row) + b"\n" for row in records))
    scored = score_predictions(args.out / "predictions.jsonl", args.out / "synthetic-labels.jsonl", args.out / "scored")
    if scored.metrics != result["mixed"]["metrics"]:
        raise AssertionError("JSONL roundtrip changed handcomputed metrics")
    (args.out / "CONTROLS.json").write_bytes(canonical_json(result) + b"\n")
    print(json.dumps({"status": "passed", "designation": result["designation"], "provider_calls": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
