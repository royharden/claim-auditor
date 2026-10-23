"""Four-way policy. A valid byte pointer does not itself prove entailment."""

from __future__ import annotations

from ..contracts import Claim, Finding, Predicate, PredicateResult

SUPPORTED_KINDS = frozenset({
    "path_exists", "symbol_declared", "config_literal", "dependency_declared",
    "metadata_declared", "cli_entry_declared", "env_reference", "bounded_code_fact",
})


def _state(predicate: Predicate, result: PredicateResult) -> str:
    if predicate.kind not in SUPPORTED_KINDS:
        return "unknown"
    if predicate.condition is not None or any(item != "explicit_fence_import" for item in predicate.qualifiers):
        return "unknown"
    if result.state == "unknown":
        return "unknown"
    # A skipped scope cannot support either negative evidence or its negation.
    if result.state == "absent":
        negative = [e for e in result.evidence if e.kind == "negative"]
        reports = {c.coverage_id: c for c in result.coverage}
        if not result.complete or not negative:
            return "unknown"
        if any(e.coverage_id not in reports or not reports[e.coverage_id].complete for e in negative):
            return "unknown"
    elif result.state == "established" and not any(e.kind == "positive" for e in result.evidence):
        return "unknown"
    elif result.state == "contradicted" and not any(e.kind == "contrary" for e in result.evidence):
        return "unknown"
    if predicate.negated:
        return "contradicted" if result.state == "established" else "established"
    return result.state


def decide_finding(
    claim: Claim,
    results: list[PredicateResult],
    *,
    citation_valid: bool,
    model_proposal: str | None = None,
) -> Finding:
    """Reduce exact predicates only after the sole citation resolver has passed."""
    if not citation_valid:
        return Finding(
            claim=claim, verdict="unknown", support_relation="no_evidence",
            reason="citation_integrity_failure", supported_predicate_ids=[],
            unresolved_predicate_ids=[p.predicate_id for p in claim.predicates],
            accused_predicate_ids=[],
            evidence_ids=[], complete=False, citation_validation="failed",
            model_proposal=model_proposal,
        )
    by_id = {r.predicate_id: r for r in results}
    if len(by_id) != len(results):
        by_id = {}  # duplicate resolution cannot silently overwrite observation
    supported: list[str] = []
    contradicted: list[str] = []
    unresolved: list[str] = []
    evidence_ids: list[str] = []
    reasons: list[str] = []
    all_complete = True
    for predicate in claim.predicates:
        result = by_id.get(predicate.predicate_id)
        if result is None:
            unresolved.append(predicate.predicate_id)
            reasons.append("missing_predicate_resolution")
            all_complete = False
            continue
        state = _state(predicate, result)
        if state == "established":
            supported.append(predicate.predicate_id)
        elif state in {"absent", "contradicted"}:
            contradicted.append(predicate.predicate_id)
            unresolved.append(predicate.predicate_id)
        else:
            unresolved.append(predicate.predicate_id)
            reasons.append(result.reason)
        all_complete = all_complete and result.complete
        evidence_ids.extend(e.evidence_id for e in result.evidence)
    if not claim.predicates or claim.kind not in SUPPORTED_KINDS:
        verdict, relation, reason = "unknown", "no_evidence", "unsupported_semantics"
        unresolved = [p.predicate_id for p in claim.predicates]
        supported = []
    elif claim.uncertainty:
        verdict, relation, reason = "unknown", "no_evidence", claim.uncertainty[0]
        unresolved = [p.predicate_id for p in claim.predicates]
        supported = []
    elif supported and len(supported) == len(claim.predicates):
        verdict, relation, reason = "verified", "supports", "static_predicates_established"
    elif supported:
        verdict, relation, reason = "partial", "mixed", "supported_and_unresolved_predicates"
    elif contradicted and len(contradicted) == len(claim.predicates):
        verdict, relation, reason = "missing", "contradicts", "scoped_absence_or_opposite_literal"
    else:
        verdict = "unknown"
        relation = "contradicts" if contradicted else "no_evidence"
        reason = reasons[0] if reasons else "incomplete_predicate_support"
    return Finding(
        claim=claim, verdict=verdict, support_relation=relation, reason=reason,
        supported_predicate_ids=supported, unresolved_predicate_ids=unresolved,
        accused_predicate_ids=contradicted if verdict in {"missing", "partial"} else [],
        evidence_ids=list(dict.fromkeys(evidence_ids)), complete=all_complete,
        citation_validation="valid" if evidence_ids else "not_applicable",
        model_proposal=model_proposal,
    )
