"""Closed multi-family descriptive aggregation; never runs inference.

The canonical paired verifier closes every case before this consumer opens any
gold. Metrics, matching and whole-family intervals remain existing authorities.
"""

from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import re
from typing import Any

from pydantic import ValidationError

from claim_auditor.citations import validate_span
from claim_auditor.contracts import (
    AuditError, DatasetCase, DatasetManifest, EvaluationLock, EvaluationResult,
    GoldAtom, Limits, POLICY_VERSION, PredictionRow, canonical_json, sha256, stable_id,
    validate_relative_path,
)
from claim_auditor.evaluation.measurements import summarize_attempts
from claim_auditor.evaluation.packet import PACKET_VERSION, code_digest
from claim_auditor.evaluation.packet_facts import PACKET_FACT_VERSION
from claim_auditor.evaluation.rulings import _ordinary_directory, _timestamp
from claim_auditor.evaluation.runner import PAIRED_ARMS, RUNNER_VERSION
from claim_auditor.evaluation.scoring import MATCHER_VERSION, _claim_key, score_rows
from claim_auditor.evaluation.verify import verify_paired
from claim_auditor.index import PARSER_VERSION
from claim_auditor.inventory.raw import safe_display
from claim_auditor.snapshot import load_snapshot
from claim_auditor.snapshot.safeio import read_ordinary

MAX_CASES = 48
MAX_GOLD_BYTES = 10 * 1024 * 1024
MAX_TOTAL_GOLD_BYTES = 32 * 1024 * 1024
ALL_ARMS = {*PAIRED_ARMS, "product_full_index"}
_MODEL_ARMS = {"extraction": "live_extraction", "single_pass": "live_single_pass"}


def _path(base: Path, value: str) -> Path:
    if not value.strip() or value.startswith(("\\\\", "//")) or any(ord(char) < 32 for char in value):
        raise AuditError("dataset_path_invalid", "explicit ordinary local paths are required")
    result = Path(value)
    if not result.is_absolute():
        validate_relative_path(value)
        result = base / result
    # Lexical only: never stat/follow/read the gold path during preflight.
    return Path(os.path.abspath(result))


def _manifest(path: Path, digest: str) -> DatasetManifest:
    raw = read_ordinary(path.parent, path.name, 2 * 1024 * 1024)
    if sha256(raw) != digest:
        raise AuditError("dataset_manifest_changed", "external manifest byte pin differs", 4)
    try:
        manifest = DatasetManifest.model_validate_json(raw)
    except ValidationError as exc:
        raise AuditError("invalid_dataset_manifest", "closed dataset manifest required; templates are unadmitted") from exc
    if not manifest.dataset_id.strip() or not manifest.protocol_id.strip() or not 1 <= len(manifest.cases) <= MAX_CASES:
        raise AuditError("dataset_cases_invalid", "nonempty study/protocol identity and 1..48 cases required")
    actual = (POLICY_VERSION, MATCHER_VERSION, PACKET_VERSION, RUNNER_VERSION, PACKET_FACT_VERSION, PARSER_VERSION)
    declared = (manifest.taxonomy_version, manifest.matcher_version, manifest.packet_version,
                manifest.runner_version, manifest.packet_fact_version, manifest.parser_version)
    if actual != declared or manifest.code_digest != code_digest():
        raise AuditError("dataset_versions_differ", "freeze exact taxonomy/matcher/packet/runner/parser/tool source before inference")
    if set(manifest.required_arms) != ALL_ARMS or len(manifest.required_arms) != len(ALL_ARMS):
        raise AuditError("dataset_required_arms", "four equal-packet methods and separate full-index utility required exactly once")
    if set(manifest.provider_models) != set(_MODEL_ARMS.values()) or set(manifest.prompt_digests) != set(_MODEL_ARMS.values()):
        raise AuditError("dataset_provider_identity", "both declared model arms need exact model/prompt identities")
    if any(not value.strip() for value in manifest.provider_models.values()):
        raise AuditError("dataset_provider_identity", "model identity cannot be blank")
    if manifest.mode == "dev_descriptive" and (manifest.admitted or manifest.admitted_by is not None or manifest.admitted_at is not None):
        raise AuditError("dataset_false_admission", "DEV descriptive studies cannot impersonate admitted evaluations")
    if manifest.mode == "locked_evaluation":
        if not manifest.admitted or not (manifest.admitted_by or "").strip() or not manifest.admitted_at:
            raise AuditError("dataset_lock_not_admitted", "locked studies require real explicit admission metadata")
        _timestamp(manifest.admitted_at)
        if not (manifest.human_review_receipt or "").strip():
            raise AuditError("dataset_human_provenance_missing", "actual review receipt must be supplied before a locked study")
    return manifest


def _case_pins(case: DatasetCase, manifest: DatasetManifest, verified: dict[str, Any], snapshot: Any) -> None:
    run, packet = verified["manifest"], verified["packet"]
    if not all(value.strip() for value in (case.case_id, case.family_id, case.ancestry_id, case.snapshot_id)):
        raise AuditError("dataset_case_identity", "case/family/ancestry/source identities must be explicit")
    if ((snapshot.snapshot_id, snapshot.manifest_digest, snapshot.content_digest)
            != (case.snapshot_id, case.snapshot_manifest_digest, case.source_content_digest)
            or packet.snapshot_id != case.snapshot_id or packet.snapshot_manifest_digest != case.snapshot_manifest_digest):
        raise AuditError("dataset_source_changed", "exact snapshot/content pins differ", 4)
    if (verified["manifest_digest"] != case.run_manifest_digest or set(verified["predictions"]) != ALL_ARMS
            or set(verified["attempts"]) != ALL_ARMS or set(run["arms"]) != ALL_ARMS):
        raise AuditError("dataset_run_scope", "every required closed arm must be present without extra treatments")
    if (run["runner_version"] != manifest.runner_version or run["parser_version"] != manifest.parser_version
            or run["packet_fact_version"] != manifest.packet_fact_version or run["code_digest"] != manifest.code_digest
            or packet.packet_version != manifest.packet_version
            or canonical_json(run["caps"]) != canonical_json(manifest.caps)):
        raise AuditError("dataset_protocol_mismatch", "cases must use identical pinned versions and declared total caps")
    for role, arm in _MODEL_ARMS.items():
        info = run["arms"][arm]
        request = info.get("request")
        if request is not None and (request["arm"] != role or request["policy_version"] != manifest.taxonomy_version
                                    or request["model"] != manifest.provider_models[arm]
                                    or request["prompt_digest"] != manifest.prompt_digests[arm]):
            raise AuditError("dataset_provider_identity", "case model/prompt/policy differs from predeclared study")
    experiment = run["experiment"]
    if manifest.mode == "locked_evaluation":
        if (not experiment or not case.protocol_digest
                or experiment["protocol_digest"] != case.protocol_digest
                or experiment["protocol_id"] != manifest.protocol_id
                or any(not (value or "").strip() for value in (case.source_rights_receipt, case.custody_receipt))):
            raise AuditError("dataset_protocol_mismatch", "locked case lost exact protocol/rights/custody bindings")
    elif experiment is not None:
        if case.protocol_digest != experiment["protocol_digest"] or experiment["protocol_id"] != manifest.protocol_id:
            raise AuditError("dataset_protocol_mismatch", "optional protocol identity differs even in descriptive mode")
    elif case.protocol_digest is not None:
        raise AuditError("dataset_protocol_mismatch", "declared protocol pin has no closed protocol artifact")


def preflight_dataset(manifest_path: Path, *, manifest_digest: str) -> dict[str, Any]:
    """Verify ALL inference closures and pins before opening ANY gold bytes.

    Returns the canonical verifier payloads for this invocation, not an admission
    token. evaluate_dataset always performs its own preflight instead of trusting
    a caller-supplied object. No gold path is opened, stated or resolved here.
    """
    manifest_path = Path(os.path.abspath(manifest_path))
    manifest = _manifest(manifest_path, manifest_digest)
    base = manifest_path.parent
    seen = {name: set() for name in ("case", "family", "ancestry", "snapshot", "content", "run")}
    cases = []
    # Reject duplicates before expensive verifier work; never choose a successful
    # representative after looking at results or labels.
    for case in manifest.cases:
        identities = dict(case=case.case_id, family=case.family_id, ancestry=case.ancestry_id,
                          snapshot=case.snapshot_id, content=case.source_content_digest,
                          run=case.run_manifest_digest)
        for kind, value in identities.items():
            if value in seen[kind]:
                raise AuditError("dataset_duplicate_case", f"repeated {kind} identity; use one predeclared representative per ancestor")
            seen[kind].add(value)
    # Lexically disjoint label locations are checked without opening/statting any
    # gold file. Ordinary-file readers reject link/reparse paths at actual reads.
    inference_roots = [_path(base, value) for case in manifest.cases for value in (case.run_root, case.snapshot_root)]
    gold_paths = [_path(base, case.gold_path) for case in manifest.cases]
    if len({os.path.normcase(str(path)) for path in gold_paths}) != len(gold_paths):
        raise AuditError("dataset_duplicate_gold_path", "cases cannot share one label file")
    for path in gold_paths:
        if path == manifest_path or any(path == root or root in path.parents for root in inference_roots):
            raise AuditError("dataset_gold_in_inference", "label files must remain outside inference/source/control trees")
    for case in manifest.cases:
        source = _path(base, case.snapshot_root)
        run_root = _path(base, case.run_root)
        verified = verify_paired(run_root, source, manifest_digest=case.run_manifest_digest)
        snapshot = load_snapshot(source)
        _case_pins(case, manifest, verified, snapshot)
        if manifest.mode == "locked_evaluation":
            # This is protocol metadata, never the gold path. Reuse the canonical
            # verifier's protocol validation; only bind its source/gold receipts.
            protocol_raw = read_ordinary(run_root, "protocol-copy.json", 128 * 1024)
            if sha256(protocol_raw) != case.protocol_digest:
                raise AuditError("dataset_protocol_changed", "closed copied protocol differs from external case pin", 4)
            lock = EvaluationLock.model_validate_json(protocol_raw)
            if (lock.source_seal_digest != case.snapshot_manifest_digest or lock.gold_seal_digest != case.gold_digest
                    or lock.custody_receipt != case.custody_receipt or lock.source_rights_receipt != case.source_rights_receipt
                    or lock.protocol_id != manifest.protocol_id
                    or any(lock.provider_models.get(arm) != manifest.provider_models[arm] for arm in _MODEL_ARMS.values())):
                raise AuditError("dataset_protocol_mismatch", "case source/later-gold/rights/custody differ from closed lock")
        cases.append(dict(case=case, source=source, run_root=run_root, snapshot=snapshot, verified=verified))
    for arm in ALL_ARMS:
        identifiers = [attempt.attempt_id for item in cases for attempt in item["verified"]["attempts"][arm]]
        if len(identifiers) != len(set(identifiers)):
            raise AuditError("dataset_duplicate_attempt", "one physical attempt cannot be billed/counted in multiple cases")
    return dict(manifest=manifest, manifest_digest=manifest_digest, manifest_path=manifest_path,
                cases=cases, gold_opened=False, status="all_inference_closed_gold_unopened")


def _gold(item: dict[str, Any], base: Path) -> tuple[list[GoldAtom], bytes]:
    """Only called after the complete dataset preflight has returned."""
    case, packet = item["case"], item["verified"]["packet"]
    path = _path(base, case.gold_path)
    raw = read_ordinary(path.parent, path.name, MAX_GOLD_BYTES)
    if sha256(raw) != case.gold_digest:
        raise AuditError("dataset_gold_changed", "later-opened exact gold bytes differ from external curator pin", 4)
    lines = raw.splitlines()
    if not lines or len(lines) > Limits().max_atoms or any(not line.strip() for line in lines):
        raise AuditError("dataset_gold_invalid", "nonempty bounded JSONL required; no dropped blank/invalid rows")
    try:
        rows = [GoldAtom.model_validate_json(line) for line in lines]
    except ValidationError as exc:
        raise AuditError("dataset_gold_invalid", "closed GoldAtom rows required") from exc
    ids, keys = set(), set()
    for row in rows:
        if (row.family_id != case.family_id or row.claim.span.snapshot_id != case.snapshot_id
                or (row.claim.span.path, row.claim.span.file_sha256) != (packet.readme_path, packet.readme_sha256)):
            raise AuditError("dataset_gold_scope", "every gold row must belong to the exact declared source/README/family")
        validate_span(item["snapshot"], item["source"], row.claim.span)
        if row.annotator_type == "human":
            if not row.adjudicated_at:
                raise AuditError("dataset_human_attribution", "human rows require an actual aware adjudication date")
            _timestamp(row.adjudicated_at)
        key = _claim_key(row.claim)
        if row.gold_id in ids or key in keys:
            raise AuditError("dataset_duplicate_gold", "duplicate/conflicting atomic gold cannot inflate denominators")
        ids.add(row.gold_id)
        keys.add(key)
    return rows, raw


def _result(rows: list[PredictionRow], gold: list[GoldAtom], attempts: list) -> EvaluationResult:
    result = score_rows(rows, gold, include_intervals=True)
    return result.model_copy(update={"comparative_complete": False, "human_adjudicated": False,
                                     "attempt_summary": summarize_attempts(attempts) if attempts else None,
                                     "limitations": [*result.limitations,
                                         "Dataset results are descriptive; human fields/receipt strings are not independently verified custody or product acceptance.",
                                         "One case per declared ancestor; whole-family intervals use ancestry IDs, not renamed case aliases."]})


def _slice(rows: list[PredictionRow], gold: list[GoldAtom]) -> EvaluationResult:
    result = score_rows(rows, gold, include_intervals=False)
    return result.model_copy(update={"comparative_complete": False, "human_adjudicated": False})


def _prerequisites(preflight: dict[str, Any], all_gold: list[GoldAtom]) -> list[str]:
    manifest = preflight["manifest"]
    missing = []
    if manifest.mode != "locked_evaluation" or not manifest.admitted:
        missing.append("study_is_DEV_descriptive_not_an_admitted_locked_comparison")
    if not (manifest.human_review_receipt or "").strip():
        missing.append("actual_human_review_receipt_unresolved")
    if not all(row.annotator_type == "human" and row.adjudicated_at is not None for row in all_gold):
        missing.append("not_every_gold_row_has_actual_human_attribution_fields")
    if any(not (item["case"].source_rights_receipt or "").strip() or not (item["case"].custody_receipt or "").strip()
           for item in preflight["cases"]):
        missing.append("source_rights_or_actual_custody_provenance_unresolved")
    for arm in _MODEL_ARMS.values():
        genuine = []
        attempts = []
        for item in preflight["cases"]:
            run = item["verified"]["manifest"]
            info = run["arms"][arm]
            experiment = run["experiment"]
            genuine.append(bool(experiment and experiment.get("execution_kind") == "live"
                                and info.get("provider_protocol") == "live_protocol"
                                and info.get("execution_kind") in {"live", "not_attempted"}))
            attempts.extend(item["verified"]["attempts"][arm])
        if not all(genuine) or not any(attempt.mode == "live" for attempt in attempts):
            missing.append(f"{arm}_has_no_complete_genuine_live_protocol_measurement")
    kinds = Counter(row.claim.kind for row in all_gold)
    if len(all_gold) < 120 or len(preflight["cases"]) < 12:
        missing.append("promoted_120_atom_12_independent_ancestor_minimum_not_met")
    if any(count < 15 for count in kinds.values()):
        missing.append("one_or_more_reported_gold_kinds_have_fewer_than_15_items")
    # Strings, digests and admitted flags do not themselves prove actual human
    # review or custody. The independent owner must settle that outside this tool.
    missing.append("independent_human_custody_and_product_acceptance_not_certified_by_aggregation")
    missing.append("predeclared_quality_cost_tradeoff_requires_independent_interpretation")
    return missing


def _aggregate(preflight: dict[str, Any], case_gold: dict[str, list[GoldAtom]]) -> tuple[dict[str, EvaluationResult], dict[str, Any]]:
    manifest = preflight["manifest"]
    gold = []
    predictions = {arm: [] for arm in manifest.required_arms}
    attempts = {arm: [] for arm in manifest.required_arms}
    cases = {}
    gold_lookup, prediction_lookup = {}, {}
    method_observations = {arm: [] for arm in manifest.required_arms}
    for item in preflight["cases"]:
        case = item["case"]
        cases[case.case_id] = dict(family_id=case.family_id, ancestry_id=case.ancestry_id,
                                  snapshot_id=case.snapshot_id, source_manifest_digest=case.snapshot_manifest_digest,
                                  run_manifest_digest=case.run_manifest_digest, gold_digest=case.gold_digest)
        for row in case_gold[case.case_id]:
            identifier = stable_id("dataset-gold", case.case_id, row.gold_id)
            adapted = row.model_copy(update={"family_id": case.ancestry_id, "gold_id": identifier})
            gold.append(adapted)
            gold_lookup[identifier] = dict(case_id=case.case_id, family_id=case.family_id,
                                            ancestry_id=case.ancestry_id, original_gold_id=row.gold_id,
                                            kind=row.claim.kind, expected_relation=row.support_relation,
                                            expected_predicates=dict(supported=row.supported_predicate_ids,
                                                                     unresolved=row.unresolved_predicate_ids,
                                                                     accused=row.accused_predicate_ids))
        for arm in manifest.required_arms:
            info = item["verified"]["manifest"]["arms"][arm]
            for row in item["verified"]["predictions"][arm]:
                identifier = stable_id("dataset-prediction", case.case_id, arm, row.prediction_id)
                predictions[arm].append(row.model_copy(update={"family_id": case.ancestry_id, "prediction_id": identifier}))
                prediction_lookup[identifier] = dict(case_id=case.case_id, family_id=case.family_id,
                                                       ancestry_id=case.ancestry_id, original_prediction_id=row.prediction_id,
                                                       kind=row.finding.claim.kind if row.finding is not None else None,
                                                       actual_relation=row.finding.support_relation if row.finding is not None else None,
                                                       actual_predicates=dict(supported=row.finding.supported_predicate_ids,
                                                                              unresolved=row.finding.unresolved_predicate_ids,
                                                                              accused=row.finding.accused_predicate_ids) if row.finding is not None else None,
                                                       error=row.error)
            attempts[arm].extend(item["verified"]["attempts"][arm])
            method_observations[arm].append(dict(case_id=case.case_id, status=info["status"],
                                                attempts=item["verified"]["attempts"][arm],
                                                execution_kind=info.get("execution_kind", "rules"),
                                                provider_protocol=info.get("provider_protocol"),
                                                observed_usage=info.get("usage", []),
                                                simulated_fixture_usage=info.get("simulated_usage", []),
                                                usage_note="simulated values are never added to observed usage totals"))
    results = {arm: _result(predictions[arm], gold, attempts[arm]) for arm in manifest.required_arms}
    per_family, per_kind = {}, {}
    for item in preflight["cases"]:
        case = item["case"]
        family_gold = [row for row in gold if row.family_id == case.ancestry_id]
        per_family[case.family_id] = {arm: _slice([row for row in predictions[arm] if row.family_id == case.ancestry_id], family_gold)
                                      for arm in manifest.required_arms}
    kinds = sorted({row.claim.kind for row in gold} | {row.finding.claim.kind for rows in predictions.values() for row in rows if row.finding is not None})
    for kind in kinds:
        kind_gold = [row for row in gold if row.claim.kind == kind]
        per_kind[kind] = {arm: _slice([row for row in predictions[arm] if row.finding is None or row.finding.claim.kind == kind], kind_gold)
                          for arm in manifest.required_arms}
    items = []
    for arm, result in results.items():
        for row in result.items:
            original = gold_lookup.get(row.gold_id) or prediction_lookup.get(row.prediction_id) or {}
            predicted = prediction_lookup.get(row.prediction_id, {})
            items.append(dict(method=arm, case_id=original.get("case_id"), family_id=original.get("family_id"),
                              ancestry_id=row.family_id, kind=original.get("kind"), item=row,
                              error=predicted.get("error"), original_gold_id=original.get("original_gold_id"),
                              original_prediction_id=predicted.get("original_prediction_id"),
                              expected_relation=original.get("expected_relation"), actual_relation=predicted.get("actual_relation"),
                              expected_predicates=original.get("expected_predicates"), actual_predicates=predicted.get("actual_predicates")))
    missing = _prerequisites(preflight, gold)
    target_states = {}
    for arm, result in results.items():
        undefined = sorted(name for name, value in result.metrics.items() if value is None)
        unknown_usage = result.attempt_summary is None or bool(result.attempt_summary.unknown_cost_attempts or result.attempt_summary.unknown_latency_attempts)
        conditions = [*missing]
        if not result.counts["dev_targets_met"]:
            conditions.append("existing_scorer_predeclared_dev_gate_false_or_underpowered")
        if unknown_usage:
            conditions.append("observed_usage_or_latency_unknown_or_no_attempt_measurements")
        target_states[arm] = dict(existing_scorer_dev_targets_met=bool(result.counts["dev_targets_met"]),
                                 undefined_metrics=undefined, observed_usage_incomplete=unknown_usage,
                                 status="inconclusive_for_comparative_acceptance", missing_conditions=conditions)
    candidate_precision = results["packet_candidate"].metrics["accusation_precision"]
    grep_precision = results["packet_grep"].metrics["accusation_precision"]
    precision_guard = None if candidate_precision is None or grep_precision is None else candidate_precision >= grep_precision
    summary = dict(format="dataset-evaluation/1", dataset_id=manifest.dataset_id, mode=manifest.mode,
                   manifest_digest=preflight["manifest_digest"], status="descriptive_comparative_incomplete",
                   comparative_complete=False, human_adjudicated=False, custody_verified=False,
                   all_gold_rows_human_attributed=all(row.annotator_type == "human" and row.adjudicated_at is not None for row in gold),
                   case_count=len(cases), independent_ancestry_clusters=len(cases), gold_atoms=len(gold), cases=cases,
                   equal_packet_methods=list(PAIRED_ARMS), separate_utility_method="product_full_index",
                   methods=results, per_family=per_family, per_kind=per_kind, items=items,
                   method_observations=method_observations, target_states=target_states,
                   candidate_not_below_grep_accusation_precision=precision_guard,
                   missing_conditions=missing, runtime_validation="unverified",
                   limitations=[
                       "Existing score_rows defines all matching/counts/metrics; summaries are not averages of case headline scores.",
                       "Existing family_bootstrap, invoked by score_rows, resamples whole ancestry clusters; intervals remain exploratory/inconclusive.",
                       "Full-index utility has privileged evidence and is excluded from the equal-packet comparison.",
                       "Generic case failures repeat in per-kind diagnostic slices; slices are nonadditive and never summed into totals.",
                       "No-attempt usage stays unknown/None; fixture observations remain separately simulated and cannot prove cheap live execution.",
                       "Gold attribution, receipt strings and closed artifact integrity do not certify actual human action, rights, custody or acceptance.",
                   ])
    return results, summary


def _write(path: Path, value: object) -> str:
    raw = canonical_json(value) + b"\n"
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return sha256(raw)


def _raw_write(path: Path, raw: bytes) -> str:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return sha256(raw)


def evaluate_dataset(manifest_path: Path, out: Path, *, manifest_digest: str) -> dict[str, EvaluationResult]:
    """Future operator scoring only; all-run preflight precedes ANY gold read."""
    preflight = preflight_dataset(manifest_path, manifest_digest=manifest_digest)
    out = Path(os.path.abspath(out))
    for item in preflight["cases"]:
        if any(out == root or root in out.parents for root in (item["source"], item["run_root"])):
            raise AuditError("dataset_output_inside_input", "output must preserve every inference/source tree")
    _ordinary_directory(out.parent)
    out.mkdir(exist_ok=False)
    phase = "gold_binding_after_all_inference_closed"
    try:
        case_gold, gold_hashes = {}, {}
        total = 0
        # No gold helper is reachable before the complete preflight returned.
        for item in preflight["cases"]:
            rows, raw = _gold(item, preflight["manifest_path"].parent)
            total += len(raw)
            if total > MAX_TOTAL_GOLD_BYTES:
                raise AuditError("dataset_gold_limit", "combined gold exceeds the declared local byte ceiling")
            case_gold[item["case"].case_id] = rows
            gold_hashes[item["case"].case_id] = sha256(raw)
        phase = "existing_scorer_aggregation"
        results, summary = _aggregate(preflight, case_gold)
        summary["gold_hashes"] = gold_hashes
        phase = "summary_artifacts"
        manifest_raw = read_ordinary(preflight["manifest_path"].parent, preflight["manifest_path"].name, 2 * 1024 * 1024)
        if sha256(manifest_raw) != manifest_digest:
            raise AuditError("dataset_manifest_changed", "operator manifest changed during scoring; preserve failed study", 4)
        hashes = {"SUMMARY.json": _write(out / "SUMMARY.json", summary),
                  "items.json": _write(out / "items.json", summary["items"]),
                  "manifest-copy.json": _raw_write(out / "manifest-copy.json", manifest_raw)}
        markdown = render_dataset_markdown(summary).encode("utf-8")
        with (out / "summary.md").open("xb") as stream:
            stream.write(markdown)
            stream.flush()
            os.fsync(stream.fileno())
        hashes["summary.md"] = sha256(markdown)
        _write(out / "DATASET.json", dict(format="dataset-output/1", dataset_id=preflight["manifest"].dataset_id,
                                           input_manifest_digest=manifest_digest, artifacts=hashes,
                                           state="closed_descriptive_unaccepted", comparative_complete=False,
                                           human_adjudicated=False, runtime_validation="unverified"))
        return results
    except (AuditError, ValidationError, OSError, ValueError, TypeError) as exc:
        try:
            _write(out / "FAILED.json", dict(format="dataset-failure/1", dataset_id=preflight["manifest"].dataset_id,
                                             manifest_digest=manifest_digest, phase=phase,
                                             reason=exc.reason if isinstance(exc, AuditError) else type(exc).__name__,
                                             status="failed_preserved_no_acceptance", comparative_complete=False))
        except OSError:
            pass  # Preserve original error and partial output; never clean up.
        raise


def _cell(value: object) -> str:
    if value is None:
        return "undefined / inconclusive"
    text = safe_display(str(value)).replace("\r", " ").replace("\n", " ").replace("\t", " ")
    # Inline code prevents Markdown links/HTML/autolinks. Choose a delimiter
    # longer than any source tick run; table pipes still need GFM escaping.
    fence = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    return fence + " " + text.replace("|", "\\|") + " " + fence


def render_dataset_markdown(summary: dict[str, Any]) -> str:
    """Render existing item/metric records only; no inferred or typed-in scores."""
    value = json.loads(canonical_json(summary))
    lines = ["# Descriptive dataset evaluation", "",
             "Comparative acceptance incomplete. Human review/custody is not independently certified by this artifact.", "",
             f"Study: {_cell(value['dataset_id'])}. Cases: {_cell(value['case_count'])}; independent declared ancestry clusters: {_cell(value['independent_ancestry_clusters'])}; gold atoms: {_cell(value['gold_atoms'])}.", ""]

    def methods_table(title: str, names: list[str]) -> None:
        lines.extend([f"## {title}", "", "| Method | Gold atoms | Prediction rows | Omissions | Accusation precision | False accusation rate | False reassurance rate | Unknown appropriateness | Unknown overuse |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"])
        for name in names:
            result = value["methods"][name]
            counts, metrics = result["counts"], result["metrics"]
            cells = [name, counts["gold_atoms"], counts["prediction_rows"], counts["omitted_atoms"],
                     metrics["accusation_precision"], metrics["false_accusation_rate"], metrics["false_reassurance_rate"],
                     metrics["unknown_appropriateness"], metrics["unknown_overuse"]]
            lines.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
        lines.append("")

    methods_table("Equal-packet methods", value["equal_packet_methods"])
    methods_table("Separate full-index utility (privileged source scope)", [value["separate_utility_method"]])
    lines.extend(["## Four-way confusion tables", ""])
    verdicts = ("verified", "partial", "missing", "unknown")
    for method, result in value["methods"].items():
        treatment = "separate utility" if method == value["separate_utility_method"] else "equal packet"
        lines.extend([f"### {_cell(method)} ({treatment})", "",
                      "| Expected / actual | verified | partial | missing | unknown |", "|---|---:|---:|---:|---:|"])
        for expected in verdicts:
            lines.append("| " + " | ".join(_cell(cell) for cell in [expected, *[result["confusion"][expected][actual] for actual in verdicts]]) + " |")
        lines.append("")
    lines.extend(["## All existing metric values", "", "| Treatment | Method | Metric | Value |", "|---|---|---|---:|"])
    for method, result in value["methods"].items():
        treatment = "separate full-index utility" if method == value["separate_utility_method"] else "equal packet"
        for name, number in result["metrics"].items():
            lines.append("| " + " | ".join(_cell(cell) for cell in (treatment, method, name, number)) + " |")
    lines.extend(["", "## Observed attempt summaries", "", "Simulated fixture usage is separate in JSON and is never counted as observed provider usage. No-attempt/unknown measurements remain undefined.", "", "| Method | Attempts | Input tokens | Output tokens | Cost USD | Unknown cost attempts | Median seconds | p95 seconds |", "|---|---:|---:|---:|---:|---:|---:|---:|"])
    for method, result in value["methods"].items():
        usage = result["attempt_summary"] or {}
        cells = [method, usage.get("attempts"), usage.get("input_tokens"), usage.get("output_tokens"), usage.get("cost_usd"),
                 usage.get("unknown_cost_attempts"), usage.get("median_seconds"), usage.get("p95_seconds")]
        lines.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
    lines.extend(["", "## Whole-ancestry intervals", "", "Existing family bootstrap only; intervals are exploratory/inconclusive, not population guarantees.", "", "| Method | Metric | Low | High | Clusters | Resamples | Status |", "|---|---|---:|---:|---:|---:|---|"])
    for method, result in value["methods"].items():
        for name, interval in result["intervals"].items():
            cells = [method, name, interval["low"], interval["high"], interval["families"], interval["resamples"], interval["status"]]
            lines.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
    for label, key in (("Per-family slices", "per_family"), ("Per-kind slices", "per_kind")):
        lines.extend(["", f"## {label}", "", "Slices are nonadditive. Generic case failures remain visible in each relevant diagnostic slice.", "", "| Slice | Method | Gold atoms | Matched atoms | Omissions | Extra predictions | Unknown appropriateness | Unknown overuse |", "|---|---|---:|---:|---:|---:|---:|---:|"])
        for name, methods in value[key].items():
            for method, result in methods.items():
                counts, metrics = result["counts"], result["metrics"]
                cells = [name, method, counts["gold_atoms"], counts["matched_atoms"], counts["omitted_atoms"], counts["extra_predictions"],
                         metrics["unknown_appropriateness"], metrics["unknown_overuse"]]
                lines.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
    lines.extend(["", "## Named item rows", "", "All scorer item rows are retained, including matches, omissions, ambiguous/extra predictions and failure items. JSON preserves original IDs, support relations and predicate partitions.", "", "| Method | Case | Family | Kind | Gold ID | Prediction ID | Status | Expected | Actual | Error |", "|---|---|---|---|---|---|---|---|---|---|"])
    for row in value["items"]:
        item = row["item"]
        cells = [row["method"], row["case_id"], row["family_id"], row["kind"], row["original_gold_id"], row["original_prediction_id"],
                 item["status"], item["expected"], item["actual"], row["error"]]
        lines.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
    lines.extend(["", "## Inconclusive conditions and target observations", "",
                  "The existing scorer's dev-target flag is descriptive. It does not certify actual human/live/heldout or product acceptance.", "",
                  f"Candidate accusation precision not below grep: {_cell(value['candidate_not_below_grep_accusation_precision'])}.", ""])
    for method, state in value["target_states"].items():
        lines.append(f"- {_cell(method)}: existing scorer dev gate {_cell(state['existing_scorer_dev_targets_met'])}; {_cell(state['status'])}.")
        for condition in state["missing_conditions"]:
            lines.append(f"  - {_cell(condition)}")
        if state["undefined_metrics"]:
            lines.append("  - Undefined: " + ", ".join(_cell(name) for name in state["undefined_metrics"]) + ".")
    lines.extend(["", "## Limits", ""])
    lines.extend("- " + _cell(note) for note in value["limitations"])
    return "\n".join(lines) + "\n"
