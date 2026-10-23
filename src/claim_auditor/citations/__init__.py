"""Sole byte/coverage resolver. No generic URL or current-checkout fallback."""

from __future__ import annotations

from pathlib import Path

from claim_auditor.contracts import (
    AuditError, AuditReport, CoverageReport, Evidence, PredictionRow, RunManifest, Snapshot, Span,
    canonical_json, sha256,
)
from claim_auditor.index import INDEX_VERSION, PARSER_VERSION, StaticIndex, build_index, resolve
from claim_auditor.patterns import PATTERN_VERSION
from claim_auditor.snapshot import load_snapshot, read_source
from claim_auditor.snapshot.safeio import read_ordinary, validated_path


def validate_span(snapshot: Snapshot, root: Path, span: Span) -> None:
    """Reopen exact raw UTF-8 bytes and both byte/line coordinate systems."""
    if span.snapshot_id != snapshot.snapshot_id:
        raise AuditError("citation_snapshot_mismatch", span.path, 4)
    entry = next((entry for entry in snapshot.entries if entry.path == span.path and entry.status == "included"), None)
    if entry is None or span.file_sha256 != entry.sha256:
        raise AuditError("citation_file_identity", span.path, 4)
    raw = read_source(snapshot, root, span.path)
    if not (0 <= span.start_byte <= span.end_byte <= len(raw)):
        raise AuditError("citation_byte_bounds", span.path, 4)
    quoted = raw[span.start_byte:span.end_byte]
    try:
        text = quoted.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise AuditError("citation_utf8_boundary", span.path, 4) from error
    start_line = raw[:span.start_byte].count(b"\n") + 1
    end_line = raw[:max(span.start_byte, span.end_byte - 1)].count(b"\n") + 1
    if (text != span.quote or sha256(quoted) != span.quote_sha256 or
            start_line != span.start_line or end_line != span.end_line):
        raise AuditError("citation_quote_or_lines", span.path, 4)


def validate_coverage(snapshot: Snapshot, coverage: CoverageReport, index: StaticIndex) -> None:
    if snapshot.snapshot_id != index.snapshot.snapshot_id or snapshot.manifest_digest != index.snapshot.manifest_digest:
        raise AuditError("coverage_index_identity", coverage.coverage_id, 4)
    if coverage.snapshot_id != snapshot.snapshot_id or coverage.scope_id != snapshot.scope_id:
        raise AuditError("coverage_snapshot_identity", coverage.coverage_id, 4)
    if (coverage.parser_version, coverage.index_version, coverage.pattern_version) != (PARSER_VERSION, INDEX_VERSION, PATTERN_VERSION):
        raise AuditError("coverage_version", coverage.coverage_id, 4)
    payload = coverage.model_dump(mode="json")
    payload.pop("artifact_digest")
    if sha256(canonical_json(payload)) != coverage.artifact_digest:
        raise AuditError("coverage_digest", coverage.coverage_id, 4)
    for entry in coverage.examined_files:
        raw = read_source(snapshot, index.root, entry.path)
        if len(raw) != entry.size or sha256(raw) != entry.sha256:
            raise AuditError("coverage_source_identity", entry.path, 4)
    replayed = resolve(index, coverage.query)
    expected = next((item for item in replayed.coverage if item.coverage_id == coverage.coverage_id), None)
    if expected is None or expected != coverage:
        raise AuditError("coverage_replay_mismatch", coverage.coverage_id, 4)


def validate_evidence(snapshot: Snapshot, root: Path, evidence: Evidence,
                      coverage: list[CoverageReport], index: StaticIndex) -> None:
    """Validate positive/contrary spans and reproduce all negative certificates."""
    if evidence.scope_id != snapshot.scope_id:
        raise AuditError("evidence_scope_identity", evidence.evidence_id, 4)
    if (evidence.parser_version, evidence.index_version, evidence.pattern_version) != (PARSER_VERSION, INDEX_VERSION, PATTERN_VERSION):
        raise AuditError("evidence_version", evidence.evidence_id, 4)
    if evidence.span is not None:
        validate_span(snapshot, root, evidence.span)
    if evidence.kind == "negative":
        matches = [item for item in coverage if item.coverage_id == evidence.coverage_id]
        if len(matches) != 1:
            raise AuditError("negative_coverage_missing_or_duplicate", evidence.evidence_id, 4)
        certificate = matches[0]
        validate_coverage(snapshot, certificate, index)
        if not certificate.complete or certificate.matched_count != 0 or certificate.query != evidence.query:
            raise AuditError("negative_coverage_not_exhaustive", evidence.evidence_id, 4)
    expected = resolve(index, evidence.query)
    if evidence not in expected.evidence:
        raise AuditError("evidence_query_replay_mismatch", evidence.evidence_id, 4)


def verify_report(run_root: Path) -> RunManifest:
    """Reopen a completed offline report and every cited frozen artifact.

    Integrity verification does not certify semantic quality or product readiness.
    The static index is reconstructed under the same enforced parser bounds.
    """
    root = Path(run_root)
    try:
        manifest = RunManifest.model_validate_json(read_ordinary(root, "RUN.json", 4 * 1024 * 1024))
        if manifest.state != "complete":
            code = 4 if manifest.state == "failed_integrity" else 3
            raise AuditError("run_not_complete", manifest.state, code)
        if manifest.completed_at is None or manifest.errors:
            raise AuditError("invalid_completed_run", manifest.run_id, 4)
        required = {"report.json", "inventory.json", "claims.jsonl", "findings.jsonl", "evidence.jsonl", "coverage.jsonl", "predictions.jsonl", "report.md", "report.html"}
        if not required.issubset(manifest.report_hashes):
            raise AuditError("missing_report_artifact", ",".join(sorted(required - set(manifest.report_hashes))), 4)
        for name, digest in manifest.report_hashes.items():
            validated_path(name)
            if name == "RUN.json" or name.startswith("snapshot/"):
                raise AuditError("invalid_report_hash_scope", name, 4)
            raw = read_ordinary(root, name, 64 * 1024 * 1024)
            if sha256(raw) != digest:
                raise AuditError("report_artifact_digest", name, 4)
        snapshot_root = root / "snapshot"
        snapshot = load_snapshot(snapshot_root)
        report = AuditReport.model_validate_json(read_ordinary(root, "report.json", 64 * 1024 * 1024))
        if report.snapshot != snapshot or manifest.snapshot_id != snapshot.snapshot_id or manifest.snapshot_manifest_digest != snapshot.manifest_digest:
            raise AuditError("report_snapshot_identity", manifest.run_id, 4)
        if report.mode != manifest.mode or report.errors or report.inventory.errors or not report.inventory.complete:
            raise AuditError("report_completion_identity", manifest.run_id, 4)
        if report.inventory.snapshot_id != snapshot.snapshot_id:
            raise AuditError("inventory_snapshot_identity", manifest.run_id, 4)
        readme = read_source(snapshot, snapshot_root, report.inventory.readme_path)
        if sha256(readme) != report.inventory.readme_sha256:
            raise AuditError("inventory_readme_digest", manifest.run_id, 4)
        claims = {claim.claim_id: claim for claim in report.inventory.claims}
        if len(claims) != len(report.inventory.claims):
            raise AuditError("duplicate_claim_identity", manifest.run_id, 4)
        for claim in report.inventory.claims:
            validate_span(snapshot, snapshot_root, claim.span)
        for block in report.inventory.blocks:
            validate_span(snapshot, snapshot_root, block.span)
            if any(claim_id not in claims for claim_id in block.claim_ids):
                raise AuditError("block_unknown_claim", block.block_id, 4)
        index = build_index(snapshot, snapshot_root)
        if index.errors:
            raise AuditError("report_replay_parser_error", manifest.run_id, 4)
        coverage = {item.coverage_id: item for item in report.coverage}
        evidence = {item.evidence_id: item for item in report.evidence}
        if len(coverage) != len(report.coverage) or len(evidence) != len(report.evidence):
            raise AuditError("duplicate_evidence_identity", manifest.run_id, 4)
        for item in report.coverage:
            validate_coverage(snapshot, item, index)
        for item in report.evidence:
            validate_evidence(snapshot, snapshot_root, item, report.coverage, index)
        seen: set[str] = set()
        from claim_auditor.audit.policy import decide_finding
        for finding in report.findings:
            claim_id = finding.claim.claim_id
            if claim_id in seen or claim_id not in claims or finding.claim != claims[claim_id]:
                raise AuditError("finding_claim_identity", claim_id, 4)
            seen.add(claim_id)
            predicates = {predicate.predicate_id for predicate in finding.claim.predicates}
            if (set(finding.supported_predicate_ids) | set(finding.unresolved_predicate_ids)) - predicates:
                raise AuditError("finding_predicate_identity", claim_id, 4)
            if set(finding.accused_predicate_ids) - predicates:
                raise AuditError("finding_accusation_identity", claim_id, 4)
            if finding.citation_validation == "failed" or any(item not in evidence for item in finding.evidence_ids):
                raise AuditError("finding_invalid_active_citation", claim_id, 4)
            for item in finding.evidence_ids:
                if evidence[item].query.predicate_id not in predicates:
                    raise AuditError("finding_foreign_evidence", claim_id, 4)
            if finding.verdict in {"verified", "partial", "missing"} and not finding.evidence_ids:
                raise AuditError("finding_supported_without_evidence", claim_id, 4)
            resolved = [resolve(index, predicate) for predicate in finding.claim.predicates]
            expected = decide_finding(finding.claim, resolved, citation_valid=True,
                                      model_proposal=finding.model_proposal)
            if expected != finding:
                raise AuditError("finding_policy_replay_mismatch", claim_id, 4)
        if seen != set(claims):
            raise AuditError("finding_accounting_gap", manifest.run_id, 4)
        _verify_duplicate_artifacts(root, report)
        return manifest
    except AuditError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise AuditError("report_integrity", str(error), 4) from error


def _verify_duplicate_artifacts(root: Path, report: AuditReport) -> None:
    expected = {
        "claims.jsonl": report.inventory.claims,
        "findings.jsonl": report.findings,
        "evidence.jsonl": report.evidence,
        "coverage.jsonl": report.coverage,
    }
    for name, rows in expected.items():
        raw = read_ordinary(root, name, 64 * 1024 * 1024)
        body = b"".join(canonical_json(row) + b"\n" for row in rows)
        if raw != body:
            raise AuditError("report_duplicate_artifact_mismatch", name, 4)
    inventory = read_ordinary(root, "inventory.json", 64 * 1024 * 1024).rstrip(b"\n")
    if inventory != canonical_json(report.inventory):
        raise AuditError("report_duplicate_artifact_mismatch", "inventory.json", 4)
    predictions = b"".join(canonical_json(PredictionRow(
        prediction_id=finding.claim.claim_id, family_id=report.snapshot.snapshot_id,
        finding=finding, status="prediction", error=None,
        accused_predicate_ids=finding.accused_predicate_ids,
    )) + b"\n" for finding in report.findings)
    if read_ordinary(root, "predictions.jsonl", 64 * 1024 * 1024) != predictions:
        raise AuditError("report_duplicate_artifact_mismatch", "predictions.jsonl", 4)


def s5_adapter(verdict: str) -> str:
    """Outbound S5 vocabulary is an integrity transport, never M2 verdict authority."""
    return "partial" if verdict in {"verified", "partial"} else "unsupported"


__all__ = ["validate_span", "validate_coverage", "validate_evidence", "verify_report", "s5_adapter"]
