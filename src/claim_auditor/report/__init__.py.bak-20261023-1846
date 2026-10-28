"""Offline report serialization. Untrusted Markdown is never rendered as HTML."""

from __future__ import annotations

import html
import re
from collections import Counter
from pathlib import Path

from claim_auditor.contracts import AuditError, AuditReport, PredictionRow, canonical_json, sha256
from claim_auditor.inventory.raw import safe_display
from claim_auditor.report.demo import create_demo_source


def _fenced(text: str) -> str:
    # A dynamically longer fence prevents source text closing its own code block.
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    delimiter = "`" * max(3, longest + 1)
    return f"{delimiter}text\n{safe_display(text)}\n{delimiter}"


def _summary(report: AuditReport) -> list[tuple[str, str]]:
    counts = Counter(finding.verdict for finding in report.findings)
    return [
        ("Mode", report.mode),
        ("Snapshot", report.snapshot.snapshot_id),
        ("Source kind", report.snapshot.source_kind),
        ("Commit", report.snapshot.commit or "not a Git snapshot"),
        ("Tree identity", report.snapshot.tree_identity),
        ("Manifest digest", report.snapshot.manifest_digest),
        ("Schema", report.schema_version),
        ("Policy", report.policy_version),
        ("Extraction", report.inventory.extraction_version),
        ("Inventory complete", str(report.inventory.complete).lower()),
        ("Snapshot complete", str(report.snapshot.complete).lower()),
        ("Claims", str(len(report.inventory.claims))),
        ("Prose/source blocks", str(len(report.inventory.blocks))),
        *[(verdict, str(counts[verdict])) for verdict in ("verified", "partial", "missing", "unknown")],
        ("Pipeline errors", str(len(report.errors))),
        ("Evaluation", report.evaluation_status),
        ("Runtime validation", "unverified"),
        ("Human-adjudicated evaluation", "not measured"),
        ("Comparative acceptance", "incomplete"),
        ("GitHub Action", "not yet run"),
    ]


def render_markdown(report: AuditReport) -> str:
    lines = ["# Claim Auditor report", "", "Scoped static evidence only. Runtime validation is unverified.", ""]
    for key, value in _summary(report):
        lines.extend([f"{key}:", "", _fenced(value), ""])
    lines += ["", "## Findings", ""]
    evidence_by_id = {item.evidence_id: item for item in report.evidence}
    coverage_by_id = {item.coverage_id: item for item in report.coverage}
    for index, finding in enumerate(report.findings, 1):
        claim = finding.claim
        lines += [f"### {index}. {finding.verdict}", "", _fenced(claim.span.quote), ""]
        details = {
            "claim_id": claim.claim_id, "kind": claim.kind,
            "readme_span": claim.span.model_dump(mode="json"),
            "predicates": [p.model_dump(mode="json") for p in claim.predicates],
            "support_relation": finding.support_relation, "reason": finding.reason,
            "supported_predicates": finding.supported_predicate_ids,
            "unresolved_predicates": finding.unresolved_predicate_ids,
            "complete": finding.complete, "citation_validation": finding.citation_validation,
            "extraction_uncertainty": claim.uncertainty,
        }
        lines += [_fenced(canonical_json(details).decode("utf-8")), ""]
        for evidence_id in finding.evidence_ids:
            item = evidence_by_id.get(evidence_id)
            if item is None:
                raise AuditError("report_reference_missing", "finding references absent evidence", 4)
            lines += [_fenced(canonical_json(item).decode("utf-8")), ""]
            if item.span is not None:
                lines += [_fenced(item.span.quote), ""]
            if item.coverage_id is not None:
                coverage = coverage_by_id.get(item.coverage_id)
                if coverage is None:
                    raise AuditError("report_reference_missing", "negative evidence references absent coverage", 4)
                lines += [_fenced(canonical_json(coverage).decode("utf-8")), ""]
    lines += ["## Extraction coverage", "", "Unsupported and unparsed blocks remain in the denominator.", ""]
    for block in report.inventory.blocks:
        lines += [_fenced(canonical_json(block).decode("utf-8")), ""]
    lines += ["## Scope gaps and pipeline errors", ""]
    for record in [*report.snapshot.exclusions, *report.errors]:
        lines += [_fenced(canonical_json(record).decode("utf-8")), ""]
    return "\n".join(lines) + "\n"


def render_html(report: AuditReport) -> str:
    def escaped(value: object) -> str:
        return html.escape(safe_display(str(value)), quote=True)

    def pre(value: str) -> str:
        return "<pre>" + escaped(value) + "</pre>"

    parts = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<title>Claim Auditor report</title><style>body{font:16px system-ui,sans-serif;margin:2rem auto;padding:0 1rem;max-width:72rem;color:#18212b;background:#f8fafc}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eef2f6;padding:1rem;border-radius:.4rem}article{border-top:1px solid #ccd4dd;padding:1rem 0}dt{font-weight:700}dd{margin-bottom:.6rem;overflow-wrap:anywhere}.notice{padding:1rem;background:#fff3cd}table{border-collapse:collapse}th,td{padding:.4rem;text-align:left;border:1px solid #ccd4dd}</style></head><body>",
        "<h1>Claim Auditor report</h1><p class=\"notice\">Scoped static evidence only. Runtime validation unverified. Human/live comparison not measured. Action not yet run.</p><dl>",
    ]
    for key, value in _summary(report):
        parts.append(f"<dt>{escaped(key)}</dt><dd>{escaped(value)}</dd>")
    parts.append("</dl><h2>Findings</h2>")
    evidence_by_id = {item.evidence_id: item for item in report.evidence}
    coverage_by_id = {item.coverage_id: item for item in report.coverage}
    for index, finding in enumerate(report.findings, 1):
        parts.append(f"<article><h3>{index}. {escaped(finding.verdict)}</h3>")
        parts.append(pre(finding.claim.span.quote))
        parts.append(pre(canonical_json(finding).decode("utf-8")))
        for evidence_id in finding.evidence_ids:
            item = evidence_by_id.get(evidence_id)
            if item is None:
                raise AuditError("report_reference_missing", "finding references absent evidence", 4)
            parts.append(pre(canonical_json(item).decode("utf-8")))
            if item.span is not None:
                parts.append(pre(item.span.quote))
            if item.coverage_id is not None:
                coverage = coverage_by_id.get(item.coverage_id)
                if coverage is None:
                    raise AuditError("report_reference_missing", "coverage reference is absent", 4)
                parts.append(pre(canonical_json(coverage).decode("utf-8")))
        parts.append("</article>")
    parts.append("<h2>Extraction coverage</h2><p>Unsupported and unparsed blocks are retained.</p>")
    for block in report.inventory.blocks:
        parts.append(pre(canonical_json(block).decode("utf-8")))
    parts.append("<h2>Scope gaps and pipeline errors</h2>")
    for record in [*report.snapshot.exclusions, *report.errors]:
        parts.append(pre(canonical_json(record).decode("utf-8")))
    parts.append("</body></html>\n")
    return "".join(parts)


def write_reports(report: AuditReport, out: Path) -> dict[str, str]:
    """Write fixed-name new artifacts; D1 publishes RUN.json only after hashes."""
    if out.is_symlink():
        raise AuditError("unsafe_output", "report output must be an ordinary directory")
    out.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "report.json": canonical_json(report) + b"\n",
        "inventory.json": canonical_json(report.inventory) + b"\n",
        "claims.jsonl": b"".join(canonical_json(row) + b"\n" for row in report.inventory.claims),
        "findings.jsonl": b"".join(canonical_json(row) + b"\n" for row in report.findings),
        "evidence.jsonl": b"".join(canonical_json(row) + b"\n" for row in report.evidence),
        "coverage.jsonl": b"".join(canonical_json(row) + b"\n" for row in report.coverage),
        "predictions.jsonl": b"".join(canonical_json(PredictionRow(prediction_id=finding.claim.claim_id, family_id=report.snapshot.snapshot_id, finding=finding, status="prediction", error=None, accused_predicate_ids=finding.accused_predicate_ids)) + b"\n" for finding in report.findings),
        "report.md": render_markdown(report).encode("utf-8"),
        "report.html": render_html(report).encode("utf-8"),
    }
    hashes: dict[str, str] = {}
    for name, raw in artifacts.items():
        try:
            with (out / name).open("xb") as handle:
                handle.write(raw)
        except FileExistsError as exc:
            raise AuditError("output_exists", f"refusing to overwrite {name}") from exc
        hashes[name] = sha256(raw)
    return hashes


__all__ = ["create_demo_source", "render_html", "render_markdown", "write_reports"]
