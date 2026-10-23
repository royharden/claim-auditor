"""Independent literal/path baseline restricted to the admitted packet."""

from __future__ import annotations

import re
from pathlib import Path

from claim_auditor.citations import validate_span
from claim_auditor.contracts import (
    AuditError, Claim, EvaluationPacket, Evidence, Finding, PacketBaseline,
    Predicate, PredictionRow, Snapshot, Span, canonical_json, sha256, stable_id,
)
from claim_auditor.inventory.raw import RawDocument

BASELINE_VERSION = "packet-literal-path/1"


def _segments(text: str) -> list[tuple[int, int]]:
    """Independent raw sentence scan; does not call candidate inventory."""
    ranges: list[tuple[int, int]] = []
    cursor = 0
    code_width = 0
    first = 0
    while cursor < len(text):
        if text[cursor] == "`":
            end = cursor + 1
            while end < len(text) and text[end] == "`":
                end += 1
            width = end - cursor
            code_width = width if code_width == 0 else 0 if code_width == width else code_width
            cursor = end
            continue
        boundary = not code_width and ((text[cursor] in ".!?" and (cursor + 1 == len(text) or text[cursor + 1].isspace())) or (text[cursor] == "\n" and (cursor + 1 == len(text) or text[cursor + 1] in "\r\n")))
        if boundary:
            start = first
            end = cursor + 1
            while start < end and text[start].isspace():
                start += 1
            while end > start and text[end - 1].isspace():
                end -= 1
            if start < end:
                ranges.append((start, end))
            first = cursor + 1
        cursor += 1
    start = first
    while start < len(text) and text[start].isspace():
        start += 1
    end = len(text.rstrip())
    if start < end:
        ranges.append((start, end))
    return ranges


def run_packet_grep(packet: EvaluationPacket, snapshot: Snapshot, root: Path) -> PacketBaseline:
    """Only exact path presence with an admitted, reopened excerpt is decided."""
    if sha256(canonical_json(packet.model_dump(mode="json", exclude={"packet_digest"}))) != packet.packet_digest:
        raise AuditError("packet_integrity_failure", "packet digest does not reopen", 4)
    if packet.snapshot_id != snapshot.snapshot_id or packet.snapshot_manifest_digest != snapshot.manifest_digest:
        raise AuditError("packet_snapshot_mismatch", "baseline packet identity differs from snapshot", 4)
    if canonical_json(packet.scope_entries) != canonical_json(snapshot.entries):
        raise AuditError("packet_scope_mismatch", "packet metadata differs from frozen scope", 4)
    raw = packet.readme_text.encode("utf-8")
    if sha256(raw) != packet.readme_sha256:
        raise AuditError("packet_integrity_failure", "packet README digest differs", 4)
    document = RawDocument.decode(raw)
    evidence: list[Evidence] = []
    predictions: list[PredictionRow] = []
    available = {entry.path: entry for entry in packet.scope_entries if entry.status == "included"}
    code_ranges: list[tuple[int, int]] = []
    offset = 0
    fence_start: int | None = None
    fence_marker = ""
    for line in document.text.splitlines(keepends=True):
        match = re.match(r" {0,3}(`{3,}|~{3,})", line)
        if match:
            marker = match.group(1)
            if fence_start is None:
                fence_start, fence_marker = offset, marker
            elif marker[0] == fence_marker[0] and len(marker) >= len(fence_marker):
                code_ranges.append((fence_start, offset + len(line)))
                fence_start = None
        offset += len(line)
    if fence_start is not None:
        code_ranges.append((fence_start, len(document.text)))
    for first, end in _segments(document.text):
        if any(first < stop and end > start for start, stop in code_ranges):
            continue
        quote = document.text[first:end]
        # Nonassertive headings and fenced examples are not propositions.
        if quote.lstrip().startswith("#") and not re.search(r"\b(is|exists|has)\b", quote):
            continue
        start_byte, end_byte = document.char_bytes[first], document.char_bytes[end]
        line_start, line_end = document.line_bounds(start_byte, end_byte)
        span = Span(snapshot_id=packet.snapshot_id, file_sha256=packet.readme_sha256, path=packet.readme_path, start_byte=start_byte, end_byte=end_byte, start_line=line_start, end_line=line_end, quote=quote, quote_sha256=sha256(raw[start_byte:end_byte]))
        validate_span(snapshot, root, span)
        parent = stable_id("sentence", snapshot.snapshot_id, packet.readme_path, start_byte, end_byte)
        claim_id = stable_id("claim", parent, 0)
        path_match = re.fullmatch(r"(?:The )?(?:file|path) `([^`]+)` (exists|does not exist|is present|is absent)[.!]?", quote.strip(), re.I)
        symbol_match = re.fullmatch(r"(?:The )?(?:top-level )?(?:function|class|method|symbol) `([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)` is (not )?declared(?: in module `([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)`)?[.!]?", quote.strip(), re.I)
        kind = "path_exists" if path_match else "symbol_declared" if symbol_match else "operational" if re.search(r"requests? per second|uptime|production|latency|throughput", quote, re.I) else "other"
        path = path_match.group(1) if path_match else None
        negated = path_match.group(2).lower() in {"does not exist", "is absent"} if path_match else bool(symbol_match.group(2)) if symbol_match else False
        fields = dict(kind=kind, subject=path if path_match else symbol_match.group(1) if symbol_match else quote, module=symbol_match.group(3) if symbol_match else None, path=path, key=None, expected=None, negated=negated, condition=None, qualifiers=[], pattern=None)
        predicate = Predicate(predicate_id=stable_id("predicate", claim_id, fields), **fields)
        claim = Claim(claim_id=claim_id, parent_id=parent, atom_ordinal=0, kind=kind, normalized=" ".join(quote.split()), span=span, predicates=[predicate], extraction_method="rules", extraction_version=BASELINE_VERSION, uncertainty=[] if path_match or symbol_match else ["unsupported_semantics"])
        selected = next((excerpt for excerpt in packet.excerpts if excerpt.path == path), None) if path is not None else None
        found = False
        selected_evidence: list[str] = []
        if path_match and not negated and path in available and selected is not None:
            entry = available[path]
            if selected.file_sha256 != entry.sha256 or selected.end_byte - selected.start_byte != len(selected.quote.encode("utf-8")):
                raise AuditError("packet_integrity_failure", "admitted excerpt metadata differs from scope", 4)
            # Display lines are calculated from the admitted excerpt offset only
            # after the sole resolver reopens it; full-file bytes are used for
            # integrity, never as hidden inference evidence.
            from claim_auditor.snapshot import read_source

            frozen = read_source(snapshot, root, path)
            lines = RawDocument.decode(frozen).line_bounds(selected.start_byte, selected.end_byte)
            pointer = Span(snapshot_id=snapshot.snapshot_id, file_sha256=entry.sha256, path=path, start_byte=selected.start_byte, end_byte=selected.end_byte, start_line=lines[0], end_line=lines[1], quote=selected.quote, quote_sha256=sha256(selected.quote.encode("utf-8")))
            validate_span(snapshot, root, pointer)
            item = Evidence(evidence_id=stable_id("baseline-evidence", packet.packet_digest, predicate.predicate_id, path), kind="positive", span=pointer, coverage_id=None, query=predicate, scope_id=snapshot.scope_id, parser_version="literal-path/1", index_version=BASELINE_VERSION, pattern_version="none")
            evidence.append(item)
            selected_evidence.append(item.evidence_id)
            found = True
        finding = Finding(claim=claim, verdict="verified" if found else "unknown", support_relation="supports" if found else "no_evidence", reason="admitted_path_excerpt" if found else "packet_baseline_no_complete_proof", supported_predicate_ids=[predicate.predicate_id] if found else [], unresolved_predicate_ids=[] if found else [predicate.predicate_id], accused_predicate_ids=[], evidence_ids=selected_evidence, complete=found, citation_validation="valid" if found else "not_applicable", model_proposal=None)
        predictions.append(PredictionRow(prediction_id=claim.claim_id, family_id=snapshot.snapshot_id, finding=finding, status="prediction", error=None, accused_predicate_ids=[]))
    return PacketBaseline(mode="packet_grep", packet_digest=packet.packet_digest, predictions=predictions, evidence=evidence, limitations=[
        "Independent literal/path baseline uses only packet README, scope metadata and admitted excerpts.",
        "Only positive exact path presence with an admitted reopened excerpt is verified; symbol/negated/absent/behavioral propositions remain unknown without a complete supported proof.",
        "A missing grep token is never a missing verdict. This baseline emits no negative coverage certificates.",
        "No provider was called by this method; running this source still requires normal-mode activation and checks.",
    ])
