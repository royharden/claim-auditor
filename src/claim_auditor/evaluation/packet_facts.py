"""One packet-only fact authority; complete admitted files, never hidden retrieval."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from claim_auditor.citations import validate_span
from claim_auditor.contracts import (
    AuditError, EvaluationPacket, Evidence, Limits, Predicate, PredicateResult, ScopeGap,
    Snapshot, Span, canonical_json, sha256, stable_id,
)
from claim_auditor.index import Fact, PARSER_VERSION, _module_from_path, _parser_packet
from claim_auditor.inventory import _sentences
from claim_auditor.inventory.raw import RawDocument
from claim_auditor.patterns import PATTERNS, PATTERN_VERSION

PACKET_FACT_VERSION = "complete-admitted-facts/1"


@dataclass
class PacketFacts:
    """Internal parsed data, not an AuditReport or negative coverage certificate."""

    packet_digest: str
    facts: list[Fact] = field(default_factory=list)
    flags: dict[str, list[str]] = field(default_factory=dict)
    complete_paths: set[str] = field(default_factory=set)
    gaps: list[ScopeGap] = field(default_factory=list)
    assertion_spans: set[tuple[int, int]] = field(default_factory=set)

    def diagnostics(self) -> dict:
        return dict(packet_digest=self.packet_digest, version=PACKET_FACT_VERSION,
                    parser_version=PARSER_VERSION, complete_paths=sorted(self.complete_paths),
                    gaps=[gap.model_dump(mode="json") for gap in self.gaps],
                    flags=self.flags, fact_count=len(self.facts), absence_authority=False)


def _assertion_spans(packet: EvaluationPacket) -> set[tuple[int, int]]:
    """Whole raw assertions, independent of rule-extracted atoms/predicates."""
    from markdown_it import MarkdownIt

    document = RawDocument.decode(packet.readme_text.encode("utf-8"))
    tokens = MarkdownIt("commonmark", {"html": True, "linkify": False, "typographer": False}).parse(document.text)
    result: set[tuple[int, int]] = set()
    for index, token in enumerate(tokens):
        if token.type != "inline" or token.map is None:
            continue
        if index and tokens[index - 1].type == "heading_open":
            continue
        start, end = document.block_bytes(*token.map)
        raw = document.raw[start:end]
        local = RawDocument.decode(raw)
        for first, after in _sentences(local.text):
            result.add((start + local.char_bytes[first], start + local.char_bytes[after]))
    return result


def build_packet_facts(packet: EvaluationPacket) -> PacketFacts:
    """Parse only whole files already fully present in admitted excerpt bytes.

    Reuses the trusted resource-enforced AST/TOML batch parser. This interface
    never receives a snapshot root, reads source, constructs a StaticIndex, or
    emits query coverage. A partial excerpt is recorded as a gap, never parsed
    as an invented module or an empty complete configuration.
    """
    fields = packet.model_dump(mode="json", exclude={"packet_digest"})
    if sha256(canonical_json(fields)) != packet.packet_digest or packet.absence_certificates:
        raise AuditError("packet_integrity_failure", "packet fact input identity/privileges differ", 4)
    if (len(packet.readme_text.encode("utf-8")) > Limits().max_readme_bytes
            or sum(len(e.quote.encode("utf-8")) for e in packet.excerpts) > 48 * 1024
            or any(len(e.quote.encode("utf-8")) > 1024 for e in packet.excerpts)):
        raise AuditError("input_too_large", "packet fact bytes exceed admitted caps")
    result = PacketFacts(packet.packet_digest)
    try:
        result.assertion_spans = _assertion_spans(packet)
    except (ImportError, ValueError, RuntimeError, MemoryError, RecursionError):
        result.gaps.append(ScopeGap(path=packet.readme_path, reason="packet_assertion_context_unavailable"))
    selected: list[dict[str, str]] = []
    originals: dict[str, bytes] = {}
    for entry in packet.scope_entries:
        if not (entry.path.endswith(".py") or entry.path == "pyproject.toml"):
            continue
        excerpts = [e for e in packet.excerpts if e.path == entry.path
                    and e.start_byte == 0 and e.end_byte == entry.size
                    and e.file_sha256 == entry.sha256]
        if entry.status != "included" or len(excerpts) != 1:
            result.gaps.append(ScopeGap(path=entry.path, reason="packet_incomplete_file_context"))
            continue
        raw = excerpts[0].quote.encode("utf-8")
        if len(raw) != entry.size or sha256(raw) != entry.sha256:
            raise AuditError("packet_integrity_failure", "whole-file excerpt digest differs", 4)
        originals[entry.path] = raw
        # Python's tokenizer uses universal newlines. Map the worker's LF-based
        # byte columns back through the authoritative original line-byte table.
        text = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").decode("utf-8") if entry.path.endswith(".py") else excerpts[0].quote
        selected.append(dict(path=entry.path, text=text))
    if not selected:
        return result
    try:
        parsed = _parser_packet(canonical_json(selected))
    except AuditError as exc:
        result.gaps.extend(ScopeGap(path=item["path"], reason=exc.reason) for item in selected)
        return result  # Enforcement unavailable is a recorded gap, no fallback.
    rows = parsed["files"]
    expected = {item["path"]: item["text"].encode("utf-8") for item in selected}
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise AuditError("parser_invalid_output", "packet parser file accounting differs", 3)
    seen: set[str] = set()
    for row in rows:
        if type(row) is not dict or set(row) != {"path", "error", "facts", "flags", "exports"}:
            raise AuditError("parser_invalid_output", "packet parser returned extra fields", 3)
        path = row["path"]
        if type(path) is not str or path not in expected or path in seen:
            raise AuditError("parser_invalid_output", "unexpected/duplicate packet file", 3)
        seen.add(path)
        if row["error"] is not None:
            result.gaps.append(ScopeGap(path=path, reason="packet_source_parse_failure"))
            continue
        if (type(row["facts"]) is not list or type(row["flags"]) is not list
                or not all(type(flag) is str for flag in row["flags"])):
            raise AuditError("parser_invalid_output", "invalid packet fact lists", 3)
        raw = expected[path]
        original = RawDocument.decode(originals[path])
        normalized = RawDocument.decode(raw)
        for value in row["facts"]:
            if (type(value) is not dict or set(value) != set(Fact.__dataclass_fields__)
                    or value["path"] != path
                    or not all(type(value[k]) is int for k in ("start_byte", "end_byte", "start_line", "end_line"))
                    or not 0 <= value["start_byte"] < value["end_byte"] <= len(raw)
                    or not all(type(value[k]) is str for k in ("kind", "subject", "path"))
                    or value["module"] != _module_from_path(path)):
                raise AuditError("parser_invalid_output", "packet fact shape/coordinates differ", 3)
            value = dict(value)
            if path.endswith(".py"):
                first, last = value["start_line"] - 1, value["end_line"] - 1
                if not 0 <= first <= last < len(normalized.line_bytes) - 1:
                    raise AuditError("parser_invalid_output", "packet AST line map escapes admitted bytes", 3)
                first_column = value["start_byte"] - normalized.line_bytes[first]
                last_column = value["end_byte"] - normalized.line_bytes[last]
                if min(first_column, last_column) < 0:
                    raise AuditError("parser_invalid_output", "negative AST byte column", 3)
                value["start_byte"] = original.line_bytes[first] + first_column
                value["end_byte"] = original.line_bytes[last] + last_column
            else:
                value["start_byte"], value["end_byte"] = 0, len(original.raw)
            value["start_line"], value["end_line"] = original.line_bounds(value["start_byte"], value["end_byte"])
            result.facts.append(Fact(**value))
        result.flags[path] = sorted(set(row["flags"]))
        result.complete_paths.add(path)
    return result


def resolve_packet_predicate(packet: EvaluationPacket, facts: PacketFacts, snapshot: Snapshot,
                             root: Path, predicate: Predicate) -> PredicateResult:
    """Return scoped positive/opposite literal proof; absence always stays unknown."""
    def unknown(reason: str) -> PredicateResult:
        return PredicateResult(predicate_id=predicate.predicate_id, state="unknown", reason=reason,
                               evidence=[], coverage=[], complete=False)

    if facts.packet_digest != packet.packet_digest:
        raise AuditError("packet_integrity_failure", "fact set belongs to another packet", 4)
    if predicate.condition or predicate.qualifiers:
        return unknown("packet_unsupported_condition_or_qualifier")
    if predicate.kind == "path_exists":
        path = predicate.path or predicate.subject
        excerpts = [e for e in packet.excerpts if e.path == path]
        if not excerpts:
            return unknown("packet_no_path_excerpt")
        e = excerpts[0]
        chosen = [(Fact("path_exists", path, None, None, path, None, e.start_byte, e.end_byte, 1, 1), "positive")]
    else:
        relevant = [e.path for e in packet.scope_entries
                    if e.path.endswith(".py") or e.path == "pyproject.toml"]
        if predicate.kind in {"metadata_declared", "dependency_declared", "cli_entry_declared"}:
            relevant = [path for path in relevant if path == "pyproject.toml"]
        if predicate.path:
            relevant = [path for path in relevant if path == predicate.path]
        if predicate.module:
            relevant = [path for path in relevant if _module_from_path(path) == predicate.module]
        # An unqualified declaration/literal cannot borrow uniqueness from a
        # partial packet. Require an explicit one-file scope except env's literal
        # existential reference, which may establish only presence.
        if predicate.kind != "env_reference" and len(relevant) != 1:
            return unknown("packet_ambiguous_or_unscoped_namespace")
        if predicate.kind in {"symbol_declared", "bounded_code_fact"} and not (predicate.path or predicate.module):
            return unknown("packet_explicit_namespace_required")
        if predicate.kind == "config_literal" and not predicate.path:
            return unknown("packet_explicit_configuration_required")
        if not relevant or any(path not in facts.complete_paths for path in relevant):
            return unknown("packet_incomplete_file_context")
        # Conservatively hold dynamic, conditional, shadowed and ambiguous files.
        if any(facts.flags.get(path) for path in relevant):
            return unknown("packet_dynamic_or_ambiguous_scope")
        options = [fact for fact in facts.facts if fact.path in relevant and fact.kind == predicate.kind]
        if predicate.kind in {"symbol_declared", "env_reference"}:
            matches = [fact for fact in options if fact.subject == predicate.subject]
        elif predicate.kind in {"config_literal", "metadata_declared", "cli_entry_declared"}:
            matches = [fact for fact in options if fact.key == (predicate.key or predicate.subject)]
        elif predicate.kind == "dependency_declared":
            subject = re.sub(r"[-_.]+", "-", predicate.subject).lower()
            matches = [fact for fact in options if fact.subject == subject]
        elif predicate.kind == "bounded_code_fact" and predicate.pattern in PATTERNS:
            key = predicate.pattern
            if key in {"literal-default/v1", "explicit-raise/v1", "decorator-argument/v1"}:
                if not predicate.key:
                    return unknown("packet_pattern_key_required")
                key += ":" + predicate.key
            matches = [fact for fact in options if fact.subject == predicate.subject and fact.key == key]
        else:
            return unknown("packet_unsupported_semantics")
        if not matches:
            return unknown("packet_no_positive_fact_never_absence")
        if len(matches) != 1:
            return unknown("packet_ambiguous_fact_binding")
        fact = matches[0]
        expects_value = predicate.kind in {"config_literal", "metadata_declared", "cli_entry_declared"}
        expects_value |= predicate.expected is not None and predicate.kind in {"dependency_declared", "bounded_code_fact"}
        expects_value |= predicate.kind == "bounded_code_fact" and predicate.pattern in {
            "literal-default/v1", "literal-constant/v1", "decorator-argument/v1"}
        equal = type(fact.value) is type(predicate.expected) and fact.value == predicate.expected
        # An opposite value can accuse only an exact unique complete binding;
        # never use a mismatching default in another function/module or an absent key.
        chosen = [(fact, "contrary" if expects_value and not equal else "positive")]
    evidence: list[Evidence] = []
    for fact, kind in chosen:
        excerpt = next((e for e in packet.excerpts if e.path == fact.path
                        and e.start_byte <= fact.start_byte <= fact.end_byte <= e.end_byte), None)
        if excerpt is None:
            raise AuditError("unadmitted_evidence_span", "fact escapes admitted packet bytes", 4)
        local = excerpt.quote.encode("utf-8")
        quote = local[fact.start_byte - excerpt.start_byte:fact.end_byte - excerpt.start_byte]
        # Root is passed solely to the citation resolver for exact reopening and
        # display coordinates; no additional bytes enter inference.
        from claim_auditor.snapshot import read_source

        frozen = read_source(snapshot, root, fact.path)
        first_line, last_line = RawDocument.decode(frozen).line_bounds(fact.start_byte, fact.end_byte)
        pointer = Span(snapshot_id=snapshot.snapshot_id, file_sha256=excerpt.file_sha256, path=fact.path,
                       start_byte=fact.start_byte, end_byte=fact.end_byte,
                       start_line=first_line, end_line=last_line,
                       quote=quote.decode("utf-8"), quote_sha256=sha256(quote))
        validate_span(snapshot, root, pointer)
        evidence.append(Evidence(evidence_id=stable_id("packet-fact", PACKET_FACT_VERSION, packet.packet_digest,
                                                       predicate, kind, pointer),
                                 kind=kind, span=pointer, coverage_id=None, query=predicate,
                                 scope_id=snapshot.scope_id, parser_version=PARSER_VERSION,
                                 index_version=PACKET_FACT_VERSION, pattern_version=PATTERN_VERSION))
    state = "contradicted" if evidence[0].kind == "contrary" else "established"
    return PredicateResult(predicate_id=predicate.predicate_id, state=state,
                           reason="packet_exact_binding_opposite_literal" if state == "contradicted" else "packet_scoped_fact",
                           evidence=evidence, coverage=[], complete=True)
