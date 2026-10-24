"""Bounded explicit-static grammar over CommonMark blocks and original bytes."""

from __future__ import annotations

import ast
import math
import re
from pathlib import Path
from typing import Iterator

from claim_auditor.contracts import (
    AuditError, Claim, ClaimKind, Inventory, InventoryBlock, Limits, PipelineError,
    Predicate, Snapshot, Span, sha256, stable_id,
)
from claim_auditor.inventory.raw import RawDocument
from claim_auditor.snapshot import read_source

EXTRACTION_VERSION = "explicit-commonmark/1"
_NAME = r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
_END = r"[.!]?\s*$"


def _sentences(text: str) -> Iterator[tuple[int, int]]:
    """Split punctuation outside code spans, retaining exact source coordinates."""
    start = 0
    fence = 0
    i = 0
    while i < len(text):
        if text[i] == "`":
            j = i
            while j < len(text) and text[j] == "`":
                j += 1
            width = j - i
            if fence == 0:
                fence = width
            elif width == fence:
                fence = 0
            i = j
            continue
        if not fence and text[i] in ".!?" and (i + 1 == len(text) or text[i + 1].isspace()):
            end = i + 1
            left = start
            while left < end and text[left].isspace():
                left += 1
            if left < end:
                yield left, end
            start = end
        i += 1
    left = start
    while left < len(text) and text[left].isspace():
        left += 1
    end = len(text.rstrip())
    if left < end:
        yield left, end


def _scalar(text: str) -> str | int | float | bool | None:
    if text in {"true", "false"}:
        return text == "true"
    if text in {"null", "None"}:
        return None
    try:
        value = ast.literal_eval(text)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return text
    if type(value) in {str, int, float, bool, type(None)}:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("nonfinite static literals are not admitted")
        return value
    raise ValueError("only scalar static literals are admitted")


def _unknown_kind(text: str) -> ClaimKind:
    lowered = text.lower()
    if re.search(r"\b(fastest|best|easy|powerful|seamless)\b", lowered):
        return "marketing"
    if re.search(r"\b(requests? per second|uptime|production|latency|throughput|deployed|available 24)\b", lowered):
        return "operational"
    if re.search(r"\b(retries|works|returns|supports|secure|safe|compatible|install|tests? pass|available|raises)\b", lowered):
        return "behavioral"
    return "other"


def _predicate(text: str, imports: dict[str, tuple[str, str] | None]) -> tuple[dict[str, object], list[str]]:
    fields: dict[str, object] = {
        "kind": _unknown_kind(text), "subject": text, "module": None,
        "path": None, "key": None, "expected": None, "negated": False,
        "condition": None, "qualifiers": [], "pattern": None,
    }
    uncertainties: list[str] = []
    # A coordinated or conditional sentence is retained as an unresolved atom.
    # No subject-existence shortcut may verify the stronger whole sentence.
    if re.search(r"\b(?:and|or|unless|provided|when|if)\b", re.sub(r"`[^`]*`", "", text), re.I):
        fields["condition"] = text if re.search(r"\b(?:unless|provided|when|if)\b", text, re.I) else None
        return fields, ["needs_decomposition"]
    clean = re.sub(r"^\s*(?:[-+*]\s+|\d+[.)]\s+|>\s*)", "", text).strip()
    patterns: list[tuple[str, str]] = [
        ("symbol", rf"(?:The )?(?:top-level )?(?:function|class|method|symbol) `(?P<subject>{_NAME})` is (?P<not>not )?declared(?: in module `(?P<module>{_NAME})`)?" + _END),
        ("path", r"(?:The )?(?:file|path) `(?P<path>[^`]+)` (?P<exists>exists|does not exist|is present|is absent)" + _END),
        ("config", r"(?:The )?config key `(?P<key>[^`]+)` equals `(?P<value>[^`]+)`(?: in `(?P<path>pyproject\.toml|[^`]+\.py)`)?" + _END),
        ("dependency", r"(?:The )?dependency `(?P<subject>[A-Za-z0-9][A-Za-z0-9._-]*)`(?: with constraint `(?P<value>[^`]+)`)? is (?P<not>not )?declared" + _END),
        ("metadata", r"(?:The )?project (?P<key>version|license|requires-python) is `(?P<value>[^`]+)`" + _END),
        ("cli", r"(?:The )?CLI entry `(?P<subject>[^`]+)` maps to `(?P<value>[^`]+)`" + _END),
        ("env", r"(?:The )?environment variable `(?P<subject>[A-Za-z_][A-Za-z0-9_]*)` is (?P<not>not )?referenced" + _END),
        ("async", rf"(?:The )?function `(?P<subject>{_NAME})` is declared with `async def`(?: in module `(?P<module>{_NAME})`)?" + _END),
        ("default", rf"(?:The )?function `(?P<subject>{_NAME})` has literal default `(?P<key>[A-Za-z_]\w*)=(?P<value>[^`]+)`(?: in module `(?P<module>{_NAME})`)?" + _END),
        ("constant", rf"(?:The )?constant `(?P<subject>{_NAME})` equals `(?P<value>[^`]+)`(?: in module `(?P<module>{_NAME})`)?" + _END),
        ("raise", rf"(?:The )?function `(?P<subject>{_NAME})` contains an explicit `raise (?P<key>{_NAME})` statement(?: in module `(?P<module>{_NAME})`)?" + _END),
        ("decorator", rf"(?:The )?function `(?P<subject>{_NAME})` has literal decorator argument `(?P<key>{_NAME})=(?P<value>[^`]+)`(?: in module `(?P<module>{_NAME})`)?" + _END),
    ]
    for grammar, pattern in patterns:
        match = re.fullmatch(pattern, clean, re.I if grammar != "cli" else 0)
        if match is None:
            continue
        captures = match.groupdict()
        fields["subject"] = captures.get("subject") or captures.get("path") or captures.get("key") or clean
        fields["module"] = captures.get("module")
        fields["key"] = captures.get("key")
        fields["path"] = captures.get("path")
        fields["negated"] = bool(captures.get("not"))
        if grammar == "symbol":
            fields["kind"] = "symbol_declared"
        elif grammar == "path":
            fields["kind"] = "path_exists"
            fields["negated"] = captures["exists"].lower() in {"does not exist", "is absent"}
        elif grammar == "config":
            fields.update(kind="config_literal", path=captures.get("path") or "pyproject.toml", expected=_scalar(captures["value"]))
        elif grammar == "dependency":
            fields.update(kind="dependency_declared", expected=captures.get("value"))
        elif grammar == "metadata":
            fields.update(kind="metadata_declared", subject="project", path="pyproject.toml", expected=captures["value"])
        elif grammar == "cli":
            fields.update(kind="cli_entry_declared", key=captures["subject"], path="pyproject.toml", expected=captures["value"])
        elif grammar == "env":
            fields.update(kind="env_reference", key=captures["subject"])
        else:
            pattern_names = {"async": "async-def/v1", "default": "literal-default/v1", "constant": "literal-constant/v1", "raise": "explicit-raise/v1", "decorator": "decorator-argument/v1"}
            fields.update(kind="bounded_code_fact", pattern=pattern_names[grammar])
            if captures.get("value") is not None:
                fields["expected"] = _scalar(captures["value"])
        subject = str(fields["subject"])
        if fields["kind"] in {"symbol_declared", "bounded_code_fact"} and fields["module"] is None and subject in imports:
            binding = imports[subject]
            if binding is None:
                uncertainties.append("ambiguous_fence_import")
            else:
                fields["module"], fields["subject"] = binding
                fields["qualifiers"] = ["explicit_fence_import"]
        return fields, uncertainties
    return fields, ["unsupported_semantics"]


def _fence_imports(content: str, imports: dict[str, tuple[str, str] | None]) -> None:
    for line in content.splitlines():
        match = re.fullmatch(rf"\s*from\s+({_NAME})\s+import\s+([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?\s*", line)
        if match is None:
            continue
        module, name, alias = match.groups()
        alias = alias or name
        binding = (module, name)
        if alias in imports and imports[alias] != binding:
            imports[alias] = None
        else:
            imports[alias] = binding


def extract_inventory(snapshot: Snapshot, root: Path, readme: str = "README.md") -> Inventory:
    # A README absent from the snapshot is an input error (2); one excluded at snapshot time is an
    # incomplete audit (3). Only included sources reach read_source, whose failures are integrity (4).
    entry = next((item for item in snapshot.entries if item.path == readme), None)
    if entry is None:
        raise AuditError("readme_not_in_snapshot", readme, 2)
    if entry.status != "included":
        gap = next((item.reason for item in snapshot.exclusions if item.path == readme), entry.status)
        return Inventory(snapshot_id=snapshot.snapshot_id, readme_path=readme, readme_sha256=entry.sha256, claims=[], blocks=[], complete=False, errors=[PipelineError(stage="inventory", reason="readme_excluded", detail=gap)], extraction_version=EXTRACTION_VERSION)
    raw = read_source(snapshot, root, readme)
    limits = Limits()
    errors: list[PipelineError] = []
    claims: list[Claim] = []
    blocks: list[InventoryBlock] = []

    def failed(reason: str, detail: str) -> Inventory:
        return Inventory(snapshot_id=snapshot.snapshot_id, readme_path=readme, readme_sha256=sha256(raw), claims=claims, blocks=blocks, complete=False, errors=[*errors, PipelineError(stage="inventory", reason=reason, detail=detail)], extraction_version=EXTRACTION_VERSION)

    if len(raw) > limits.max_readme_bytes:
        return failed("readme_too_large", "README exceeds admitted byte cap")
    try:
        document = RawDocument.decode(raw)
    except UnicodeDecodeError:
        return failed("unsupported_encoding", "README must be strict UTF-8; raw digest retained")
    if len(document.line_bytes) - 1 > limits.max_lines or any(len(line) > limits.max_line_bytes for line in raw.splitlines()):
        return failed("readme_line_limit", "README line count or byte length exceeds cap")
    try:
        from markdown_it import MarkdownIt

        tokens = MarkdownIt("commonmark", {"html": True, "linkify": False, "typographer": False}).parse(document.text)
    except ImportError:
        return failed("parser_unavailable", "markdown-it-py is required; no fallback extractor was substituted")
    except (ValueError, RuntimeError, RecursionError, MemoryError) as exc:
        return failed("parser_failure", type(exc).__name__)

    def span(start: int, end: int) -> Span:
        quote = raw[start:end].decode("utf-8", errors="strict")
        line_start, line_end = document.line_bounds(start, end)
        return Span(snapshot_id=snapshot.snapshot_id, file_sha256=sha256(raw), path=readme, start_byte=start, end_byte=end, start_line=line_start, end_line=line_end, quote=quote, quote_sha256=sha256(raw[start:end]))

    imports: dict[str, tuple[str, str] | None] = {}
    seen_ranges: set[tuple[int, int]] = set()
    for token_index, token in enumerate(tokens):
        if token.map is None or token.type not in {"inline", "fence", "code_block", "html_block"}:
            continue
        try:
            start, end = document.block_bytes(*token.map)
        except ValueError as exc:
            errors.append(PipelineError(stage="inventory", reason="invalid_block_map", detail=str(exc)))
            continue
        if (start, end) in seen_ranges:
            continue
        seen_ranges.add((start, end))
        block_span = span(start, end)
        block_id = stable_id("block", snapshot.snapshot_id, readme, start, end)
        if token.type != "inline":
            if token.type == "fence" and token.info.strip().lower() in {"python", "py", "python3"}:
                _fence_imports(token.content, imports)
            blocks.append(InventoryBlock(block_id=block_id, block_kind=token.type, span=block_span, claim_ids=[], status="nonassertion", reason="code_or_html_is_not_an_assertion"))
            continue
        is_heading = token_index > 0 and tokens[token_index - 1].type == "heading_open"
        if is_heading and not re.search(r"\b(?:is|has|equals|exists|declares)\b", token.content, re.I):
            blocks.append(InventoryBlock(block_id=block_id, block_kind="heading", span=block_span, claim_ids=[], status="nonassertion", reason="nonassertive_heading_retained"))
            continue
        claim_ids: list[str] = []
        block_text = raw[start:end].decode("utf-8")
        local = RawDocument.decode(raw[start:end])
        for first, after in _sentences(block_text):
            sentence = block_text[first:after]
            if not re.search(r"\w", sentence):
                continue
            if len(claims) >= limits.max_atoms:
                errors.append(PipelineError(stage="inventory", reason="atom_limit", detail="remaining source blocks retained; inventory incomplete"))
                break
            byte_start, byte_end = start + local.char_bytes[first], start + local.char_bytes[after]
            parent = stable_id("sentence", snapshot.snapshot_id, readme, byte_start, byte_end)
            claim_id = stable_id("claim", parent, 0)
            try:
                fields, uncertainty = _predicate(sentence, imports)
            except (ValueError, SyntaxError, RecursionError, MemoryError) as exc:
                fields, uncertainty = _predicate("unsupported source", {})
                fields["subject"] = sentence
                uncertainty = ["invalid_static_literal"]
                errors.append(PipelineError(stage="inventory", reason="literal_parse_failure", detail=type(exc).__name__))
            predicate = Predicate(predicate_id=stable_id("predicate", claim_id, fields), **fields)
            claim = Claim(claim_id=claim_id, parent_id=parent, atom_ordinal=0, kind=predicate.kind, normalized=" ".join(sentence.split()), span=span(byte_start, byte_end), predicates=[predicate], extraction_method="rules", extraction_version=EXTRACTION_VERSION, uncertainty=uncertainty)
            claims.append(claim)
            claim_ids.append(claim_id)
        supported = any(c.kind not in {"other", "behavioral", "operational", "marketing"} for c in claims if c.claim_id in claim_ids)
        status = "unparsed" if not claim_ids else "extracted" if supported else "unsupported"
        blocks.append(InventoryBlock(block_id=block_id, block_kind=token.type, span=block_span, claim_ids=claim_ids, status=status, reason=None if supported else "unsupported_or_nonassertive_prose_retained"))
    # Parser omission must remain visible, including link definitions and blank
    # separators; these raw ranges are inventory coverage, never negative proof.
    covered = sorted(seen_ranges)
    cursor = 0
    for start, end in [*covered, (len(raw), len(raw))]:
        if start > cursor:
            gap = raw[cursor:start]
            nonassertion = not gap.strip()
            blocks.append(InventoryBlock(block_id=stable_id("block", snapshot.snapshot_id, readme, cursor, start), block_kind="raw_gap", span=span(cursor, start), claim_ids=[], status="nonassertion" if nonassertion else "unparsed", reason="blank_separator" if nonassertion else "parser_unmapped_source"))
            if not nonassertion:
                errors.append(PipelineError(stage="inventory", reason="unmapped_prose", detail=f"raw source bytes {cursor}:{start} retained without interpretation"))
        cursor = max(cursor, end)
    blocks.sort(key=lambda item: (item.span.start_byte, item.span.end_byte))
    return Inventory(snapshot_id=snapshot.snapshot_id, readme_path=readme, readme_sha256=sha256(raw), claims=claims, blocks=blocks, complete=not errors, errors=errors, extraction_version=EXTRACTION_VERSION)


__all__ = ["EXTRACTION_VERSION", "extract_inventory"]
