"""Bounded syntax facts and reproducible query coverage, never target imports."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import subprocess
import sys
import threading

from claim_auditor.contracts import (
    AuditError, CoverageReport, Evidence, PipelineError, Predicate, PredicateResult,
    ScopeGap, Snapshot, SnapshotEntry, Span, canonical_json, sha256, stable_id,
)
from claim_auditor.patterns import PATTERNS, PATTERN_VERSION
from claim_auditor.snapshot import read_source

PARSER_VERSION = f"python-ast-tomllib/1-python{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
INDEX_VERSION = "bounded-index/1"
NORMALIZATION = "exact-path-symbol-pep503-distribution/1"


@dataclass(frozen=True)
class Fact:
    kind: str
    subject: str
    key: str | None
    value: str | int | float | bool | None
    path: str
    module: str | None
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int


@dataclass
class StaticIndex:
    snapshot: Snapshot
    root: Path
    facts: list[Fact] = field(default_factory=list)
    parse_failures: list[ScopeGap] = field(default_factory=list)
    dynamic_flags: list[str] = field(default_factory=list)
    errors: list[PipelineError] = field(default_factory=list)
    parsed_paths: list[str] = field(default_factory=list)
    exports: dict[str, dict[str, tuple[str, str]]] = field(default_factory=dict)


def _parser_packet(packet: bytes) -> dict[str, object]:
    worker = Path(__file__).with_name("_worker.py").resolve()
    # Isolated Python ignores target PYTHONPATH, cwd import shadowing and user site.
    process = subprocess.Popen([sys.executable, "-I", str(worker)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=worker.parent,
                               shell=False)
    chunks: list[bytes] = []
    diagnostics: list[bytes] = []
    overflow = threading.Event()

    def drain(pipe: object, destination: list[bytes], cap: int) -> None:
        total = 0
        try:
            while True:
                chunk = pipe.read(64 * 1024)  # type: ignore[attr-defined]
                if not chunk:
                    return
                total += len(chunk)
                if total > cap:
                    overflow.set()
                    process.kill()
                    return
                destination.append(chunk)
        finally:
            pipe.close()  # type: ignore[attr-defined]

    readers = [threading.Thread(target=drain, args=(process.stdout, chunks, 32 * 1024 * 1024), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, diagnostics, 64 * 1024), daemon=True)]
    for reader in readers:
        reader.start()
    try:
        assert process.stdin is not None
        # A writer thread prevents a worker/setup failure from blocking the parent
        # on a large stdin write outside the wall-clock watchdog.
        def write() -> None:
            try:
                assert process.stdin is not None
                process.stdin.write(packet)
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        writer = threading.Thread(target=write, daemon=True)
        writer.start()
        process.wait(timeout=30)
        writer.join(timeout=2)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        raise AuditError("parser_timeout", "isolated batch exceeded 30 seconds", 3) from error
    finally:
        for reader in readers:
            reader.join(timeout=2)
    if overflow.is_set() or any(reader.is_alive() for reader in readers):
        raise AuditError("parser_output_limit", "bounded worker output exceeded", 3)
    if process.returncode != 0:
        raise AuditError("parser_failure", b"".join(diagnostics).decode("utf-8", "replace")[:500], 3)
    try:
        value = json.loads(b"".join(chunks))
    except (ValueError, UnicodeDecodeError) as error:
        raise AuditError("parser_invalid_output", "worker did not return a closed packet", 3) from error
    if type(value) is not dict or set(value) != {"enforced", "error", "files"} or type(value["enforced"]) is not bool:
        raise AuditError("parser_invalid_output", "invalid worker envelope", 3)
    if not value["enforced"]:
        raise AuditError("parser_enforcement_unavailable", str(value["error"]), 2)
    if value["error"] is not None or type(value["files"]) is not list:
        raise AuditError("parser_invalid_output", "invalid worker body", 3)
    return value


def build_index(snapshot: Snapshot, root: Path) -> StaticIndex:
    index = StaticIndex(snapshot=snapshot, root=Path(root))
    selected = [entry for entry in snapshot.entries if entry.status == "included" and
                (entry.path.endswith(".py") or entry.path == "pyproject.toml")]
    packet = canonical_json([dict(path=entry.path, text=read_source(snapshot, root, entry.path).decode("utf-8")) for entry in selected])
    try:
        result = _parser_packet(packet)
    except AuditError as error:
        if error.exit_code == 2:
            raise  # No unbounded fallback on platforms without enforced limits.
        index.errors.append(PipelineError(stage="index", reason=error.reason, detail=error.detail))
        index.parse_failures.extend(ScopeGap(path=entry.path, reason=error.reason) for entry in selected)
        return index
    rows = result["files"]
    if not isinstance(rows, list) or len(rows) != len(selected):
        raise AuditError("parser_invalid_output", "file accounting mismatch", 3)
    expected_paths = {entry.path for entry in selected}
    seen: set[str] = set()
    fact_fields = set(Fact.__dataclass_fields__)
    for row in rows:
        if type(row) is not dict or set(row) != {"path", "error", "facts", "flags", "exports"}:
            raise AuditError("parser_invalid_output", "invalid file envelope", 3)
        path = row["path"]
        if type(path) is not str or path not in expected_paths or path in seen:
            raise AuditError("parser_invalid_output", "unexpected or duplicate file", 3)
        seen.add(path)
        if row["error"] is not None:
            index.parse_failures.append(ScopeGap(path=path, reason=str(row["error"])))
            index.errors.append(PipelineError(stage="index", reason="source_parse_failure", detail=f"{path}: {row['error']}"))
            continue
        if type(row["facts"]) is not list or type(row["flags"]) is not list or type(row["exports"]) is not dict:
            raise AuditError("parser_invalid_output", "invalid facts or flags", 3)
        for fact in row["facts"]:
            if type(fact) is not dict or set(fact) != fact_fields or fact["path"] != path:
                raise AuditError("parser_invalid_output", "unexpected fact fields", 3)
            if not all(type(fact[key]) is int for key in ("start_byte", "end_byte", "start_line", "end_line")):
                raise AuditError("parser_invalid_output", "invalid byte coordinates", 3)
            index.facts.append(Fact(**fact))
        if not all(type(flag) is str for flag in row["flags"]):
            raise AuditError("parser_invalid_output", "invalid scope flags", 3)
        index.dynamic_flags.extend(f"{path}:{flag}" for flag in row["flags"])
        index.exports[path] = {str(name): tuple(target) for name, target in row["exports"].items()
                               if type(target) is list and len(target) == 2 and all(type(item) is str for item in target)}
        index.parsed_paths.append(path)
    index.dynamic_flags.sort()
    index.facts.sort(key=lambda fact: (fact.path, fact.start_byte, fact.kind, fact.subject, fact.key or ""))
    return index


def _span(index: StaticIndex, fact: Fact) -> Span:
    raw = read_source(index.snapshot, index.root, fact.path)
    quote = raw[fact.start_byte:fact.end_byte].decode("utf-8", "strict")
    entry = next(entry for entry in index.snapshot.entries if entry.path == fact.path)
    return Span(snapshot_id=index.snapshot.snapshot_id, file_sha256=entry.sha256, path=fact.path,
                start_byte=fact.start_byte, end_byte=fact.end_byte, start_line=fact.start_line,
                end_line=fact.end_line, quote=quote, quote_sha256=sha256(quote.encode("utf-8")))


def _coverage(index: StaticIndex, predicate: Predicate, matches: int, complete: bool,
              relevant: list[SnapshotEntry], flags: list[str], near: list[str]) -> CoverageReport:
    body = dict(
        coverage_id=stable_id("coverage", index.snapshot.snapshot_id, predicate.model_dump(mode="json")),
        snapshot_id=index.snapshot.snapshot_id, scope_id=index.snapshot.scope_id, query=predicate,
        normalization=NORMALIZATION, examined_files=relevant,
        parse_failures=index.parse_failures, exclusions=index.snapshot.exclusions,
        dynamic_flags=sorted(flags), matched_count=matches, near_misses=sorted(set(near)), complete=complete,
        parser_version=PARSER_VERSION, index_version=INDEX_VERSION, pattern_version=PATTERN_VERSION,
        artifact_digest="0" * 64,
    )
    provisional = CoverageReport(**body)
    payload = provisional.model_dump(mode="json")
    payload.pop("artifact_digest")
    body["artifact_digest"] = sha256(canonical_json(payload))
    return CoverageReport(**body)


def _evidence(index: StaticIndex, query: Predicate, kind: str, fact: Fact | None,
              coverage: CoverageReport | None) -> Evidence:
    span = _span(index, fact) if fact else None
    coverage_id = coverage.coverage_id if coverage else None
    return Evidence(
        evidence_id=stable_id("evidence", query.model_dump(mode="json"), kind,
                              span.model_dump(mode="json") if span else coverage_id),
        kind=kind, span=span, coverage_id=coverage_id, query=query,
        scope_id=index.snapshot.scope_id, parser_version=PARSER_VERSION,
        index_version=INDEX_VERSION, pattern_version=PATTERN_VERSION,
    )


def resolve(index: StaticIndex, predicate: Predicate) -> PredicateResult:
    """Resolve the positive proposition only; policy owns negation/reduction."""
    facts = index.facts
    relevant = [entry for entry in index.snapshot.entries if entry.status == "included"]
    flags = list(index.dynamic_flags)
    complete = index.snapshot.complete and not index.parse_failures
    unknown: str | None = None
    candidates: list[Fact] = []
    contrary: list[Fact] = []
    near: list[str] = []
    if predicate.condition or any(qualifier != "explicit_fence_import" for qualifier in predicate.qualifiers):
        unknown = "unsupported_condition_or_qualifier"
    if predicate.kind in {"behavioral", "operational", "marketing", "other"}:
        unknown = "unsupported_semantics"
    if predicate.kind == "path_exists":
        path = predicate.path or predicate.subject
        from claim_auditor.snapshot.safeio import validated_path
        try:
            validated_path(path)
        except ValueError:
            unknown = "invalid_path_claim"
        entry = next((entry for entry in index.snapshot.entries if entry.path == path), None)
        if entry is not None and entry.status == "included":
            raw = read_source(index.snapshot, index.root, path)
            # Empty file existence is still a real, zero-byte, digest-bound span.
            candidates = [Fact("path_exists", path, None, None, path, None, 0, min(len(raw), len(raw.splitlines(keepends=True)[0]) if raw else 0), 1, 1)]
        elif entry is not None or any(gap.path and (path == gap.path or path.startswith(gap.path + "/")) for gap in index.snapshot.exclusions):
            unknown = "path_content_unavailable"
        near = [entry.path for entry in index.snapshot.entries if entry.path.casefold() == path.casefold() and entry.path != path]
    else:
        relevant = [entry for entry in relevant if entry.path.endswith(".py") or entry.path == "pyproject.toml"]
        if predicate.path:
            facts = [fact for fact in facts if fact.path == predicate.path]
            relevant = [entry for entry in relevant if entry.path == predicate.path]
        if predicate.module:
            facts = [fact for fact in facts if fact.module == predicate.module]
            relevant = [entry for entry in relevant if _module_from_path(entry.path) == predicate.module]
        if predicate.kind in {"dependency_declared", "metadata_declared", "cli_entry_declared"}:
            facts = [fact for fact in facts if fact.path == "pyproject.toml"]
            relevant = [entry for entry in relevant if entry.path == "pyproject.toml"]
            if not relevant:
                # Complete tracked inventory can establish no static declaration.
                complete = complete and not any(gap.path == "pyproject.toml" for gap in index.snapshot.exclusions)
        if predicate.kind == "symbol_declared":
            candidates = [fact for fact in facts if fact.kind == predicate.kind and fact.subject == predicate.subject]
            if not candidates and predicate.module:
                candidates = _one_hop_export(index, predicate)
            near = [fact.subject for fact in facts if fact.kind == predicate.kind and fact.subject.casefold() == predicate.subject.casefold()
                    and fact.subject != predicate.subject]
            if len(candidates) > 1:
                unknown = "ambiguous_declaration"
            if not predicate.module and not predicate.path and not complete:
                unknown = "incomplete_unqualified_resolution"
            scoped_flags = _flags_for(index, relevant)
            if any(flag.endswith(f"shadowed:{predicate.subject}") or flag.endswith(f"shadowed:{predicate.subject.split('.')[0]}") for flag in scoped_flags):
                unknown = "shadowed_declaration"
            if any(f"conditional_class_bindings:{predicate.subject.split('.')[0]}" in flag for flag in scoped_flags):
                complete = False
                if not candidates:
                    unknown = "conditional_class_scope"
            if any("dynamic_namespace" in flag or "conditional_module_bindings" in flag or "wildcard_import" in flag for flag in scoped_flags):
                complete = False
                if not candidates:
                    unknown = "dynamic_or_conditional_scope"
        elif predicate.kind == "config_literal":
            key = predicate.key or predicate.subject
            matches = [fact for fact in facts if fact.kind == predicate.kind and fact.key == key]
            candidates = [fact for fact in matches if _equal(fact.value, predicate.expected)]
            contrary = [fact for fact in matches if not _equal(fact.value, predicate.expected)]
            if len(matches) > 1:
                unknown = "ambiguous_literal_binding"
            if any(f"dynamic_assignment:{key}" in flag or "dynamic_namespace" in flag or "conditional_module_bindings" in flag for flag in _flags_for(index, relevant)):
                complete = False
                if not candidates and not contrary:
                    unknown = "dynamic_literal_binding"
        elif predicate.kind == "dependency_declared":
            subject = re.sub(r"[-_.]+", "-", predicate.subject).lower()
            matches = [fact for fact in facts if fact.kind == predicate.kind and fact.subject == subject]
            candidates = [fact for fact in matches if predicate.expected is None or _equal(fact.value, predicate.expected)]
            contrary = [fact for fact in matches if predicate.expected is not None and not _equal(fact.value, predicate.expected)]
            if any("dynamic_metadata:dependencies" in flag or "invalid_dependency_literal" in flag for flag in flags):
                complete = False
                unknown = "dynamic_dependencies"
        elif predicate.kind in {"metadata_declared", "cli_entry_declared"}:
            key = predicate.key or predicate.subject
            matches = [fact for fact in facts if fact.kind == predicate.kind and fact.key == key]
            candidates = [fact for fact in matches if predicate.expected is None or _equal(fact.value, predicate.expected)]
            contrary = [fact for fact in matches if predicate.expected is not None and not _equal(fact.value, predicate.expected)]
            if any(f"dynamic_metadata:{key}" in flag or "dynamic_cli_mapping" in flag for flag in flags):
                unknown = "dynamic_metadata"
                complete = False
        elif predicate.kind == "env_reference":
            candidates = [fact for fact in facts if fact.kind == predicate.kind and fact.subject == predicate.subject]
            if any("shadowed_env_binding" in flag or "unresolved_env_binding" in flag or "dynamic_namespace" in flag for flag in _flags_for(index, relevant)):
                complete = False
                if not candidates:
                    unknown = "ambiguous_environment_binding"
        elif predicate.kind == "bounded_code_fact":
            if not predicate.module and not predicate.path and not complete:
                unknown = "incomplete_unqualified_resolution"
            if predicate.pattern not in PATTERNS:
                unknown = "unsupported_pattern"
            else:
                pattern_key = predicate.pattern
                if predicate.pattern in {"literal-default/v1", "explicit-raise/v1", "decorator-argument/v1"}:
                    if not predicate.key:
                        unknown = "pattern_key_required"
                    pattern_key = f"{predicate.pattern}:{predicate.key}"
                matches = [fact for fact in facts if fact.kind == predicate.kind and fact.subject == predicate.subject and fact.key == pattern_key]
                candidates = [fact for fact in matches if predicate.expected is None or _equal(fact.value, predicate.expected)]
                contrary = [fact for fact in matches if predicate.expected is not None and not _equal(fact.value, predicate.expected)]
                declaration_paths = {fact.path for fact in facts if fact.kind == "symbol_declared" and fact.subject == predicate.subject}
                if len(declaration_paths) > 1 or len({(fact.path, fact.start_byte) for fact in matches}) > 1:
                    unknown = "ambiguous_pattern_subject"
                if any("dynamic_namespace" in flag or "conditional_module_bindings" in flag or f"shadowed:{predicate.subject.split('.')[0]}" in flag
                       for flag in _flags_for(index, relevant)):
                    complete = False
                    if not matches:
                        unknown = "dynamic_pattern_scope"
        else:
            unknown = unknown or "unsupported_semantics"
    if candidates and contrary:
        unknown = "inconsistent_or_ambiguous_static_values"
    if index.parse_failures:
        flags.extend(f"parse_failure:{gap.path}" for gap in index.parse_failures)
    coverage = _coverage(index, predicate, len(candidates) + len(contrary), complete and unknown is None, relevant, flags, near)
    evidence = [_evidence(index, predicate, "positive", fact, None) for fact in candidates]
    evidence.extend(_evidence(index, predicate, "contrary", fact, None) for fact in contrary)
    if unknown:
        state, reason = "unknown", unknown
    elif candidates:
        state, reason = "established", "scoped_static_predicate_established"
    elif contrary:
        state, reason = "contradicted", "contrary_literal"
    elif complete:
        state, reason = "absent", "exhaustive_scoped_absence"
        evidence.append(_evidence(index, predicate, "negative", None, coverage))
    else:
        state, reason = "unknown", "incomplete_scope"
    return PredicateResult(predicate_id=predicate.predicate_id, state=state, reason=reason,
                           evidence=evidence, coverage=[coverage], complete=coverage.complete)


def _equal(left: object, right: object) -> bool:
    return type(left) is type(right) and left == right


def _module_from_path(path: str) -> str | None:
    if not path.endswith(".py"):
        return None
    parts = path[:-3].split("/")
    if parts[0] == "src":
        parts.pop(0)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _flags_for(index: StaticIndex, entries: list[SnapshotEntry]) -> list[str]:
    paths = {entry.path for entry in entries}
    return [flag for flag in index.dynamic_flags if flag.split(":", 1)[0] in paths]


def _one_hop_export(index: StaticIndex, predicate: Predicate) -> list[Fact]:
    exporting_paths = [entry.path for entry in index.snapshot.entries if _module_from_path(entry.path) == predicate.module]
    results: list[Fact] = []
    for path in exporting_paths:
        if any(flag.startswith(path + ":") for flag in index.dynamic_flags):
            continue
        target = index.exports.get(path, {}).get(predicate.subject)
        if not target or target[0] == predicate.module:
            continue
        results.extend(fact for fact in index.facts if fact.kind == "symbol_declared" and
                       fact.module == target[0] and fact.subject == target[1] and
                       not any(flag.startswith(fact.path + ":") for flag in index.dynamic_flags))
    return results


__all__ = ["StaticIndex", "build_index", "resolve", "PARSER_VERSION", "INDEX_VERSION"]
