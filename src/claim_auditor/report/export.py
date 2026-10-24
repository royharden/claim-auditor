"""Selected local offline copy; canonical report verification is the authority.

This module defines export selection/bookkeeping, not a new report verifier or
run schema. No archive, publication, credentials or workflow operation exists.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
from typing import Any

from pydantic import ValidationError

from claim_auditor.citations import verify_report
from claim_auditor.contracts import AuditError, RunManifest, Snapshot, canonical_json, sha256, stable_id, validate_relative_path
from claim_auditor.provenance import guard_tool_paths
from claim_auditor.snapshot.safeio import MAX_ENTRIES, MAX_FILE_BYTES, bounded_scandir, fresh_directory, read_ordinary

# This is a conservative EXPORT allowlist over the canonical manifest inventory,
# not an alternate definition of report validity. Missing required artifacts are
# diagnosed by verify_report; unknown artifacts are not copied or silently dropped.
_REPORT_FILES = {
    "report.json", "inventory.json", "claims.jsonl", "findings.jsonl", "evidence.jsonl",
    "coverage.jsonl", "predictions.jsonl", "report.md", "report.html", "context.json", "context.jsonl",
}
MAX_EXPORT_BYTES = 128 * 1024 * 1024
MAX_EXPORT_FILES = MAX_ENTRIES + 32
_ARTIFACT_CAP = 64 * 1024 * 1024
_PRIVATE_PARTS = {
    ".git", ".thinking", ".agent-work", ".agent-registry", ".chatexports", "agentops",
    ".claude", ".codex", ".cursor", ".grok", ".gemini", "journal-credentials",
    "credentials", "secrets", "tokens", "owner-authorizations", "backups", ".backups",
}
_SECRET_NAMES = {
    ".env", ".netrc", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "authorized_keys",
    "auth.json", "credentials.py", "secrets.py", "agents.md", "claude.md", "cursor.md",
    "agent_log.md", "agent_lessons.md",
    "auth", "token", "credential", "secret", "password", "passwords", "api_key", "apikey", "authorization", "budget", "ledger",
}
_DATA_SUFFIXES = {".json", ".jsonl", ".yaml", ".yml", ".toml", ".ini", ".db", ".sqlite", ".sqlite3"}


def _sensitive(path: str) -> bool:
    parts = path.casefold().split("/")
    name = parts[-1]
    if any(part in _PRIVATE_PARTS for part in parts) or name in _SECRET_NAMES:
        return True
    if ".bak" in name or name.endswith((".backup", ".orig", ".rej", ".swp", ".swo", "~")) or name.startswith("~$"):
        return True
    if name.startswith(".env.") and name not in {".env.example", ".env.sample", ".env.template"}:
        return True
    if Path(name).suffix in {".pem", ".key", ".p12", ".pfx"}:
        return True
    return Path(name).suffix in _DATA_SUFFIXES and any(
        word in part for part in parts for word in ("auth", "credential", "token", "secret", "authorization", "budget", "ledger")
    )


def _ordinary(info: os.stat_result, *, directory: bool) -> None:
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise AuditError("unsafe_export_path", "links/reparse points cannot enter an offline export", 4)
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise AuditError("unsafe_export_path", "ordinary directories/files required", 4)


def _directories(path: Path) -> dict[Path, tuple[int, int, int, int]]:
    result = {}
    for item in [*reversed(path.parents), path]:
        info = item.lstat()
        _ordinary(info, directory=True)
        result[item] = (info.st_dev, info.st_ino, info.st_mode, getattr(info, "st_file_attributes", 0))
    return result


def _layout(files: set[str]) -> dict[str, set[str]]:
    directories: dict[str, set[str]] = {"": set()}
    for relative in sorted(files):
        validate_relative_path(relative)
        parts = relative.split("/")
        for index, part in enumerate(parts):
            parent = "/".join(parts[:index])
            directories.setdefault(parent, set()).add(part)
            if index < len(parts) - 1:
                directories.setdefault("/".join(parts[:index + 1]), set())
    if (set(directories) - {""}) & files:
        raise AuditError("invalid_export_inventory", "one selected path cannot be both file and directory", 4)
    return directories


def _exact_layout(root: Path, files: set[str]) -> None:
    """Audit names/types only in inventory-derived directories; never copy walks."""
    directories = _layout(files)
    for relative, expected in sorted(directories.items(), key=lambda item: (item[0].count("/"), item[0])):
        directory = root.joinpath(*relative.split("/")) if relative else root
        _directories(directory)
        entries = bounded_scandir(directory, MAX_EXPORT_FILES)
        if {entry.name for entry in entries} != expected:
            raise AuditError("export_inventory_mismatch", "unlisted, extra or missing objects in canonical export scope", 4)
        for entry in entries:
            child = f"{relative}/{entry.name}" if relative else entry.name
            _ordinary(Path(entry.path).lstat(), directory=child in directories)


def _cap(relative: str) -> int:
    if relative.startswith("snapshot/files/"):
        return MAX_FILE_BYTES
    if relative in {"RUN.json", "snapshot/manifest.json"}:
        return 4 * 1024 * 1024
    if relative in {"context.json", "context.jsonl"}:
        return 128 * 1024
    return _ARTIFACT_CAP


def _read_pinned(root: Path, relative: str, digest: str, size: int | None) -> bytes:
    raw = read_ordinary(root, relative, _cap(relative))
    if sha256(raw) != digest or (size is not None and len(raw) != size):
        raise AuditError("export_input_changed", "selected bytes differ from the pinned verified inventory", 4)
    return raw


def _write_new(root: Path, relative: str, raw: bytes) -> None:
    validate_relative_path(relative)
    target = root.joinpath(*relative.split("/"))
    before = _directories(target.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, 0o600)
    try:
        _ordinary(os.fstat(descriptor), directory=False)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    if before != _directories(target.parent) or read_ordinary(root, relative, len(raw)) != raw:
        raise AuditError("export_output_changed", "written path/bytes changed during copying", 4)


def _plan(root: Path, raw_run: bytes, manifest: RunManifest, manifest_digest: str) -> dict[str, tuple[str, int | None]]:
    names = set(manifest.report_hashes)
    if names - _REPORT_FILES:
        raise AuditError("unsupported_export_artifact", "manifest contains nonexportable/unrelated artifacts; none will be opened or omitted")
    # Preserve canonical completeness/missing-artifact diagnostics before trying
    # to plan a snapshot that an interrupted run may never have created.
    if manifest.state != "complete" or not _REPORT_FILES <= names or manifest.completed_at is None or manifest.errors:
        verify_report(root)  # Canonical failure is propagated unchanged.
        raise AuditError("unsupported_export_artifact", "canonical artifact contract differs from this export selection policy")
    raw_snapshot = read_ordinary(root, "snapshot/manifest.json", 4 * 1024 * 1024)
    try:
        snapshot = Snapshot.model_validate_json(raw_snapshot)
    except ValidationError:
        verify_report(root)  # Canonical malformed-source diagnostic, no copy.
        raise
    if len(snapshot.entries) > MAX_ENTRIES:
        raise AuditError("export_inventory_limit", "snapshot inventory exceeds the existing source entry cap")
    files = {"RUN.json": (manifest_digest, len(raw_run)),
             "snapshot/manifest.json": (sha256(raw_snapshot), len(raw_snapshot)),
             **{name: (digest, None) for name, digest in manifest.report_hashes.items()}}
    for entry in snapshot.entries:
        if entry.status != "included":
            continue  # Exclusions remain in metadata, never become copied bytes.
        if _sensitive(entry.path):
            raise AuditError("nonexportable_required_source", "required source may contain credentials/agent/owner data; refuse the whole export instead of omitting evidence")
        files[f"snapshot/files/{entry.path}"] = (entry.sha256, entry.size)
    if len(files) > MAX_EXPORT_FILES:
        raise AuditError("export_inventory_limit", "selected offline closure has too many files")
    return files


def export_report(run_root: Path, out: Path, *, manifest_digest: str) -> dict[str, Any]:
    """Future local export only. Returned record is EXPORT.json bookkeeping.

    An independently trusted external SHA256 pins exact RUN.json bytes; a digest
    reread from an untrusted run is not origin proof. No export is executed during
    source construction. The canonical run remains under out/run for reopening.
    """
    if not isinstance(manifest_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", manifest_digest):
        raise AuditError("invalid_export_pin", "an external full lowercase RUN.json SHA256 is mandatory")
    if any(str(value).startswith(("\\\\", "//")) or ".." in Path(value).parts for value in (run_root, out)):
        raise AuditError("invalid_export_path", "local nontraversing source/destination paths required")
    root, destination = Path(os.path.abspath(run_root)), Path(os.path.abspath(out))
    source_resolved, out_resolved = root.resolve(), destination.resolve()
    if (source_resolved == out_resolved or source_resolved in out_resolved.parents
            or out_resolved in source_resolved.parents):
        raise AuditError("export_source_destination_overlap", "source and destination trees must be disjoint")
    guard_tool_paths(root / "snapshot", destination)
    _directories(root)
    _directories(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise AuditError("output_exists", "offline export requires a fresh destination")
    raw_run = read_ordinary(root, "RUN.json", 4 * 1024 * 1024)
    if sha256(raw_run) != manifest_digest:
        raise AuditError("export_manifest_pin_mismatch", "exact input RUN.json differs from external pin", 4)
    try:
        manifest = RunManifest.model_validate_json(raw_run)
    except ValidationError:
        verify_report(root)  # Do not replace the canonical invalid-run diagnostic.
        raise
    files = _plan(root, raw_run, manifest, manifest_digest)
    _exact_layout(root, set(files))
    verified = verify_report(root)  # Sole semantic/context/citation authority.
    if verified != manifest or read_ordinary(root, "RUN.json", 4 * 1024 * 1024) != raw_run:
        raise AuditError("export_input_changed", "run manifest changed during canonical verification", 4)
    # No output exists until pinned input and complete canonical verification pass.
    destination = fresh_directory(destination)
    copied = []
    try:
        copied_root = destination / "run"
        fresh_directory(copied_root)
        for relative in sorted(_layout(set(files)), key=lambda path: (path.count("/"), path)):
            if relative:
                parent = copied_root.joinpath(*relative.split("/")).parent
                _directories(parent)
                copied_root.joinpath(*relative.split("/")).mkdir(exist_ok=False)
        total = 0
        for relative, (digest, size) in sorted(files.items()):
            raw = _read_pinned(root, relative, digest, size)
            total += len(raw)
            if total > MAX_EXPORT_BYTES:
                raise AuditError("export_byte_limit", "complete local closure exceeds export cap; no evidence is silently dropped")
            _write_new(copied_root, relative, raw)
            copied.append(dict(path=f"run/{relative}", size=len(raw), sha256=digest))
        _exact_layout(root, set(files))
        _exact_layout(copied_root, set(files))
        # Observe every selected original again after copying to refuse mutations,
        # including changes to context/source files while another file was copied.
        for relative, (digest, size) in sorted(files.items()):
            _read_pinned(root, relative, digest, size)
        reopened = verify_report(copied_root)
        if reopened != manifest or read_ordinary(copied_root, "RUN.json", 4 * 1024 * 1024) != raw_run:
            raise AuditError("export_copy_identity", "copied closure no longer equals the pinned canonical run", 4)
        for relative, (digest, size) in sorted(files.items()):
            _read_pinned(copied_root, relative, digest, size)
        _exact_layout(copied_root, set(files))
        record = dict(format="offline-report-export/1", input_run_manifest_digest=manifest_digest,
                      run_relative_path="run", run_id=manifest.run_id, context_digest=manifest.context_digest,
                      snapshot_id=manifest.snapshot_id, snapshot_manifest_digest=manifest.snapshot_manifest_digest,
                      inventory=copied, total_bytes=total, state="closed_local_copy_unpublished",
                      origin_verified=False, custody_verified=False, publication_authorized=False,
                      workflow_execution_observed=False, runtime_validation="unverified",
                      note="Copied evidence/source can be private. Local export grants no publication permission. Digests prove consistency, not origin or custody.")
        record["export_id"] = stable_id("offline-export", record)
        _write_new(destination, "EXPORT.json", canonical_json(record) + b"\n")
        return record
    except (AuditError, OSError, ValueError, TypeError) as exc:
        try:
            failure = dict(format="offline-report-export-failure/1", input_run_manifest_digest=manifest_digest,
                           state="incomplete_preserved_not_publishable", copied_paths=[item["path"] for item in copied],
                           reason=exc.reason if isinstance(exc, AuditError) else type(exc).__name__)
            _write_new(destination, "FAILED.json", canonical_json(failure) + b"\n")
        except (AuditError, OSError, ValueError):
            pass  # Original error and all partial artifacts remain; no cleanup.
        raise
