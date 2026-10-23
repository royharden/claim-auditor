"""Immutable local snapshots; no checkout, archive extraction or target execution."""

from __future__ import annotations

import os
from pathlib import Path
import stat

from claim_auditor.contracts import (
    AuditError, ScopeGap, Snapshot, SnapshotEntry, canonical_json, sha256, stable_id,
)
from .safeio import (
    MAX_ENTRIES, MAX_FILE_BYTES, MAX_TEXT_BYTES, SnapshotError, bounded_scandir, collision_key,
    fresh_directory, read_ordinary, text_error, validated_path,
)


def _manifest_digest(value: dict[str, object]) -> str:
    return sha256(canonical_json({key: item for key, item in value.items() if key != "manifest_digest"}))


def _make_snapshot(
    entries: list[SnapshotEntry], gaps: list[ScopeGap], source_kind: str,
    commit: str | None = None, hash_algorithm: str | None = None,
    tree_identity: str | None = None,
) -> Snapshot:
    entries = sorted(entries, key=lambda entry: entry.path)
    digest = sha256(canonical_json([entry.model_dump(mode="json") for entry in entries]))
    identity = f"local-git:{commit}" if commit else f"fixture:{digest}"
    tree = tree_identity or digest
    snapshot_id = stable_id("snapshot", source_kind, identity, tree, digest)
    scope_id = stable_id("scope", snapshot_id, [gap.model_dump(mode="json") for gap in gaps])
    body = dict(
        schema_version="claim-auditor/1", policy_version="declared-static/1",
        snapshot_id=snapshot_id, source_kind=source_kind, source_identity=identity,
        commit=commit, hash_algorithm=hash_algorithm, tree_identity=tree,
        content_digest=digest, manifest_digest="0" * 64, entries=entries,
        exclusions=gaps, complete=not gaps and all(entry.status == "included" for entry in entries),
        scope_id=scope_id,
    )
    provisional = Snapshot(**body)
    body["manifest_digest"] = _manifest_digest(provisional.model_dump(mode="json"))
    return Snapshot(**body)


def _publish(root: Path, snapshot: Snapshot) -> None:
    pending = root / "manifest.pending.json"
    with pending.open("xb") as output:
        output.write(canonical_json(snapshot) + b"\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(pending, root / "manifest.json")


def _write_source(root: Path, relative: str, data: bytes) -> None:
    validated_path(relative)
    path = root / "files" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(data)


def create_fixture_snapshot(source: Path, out: Path) -> Snapshot:
    """Freeze an owned loose-file inventory. Inputs are never imported."""
    source, out = Path(source), Path(out)
    try:
        source_absolute = Path(os.path.abspath(source))
        out_absolute = Path(os.path.abspath(out))
        if source_absolute == out_absolute or source_absolute in out_absolute.parents:
            raise SnapshotError("output_must_be_outside_source")
        source_info = source_absolute.lstat()
        if not stat.S_ISDIR(source_info.st_mode) or getattr(source_info, "st_file_attributes", 0) & 0x400:
            raise SnapshotError("fixture_root_must_be_ordinary_directory")
        root = fresh_directory(out_absolute)
        (root / "files").mkdir()
        entries: list[SnapshotEntry] = []
        gaps: list[ScopeGap] = []
        seen: set[str] = set()
        total = 0
        pending = [(source_absolute, "")]
        while pending:
            directory, prefix = pending.pop()
            before = directory.lstat()
            if not stat.S_ISDIR(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
                raise SnapshotError("fixture_directory_replaced")
            children = bounded_scandir(directory, MAX_ENTRIES)
            for child in children:
                relative = validated_path(f"{prefix}/{child.name}" if prefix else child.name)
                key = collision_key(relative)
                if len(seen) >= MAX_ENTRIES:
                    raise SnapshotError("fixture_directory_entry_limit")
                if key in seen:
                    raise SnapshotError("casefold_or_unicode_path_collision")
                seen.add(key)
                info = child.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise SnapshotError("symlink_or_reparse_point")
                if stat.S_ISDIR(info.st_mode):
                    if child.name == ".git":
                        raise SnapshotError("fixture_source_contains_git_store_use_git_snapshot")
                    pending.append((Path(child.path), relative))
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise SnapshotError("unsupported_fixture_file_type")
                if len(entries) >= MAX_ENTRIES:
                    raise SnapshotError("entry_limit")
                data = read_ordinary(source_absolute, relative)
                error = text_error(data, relative.casefold().endswith("readme.md"))
                if error is None:
                    total += len(data)
                    if total > MAX_TEXT_BYTES:
                        raise SnapshotError("total_text_byte_limit")
                    _write_source(root, relative, data)
                else:
                    gaps.append(ScopeGap(path=relative, reason=error))
                entries.append(SnapshotEntry(
                    path=relative, sha256=sha256(data), size=len(data),
                    mode="100755" if info.st_mode & 0o111 else "100644",
                    status="included" if error is None else "excluded",
                ))
            after = directory.lstat()
            if (before.st_dev, before.st_ino, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns):
                raise SnapshotError("fixture_directory_changed")
        snapshot = _make_snapshot(entries, gaps, "fixture_inventory")
        _publish(root, snapshot)
        return snapshot
    except (OSError, ValueError) as error:
        if isinstance(error, AuditError):
            raise
        raise AuditError("snapshot_input", str(error), 2) from error


def create_git_snapshot(repo: Path, commit: str, out: Path) -> Snapshot:
    """Copy ordinary objects into a trusted bare store; never execute target hooks."""
    from .git import acquire_git
    return acquire_git(Path(repo), commit, Path(out))


def load_snapshot(root: Path) -> Snapshot:
    """Verify canonical identity and all included raw bytes before use."""
    root = Path(root)
    try:
        raw = read_ordinary(root, "manifest.json", 4 * 1024 * 1024)
        snapshot = Snapshot.model_validate_json(raw)
        value = snapshot.model_dump(mode="json")
        if _manifest_digest(value) != snapshot.manifest_digest:
            raise SnapshotError("manifest_digest_mismatch")
        if len(snapshot.entries) > MAX_ENTRIES:
            raise SnapshotError("entry_limit")
        if len({collision_key(entry.path) for entry in snapshot.entries}) != len(snapshot.entries):
            raise SnapshotError("unicode_path_collision")
        expected = _make_snapshot(
            snapshot.entries, snapshot.exclusions, snapshot.source_kind,
            snapshot.commit, snapshot.hash_algorithm, snapshot.tree_identity,
        )
        if expected != snapshot:
            raise SnapshotError("snapshot_identity_mismatch")
        total = 0
        for entry in snapshot.entries:
            if entry.status == "included":
                data = read_source(snapshot, root, entry.path)
                total += len(data)
        if total > MAX_TEXT_BYTES:
            raise SnapshotError("total_text_byte_limit")
        return snapshot
    except (OSError, ValueError) as error:
        raise AuditError("snapshot_integrity", str(error), 4) from error


def read_source(snapshot: Snapshot, root: Path, path: str) -> bytes:
    """Return exact frozen bytes, never a current-checkout fallback."""
    try:
        validated_path(path)
        entry = next((entry for entry in snapshot.entries if entry.path == path), None)
        if entry is None or entry.status != "included":
            raise SnapshotError("source_not_in_included_scope")
        data = read_ordinary(Path(root) / "files", path, MAX_FILE_BYTES)
        if len(data) != entry.size or sha256(data) != entry.sha256:
            raise SnapshotError("source_digest_mismatch")
        if text_error(data, path.casefold().endswith("readme.md")):
            raise SnapshotError("included_source_violates_text_limits")
        return data
    except (OSError, ValueError) as error:
        raise AuditError("source_integrity", f"{path}: {error}", 4) from error


def copy_snapshot(snapshot: Snapshot, source: Path, out: Path) -> Snapshot:
    """Copy one already frozen bundle into a fresh run's local evidence store."""
    verified = load_snapshot(source)
    if verified != snapshot:
        raise AuditError("snapshot_identity", "source changed before copy", 4)
    try:
        root = fresh_directory(Path(out))
        (root / "files").mkdir()
        for entry in snapshot.entries:
            if entry.status == "included":
                _write_source(root, entry.path, read_source(snapshot, source, entry.path))
        _publish(root, snapshot)
        return snapshot
    except OSError as error:
        raise AuditError("snapshot_copy", str(error), 4) from error


__all__ = ["create_fixture_snapshot", "create_git_snapshot", "load_snapshot", "read_source", "copy_snapshot"]
