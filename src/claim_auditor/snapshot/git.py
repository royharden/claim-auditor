"""Allowlisted Git object acquisition, isolated from repository configuration."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import threading
import time

from claim_auditor.contracts import AuditError, ScopeGap, Snapshot, SnapshotEntry, sha256
from .safeio import (
    MAX_ENTRIES, MAX_FILE_BYTES, MAX_OBJECT_BYTES, MAX_TEXT_BYTES, SnapshotError,
    bounded_scandir, collision_key, fresh_directory, read_ordinary, text_error, validated_path,
)

GIT_TIMEOUT = 30


def _environment() -> dict[str, str]:
    # Do not mutate HOME or host environment. Remove every inherited Git injection.
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull, "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_CONFIG_COUNT": "0",
        "GIT_ALLOW_PROTOCOL": "", "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C", "LANG": "C",
    })
    return env


def _run(args: list[str], cwd: Path, env: dict[str, str], cap: int, data: bytes = b"") -> bytes:
    """Drain both pipes under byte/time caps; terminate on any overflow."""
    process = subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    output: list[bytes] = []
    errors: list[bytes] = []
    overflow = threading.Event()

    def drain(pipe: object, destination: list[bytes], limit: int) -> None:
        total = 0
        try:
            while True:
                chunk = pipe.read(64 * 1024)  # type: ignore[attr-defined]
                if not chunk:
                    return
                total += len(chunk)
                if total > limit:
                    overflow.set()
                    process.kill()
                    return
                destination.append(chunk)
        finally:
            pipe.close()  # type: ignore[attr-defined]

    readers = [threading.Thread(target=drain, args=(process.stdout, output, cap), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, errors, 64 * 1024), daemon=True)]
    for reader in readers:
        reader.start()
    try:
        assert process.stdin is not None
        process.stdin.write(data)
        process.stdin.close()
        process.wait(timeout=GIT_TIMEOUT)
    except (subprocess.TimeoutExpired, BrokenPipeError) as error:
        process.kill()
        process.wait()
        raise SnapshotError("git_timeout_or_closed_input") from error
    finally:
        for reader in readers:
            reader.join(timeout=2)
    if overflow.is_set() or any(reader.is_alive() for reader in readers):
        raise SnapshotError("git_output_limit")
    if process.returncode != 0:
        # Error text stays a diagnostic only; no terminal control is evaluated.
        detail = b"".join(errors).decode("utf-8", "replace")[:1000]
        raise SnapshotError(f"git_object_error: {detail!r}")
    return b"".join(output)


def _ordinary_directory(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise SnapshotError("git_store_must_be_ordinary_directory")


def _copy_objects(source: Path, destination: Path, algorithm: str) -> None:
    _ordinary_directory(source)
    width = 40 if algorithm == "sha1" else 64
    total = 0
    count = 0
    before = source.lstat()
    directories = bounded_scandir(source, 260)
    for directory in directories:
        info = directory.stat(follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise SnapshotError("unexpected_git_object_entry")
        if directory.name == "info":
            if os.path.lexists(Path(directory.path) / "alternates") or os.path.lexists(Path(directory.path) / "http-alternates"):
                raise SnapshotError("alternate_object_store_not_supported")
            continue
        is_pack = directory.name == "pack"
        if not is_pack and not re.fullmatch(r"[a-f0-9]{2}", directory.name):
            raise SnapshotError("unexpected_git_object_directory")
        files = bounded_scandir(Path(directory.path), 100_000)
        for item in files:
            count += 1
            if count > 100_000:
                raise SnapshotError("compressed_object_file_count_limit")
            if is_pack:
                if item.name.endswith(".promisor"):
                    raise SnapshotError("promisor_object_store_not_supported")
                if not re.fullmatch(rf"pack-[a-f0-9]{{{width}}}\.(pack|idx|rev)", item.name):
                    if re.fullmatch(rf"pack-[a-f0-9]{{{width}}}\.(bitmap|keep)", item.name):
                        continue
                    raise SnapshotError("unexpected_pack_object_file")
            elif not re.fullmatch(rf"[a-f0-9]{{{width - 2}}}", item.name):
                raise SnapshotError("unexpected_loose_object_file")
            relative = f"{directory.name}/{item.name}"
            raw = read_ordinary(source, relative, MAX_OBJECT_BYTES - total)
            total += len(raw)
            if total > MAX_OBJECT_BYTES:
                raise SnapshotError("compressed_object_byte_limit")
            output = destination / relative
            output.parent.mkdir(exist_ok=True)
            with output.open("xb") as stream:
                stream.write(raw)
    after = source.lstat()
    if (before.st_dev, before.st_ino, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns):
        raise SnapshotError("object_store_changed_during_copy")


def _trusted_git() -> Path:
    """Resolve git from absolute PATH entries only, never the cwd; Windows requires git.exe (no .bat/.cmd)."""
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        cwd = None
    name = "git.exe" if os.name == "nt" else "git"
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        try:
            if Path(entry).resolve() == cwd:
                continue
        except OSError:
            continue
        try:
            # Return the physical executable identity used by acquire_git's target
            # containment check. A PATH junction must not disguise target code.
            candidate = (Path(entry) / name).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if candidate.parent == cwd:
            continue
        if os.name == "nt" and candidate.suffix.casefold() != ".exe":
            continue
        if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
            return candidate
    raise SnapshotError("trusted_git_binary_unavailable")


def _verify_object_id(algorithm: str, kind: str, payload: bytes, oid: str) -> None:
    """Content addressing: recompute the object ID; never trust store or Git output bytes."""
    if hashlib.new(algorithm, f"{kind} {len(payload)}\0".encode("ascii") + payload).hexdigest() != oid:
        raise AuditError("git_object_hash_mismatch", f"{kind} {oid}", 4)


def _tree_entries(payload: bytes, width: int) -> list[tuple[str, bytes, str]]:
    """Parse one verified tree object into (mode, name, hex object ID) records."""
    records = []
    position = 0
    while position < len(payload):
        space = payload.find(b" ", position)
        nul = payload.find(b"\x00", space + 1) if space >= 0 else -1
        if space < 0 or nul < 0 or nul + 1 + width > len(payload):
            raise SnapshotError("malformed_tree_entry")
        mode = payload[position:space].decode("ascii")
        name = payload[space + 1:nul]
        if not re.fullmatch(r"[0-7]{5,6}", mode) or not name or b"/" in name or name in (b".", b".."):
            raise SnapshotError("malformed_tree_entry")
        # Canonicalize like Git's canon_mode (as ls-tree reported): 040000 -> 40000, 100664 -> 100644.
        value = int(mode, 8)
        file_type = value & 0o170000
        if file_type == 0o040000:
            mode = "40000"
        elif file_type == 0o100000:
            mode = "100755" if value & 0o100 else "100644"
        elif file_type in (0o120000, 0o160000):
            mode = f"{file_type:o}"
        else:
            raise SnapshotError("malformed_tree_entry")
        records.append((mode, name, payload[nul + 1:nul + 1 + width].hex()))
        position = nul + 1 + width
    return records


def _batch_bounded(git: list[str], trusted: Path, env: dict[str, str], oid: str, cap: int, kind: str) -> tuple[bytes | None, int]:
    """Return (payload, size), or (None, size) without reading the object when size exceeds cap.

    A read payload is hash-verified against `oid` (SHA-1/SHA-256 inferred from its width).
    """
    checked = _run(git + ["cat-file", "--batch-check"], trusted, env, 256, (oid + "\n").encode("ascii"))
    parts = checked.rstrip(b"\n").split(b" ")
    if len(parts) != 3 or parts[0].decode("ascii") != oid or parts[1].decode("ascii") != kind:
        raise SnapshotError("unexpected_git_object_type")
    size = int(parts[2])
    if size < 0:
        raise SnapshotError("decompressed_object_byte_limit")
    if size > cap:
        return None, size
    raw = _run(git + ["cat-file", "--batch"], trusted, env, size + 256, (oid + "\n").encode("ascii"))
    header, separator, payload = raw.partition(b"\n")
    if not separator or header != checked.rstrip(b"\n") or len(payload) != size + 1 or not payload.endswith(b"\n"):
        raise SnapshotError("malformed_git_batch_output")
    _verify_object_id("sha1" if len(oid) == 40 else "sha256", kind, payload[:-1], oid)
    return payload[:-1], size


def _batch(git: list[str], trusted: Path, env: dict[str, str], oid: str, cap: int, kind: str) -> bytes:
    payload, _ = _batch_bounded(git, trusted, env, oid, cap, kind)
    if payload is None:
        raise SnapshotError("decompressed_object_byte_limit")
    return payload


def acquire_git(repo: Path, commit: str, out: Path) -> Snapshot:
    from . import _make_snapshot, _publish, _write_source, unread_entry_digest
    if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit):
        raise AuditError("git_commit", "a full lowercase object ID is required", 2)
    algorithm = "sha1" if len(commit) == 40 else "sha256"
    try:
        repo = Path(os.path.abspath(repo))
        output_absolute = Path(os.path.abspath(out))
        if repo == output_absolute or repo in output_absolute.parents:
            raise SnapshotError("output_must_be_outside_target_repository")
        _ordinary_directory(repo)
        # Compare physical identities on both sides, including Windows 8.3 path
        # spellings. Ordinary/no-follow source validation still uses the input path.
        target_identity = repo.resolve(strict=True)
        output_identity = output_absolute.resolve()
        if target_identity == output_identity or target_identity in output_identity.parents:
            raise SnapshotError("output_must_be_outside_target_repository")
        store = repo / ".git"
        _ordinary_directory(store)  # Reject .git files/worktree indirection and bare input.
        if os.path.lexists(store / "shallow") or os.path.lexists(store / "commondir"):
            raise SnapshotError("shallow_or_worktree_store_not_supported_use_verified_bundle")
        if os.path.lexists(store / "config.worktree"):
            raise SnapshotError("worktree_config_not_supported")
        # Config is inspected as bounded bytes only; it is never supplied to Git.
        config = read_ordinary(store, "config", 256 * 1024)
        if re.search(rb"promisor|partialclone|worktreeconfig", config, flags=re.IGNORECASE):
            raise SnapshotError("partial_or_promisor_store_not_supported")
        executable_path = _trusted_git()
        if target_identity == executable_path or target_identity in executable_path.parents:
            raise SnapshotError("git_binary_must_not_come_from_target")
        env = _environment()
        deadline = time.monotonic() + 120
        with tempfile.TemporaryDirectory(prefix="claim-auditor-objects-") as temporary:
            trusted = Path(temporary)
            template = trusted / "empty-template"
            template.mkdir()
            bare = trusted / "store.git"
            _run([str(executable_path), "init", "--bare", f"--template={template}",
                  f"--object-format={algorithm}", str(bare)], trusted, env, 64 * 1024)
            _copy_objects(store / "objects", bare / "objects", algorithm)
            git = [str(executable_path), "--no-pager", "--no-replace-objects", f"--git-dir={bare}",
                   "-c", f"core.hooksPath={template}", "-c", "core.fsmonitor=false",
                   "-c", "credential.helper=", "-c", "protocol.allow=never"]
            commit_raw = _batch(git, trusted, env, commit, MAX_FILE_BYTES, "commit")
            first = commit_raw.split(b"\n", 1)[0]
            if not re.fullmatch(rb"tree [a-f0-9]{" + str(len(commit)).encode("ascii") + rb"}", first):
                raise SnapshotError("invalid_commit_tree")
            tree = first[5:].decode("ascii")
            # Walk hash-verified tree objects from the verified commit (no ls-tree): every listed
            # blob provably belongs to this commit's tree. Same 20 MiB listing and entry caps.
            width = len(commit) // 2
            records: list[tuple[str, str, str, str]] = []
            pending = [("", tree)]
            tree_count = tree_bytes = 0
            while pending:
                if time.monotonic() > deadline:
                    raise SnapshotError("snapshot_time_limit")
                prefix, tree_oid = pending.pop()
                tree_count += 1
                if tree_count > MAX_ENTRIES:
                    raise SnapshotError("invalid_tree_or_entry_limit")
                tree_raw = _batch(git, trusted, env, tree_oid, 20 * 1024 * 1024 - tree_bytes, "tree")
                tree_bytes += len(tree_raw)
                for mode, name, oid in _tree_entries(tree_raw, width):
                    raw_path = (prefix.encode("utf-8") + b"/" if prefix else b"") + name
                    if len(raw_path) > 4096:
                        raise SnapshotError("tree_path_limit_or_collision")
                    relative = validated_path(raw_path.decode("utf-8", "strict"))
                    if mode == "40000":
                        pending.append((relative, oid))
                        continue
                    records.append((relative, mode, "commit" if mode == "160000" else "blob", oid))
                    if len(records) > MAX_ENTRIES:
                        raise SnapshotError("invalid_tree_or_entry_limit")
            root = fresh_directory(output_absolute)
            (root / "files").mkdir()
            entries: list[SnapshotEntry] = []
            gaps: list[ScopeGap] = []
            seen: set[str] = set()
            total = 0
            for relative, mode, kind, oid in records:
                if time.monotonic() > deadline:
                    raise SnapshotError("snapshot_time_limit")
                if collision_key(relative) in seen:
                    raise SnapshotError("tree_path_limit_or_collision")
                seen.add(collision_key(relative))
                if mode == "160000" and kind == "commit":
                    gaps.append(ScopeGap(path=relative, reason="submodule_content_unavailable"))
                    continue
                if mode not in {"100644", "100755"} or kind != "blob":
                    raise SnapshotError("symlink_or_unsupported_tree_mode")
                raw, size = _batch_bounded(git, trusted, env, oid, MAX_FILE_BYTES, "blob")
                if raw is None:
                    # Over-cap blob is unsupported scope, never read; the snapshot continues.
                    gaps.append(ScopeGap(path=relative, reason="file_byte_limit"))
                    entries.append(SnapshotEntry(path=relative, sha256=unread_entry_digest("file_byte_limit", size, oid),
                                                 size=size, mode=mode, status="excluded"))
                    continue
                error = text_error(raw, relative.casefold().endswith("readme.md"))
                if error is None:
                    total += len(raw)
                    if total > MAX_TEXT_BYTES:
                        raise SnapshotError("total_text_byte_limit")
                    _write_source(root, relative, raw)
                else:
                    gaps.append(ScopeGap(path=relative, reason=error))
                entries.append(SnapshotEntry(path=relative, sha256=sha256(raw), size=len(raw), mode=mode,
                                             status="included" if error is None else "excluded"))
            snapshot = _make_snapshot(entries, gaps, "git_commit", commit, algorithm, tree)
            _publish(root, snapshot)
            return snapshot
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise AuditError("git_snapshot_input", str(error), 2) from error
