"""Allowlisted Git object acquisition, isolated from repository configuration."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
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


def _batch(git: list[str], trusted: Path, env: dict[str, str], oid: str, cap: int, kind: str) -> bytes:
    checked = _run(git + ["cat-file", "--batch-check"], trusted, env, 256, (oid + "\n").encode("ascii"))
    parts = checked.rstrip(b"\n").split(b" ")
    if len(parts) != 3 or parts[0].decode("ascii") != oid or parts[1].decode("ascii") != kind:
        raise SnapshotError("unexpected_git_object_type")
    size = int(parts[2])
    if size < 0 or size > cap:
        raise SnapshotError("decompressed_object_byte_limit")
    raw = _run(git + ["cat-file", "--batch"], trusted, env, size + 256, (oid + "\n").encode("ascii"))
    header, separator, payload = raw.partition(b"\n")
    if not separator or header != checked.rstrip(b"\n") or len(payload) != size + 1 or not payload.endswith(b"\n"):
        raise SnapshotError("malformed_git_batch_output")
    return payload[:-1]


def acquire_git(repo: Path, commit: str, out: Path) -> Snapshot:
    from . import _make_snapshot, _publish, _write_source
    if not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", commit):
        raise AuditError("git_commit", "a full lowercase object ID is required", 2)
    algorithm = "sha1" if len(commit) == 40 else "sha256"
    try:
        repo = Path(os.path.abspath(repo))
        output_absolute = Path(os.path.abspath(out))
        if repo == output_absolute or repo in output_absolute.parents:
            raise SnapshotError("output_must_be_outside_target_repository")
        _ordinary_directory(repo)
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
        executable = shutil.which("git")
        if executable is None:
            raise SnapshotError("trusted_git_binary_unavailable")
        executable_path = Path(executable).absolute()
        if repo == executable_path or repo in executable_path.parents:
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
            listing = _run(git + ["ls-tree", "-r", "-z", "--full-tree", commit], trusted, env, 20 * 1024 * 1024)
            records = listing.split(b"\x00")
            if records[-1] != b"" or len(records) - 1 > MAX_ENTRIES:
                raise SnapshotError("invalid_tree_or_entry_limit")
            root = fresh_directory(output_absolute)
            (root / "files").mkdir()
            entries: list[SnapshotEntry] = []
            gaps: list[ScopeGap] = []
            seen: set[str] = set()
            total = 0
            for record in records[:-1]:
                if time.monotonic() > deadline:
                    raise SnapshotError("snapshot_time_limit")
                header, separator, raw_path = record.partition(b"\t")
                if not separator:
                    raise SnapshotError("malformed_tree_entry")
                relative = validated_path(raw_path.decode("utf-8", "strict"))
                if len(raw_path) > 4096 or collision_key(relative) in seen:
                    raise SnapshotError("tree_path_limit_or_collision")
                seen.add(collision_key(relative))
                mode, kind, oid = header.decode("ascii").split(" ")
                if not re.fullmatch(rf"[a-f0-9]{{{len(commit)}}}", oid):
                    raise SnapshotError("invalid_tree_object_id")
                if mode == "160000" and kind == "commit":
                    gaps.append(ScopeGap(path=relative, reason="submodule_content_unavailable"))
                    continue
                if mode not in {"100644", "100755"} or kind != "blob":
                    raise SnapshotError("symlink_or_unsupported_tree_mode")
                raw = _batch(git, trusted, env, oid, MAX_FILE_BYTES, "blob")
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
