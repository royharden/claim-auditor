"""Bounded ordinary-file IO. Untrusted paths never become process arguments."""

from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
import stat
import unicodedata

MAX_ENTRIES = 5_000
MAX_FILE_BYTES = 512 * 1024
MAX_README_BYTES = 128 * 1024
MAX_TEXT_BYTES = 20 * 1024 * 1024
MAX_LINES = 10_000
MAX_LINE_BYTES = 16 * 1024
MAX_OBJECT_BYTES = 500 * 1024 * 1024


class SnapshotError(ValueError):
    """An input cannot satisfy the bounded immutable-snapshot contract."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validated_path(value: str) -> str:
    """Accept a portable literal relative path, never normalize traversal away."""
    if not value or "\x00" in value or "\\" in value or ":" in value or any(char in value for char in '<>"|?*'):
        raise SnapshotError("invalid_relative_path")
    if value.startswith("/") or any(part in ("", ".", "..") for part in value.split("/")):
        raise SnapshotError("invalid_relative_path")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value:
        raise SnapshotError("noncanonical_relative_path")
    for part in path.parts:
        if part.endswith((".", " ")) or any(ord(char) < 32 for char in part):
            raise SnapshotError("nonportable_relative_path")
        stem = part.split(".", 1)[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
            raise SnapshotError("reserved_path_component")
    return value


def collision_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def bounded_scandir(path: Path, cap: int) -> list[os.DirEntry[str]]:
    entries = []
    with os.scandir(path) as iterator:
        for entry in iterator:
            if len(entries) >= cap:
                raise SnapshotError("directory_entry_limit")
            entries.append(entry)
    return sorted(entries, key=lambda entry: entry.name)


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    # File type only: Windows lstat() synthesizes execute bits from the extension; fstat() does not.
    if stat.S_ISDIR(info.st_mode):
        # Sibling creation changes an ancestor's size/mtime without replacing it.
        # Directory handles/no-follow checks pin the path; compare its identity,
        # while retaining content metadata checks for ordinary files below.
        return info.st_dev, info.st_ino, 0, 0, stat.S_IFMT(info.st_mode)
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, stat.S_IFMT(info.st_mode)


def _ordinary(info: os.stat_result, directory: bool) -> None:
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise SnapshotError("symlink_or_reparse_point")
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise SnapshotError("not_ordinary_directory" if directory else "not_ordinary_file")


def _chain(root: Path, relative: str) -> tuple[Path, list[tuple[Path, tuple[int, int, int, int, int]]]]:
    validated_path(relative)
    # Reject reparse/symlink roots and ancestors instead of resolving through them.
    root = Path(os.path.abspath(root))
    paths = [*reversed(root.parents), root]
    target = root.joinpath(*PurePosixPath(relative).parts)
    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current = current / part
        paths.append(current)
    observations = []
    for item in paths:
        info = item.lstat()
        _ordinary(info, True)
        observations.append((item, _identity(info)))
    return target, observations


@contextmanager
def _opened_ordinary(target: Path, ancestors: list[tuple[Path, tuple[int, int, int, int, int]]]):
    """Hold no-follow directory handles for the entire file read.

    POSIX opens every component relative to its already-open parent. Windows
    denies delete-sharing on ancestor handles, preventing path replacement while
    descendant handles are opened. Reparse points are opened as links and rejected.
    """
    descriptors: list[int] = []
    if os.name != "nt":
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        current = os.open(target.anchor, flags)
        descriptors.append(current)
        try:
            for part in target.parts[1:-1]:
                current = os.open(part, flags, dir_fd=current)
                descriptors.append(current)
            descriptor = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current)
            descriptors.append(descriptor)
            yield descriptor
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
        return
    import ctypes
    from ctypes import wintypes
    import msvcrt

    class AttributeTag(ctypes.Structure):
        _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    handles: list[object] = []
    descriptor: int | None = None
    try:
        for path, _identity_before in [*ancestors, (target, ())]:
            directory = path != target
            access = 0x80 if directory else 0x80000000  # FILE_READ_ATTRIBUTES / GENERIC_READ.
            flags = 0x00200000 | (0x02000000 if directory else 0)  # OPEN_REPARSE_POINT / BACKUP_SEMANTICS.
            handle = kernel.CreateFileW(str(path), access, 0x1 | 0x2, None, 3, flags, None)
            if handle == ctypes.c_void_p(-1).value:
                raise SnapshotError(f"ordinary_handle_unavailable:{ctypes.get_last_error()}")
            handles.append(handle)
            attributes = AttributeTag()
            if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)):
                raise SnapshotError("handle_attributes_unavailable")
            if attributes.FileAttributes & 0x400 or bool(attributes.FileAttributes & 0x10) != directory:
                raise SnapshotError("reparse_or_wrong_handle_type")
        final = handles.pop()
        try:
            descriptor = msvcrt.open_osfhandle(int(final), os.O_RDONLY | os.O_BINARY)
        except Exception:
            kernel.CloseHandle(final)
            raise
        yield descriptor
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for handle in reversed(handles):
            kernel.CloseHandle(handle)


def read_ordinary(root: Path, relative: str, cap: int = MAX_FILE_BYTES) -> bytes:
    """Read one opened handle, rejecting links and observable identity changes.

    O_NOFOLLOW protects the final component on POSIX. Windows reparse attributes
    and identity comparisons are checked on the opened handle and every ancestor.
    Platform race resistance still needs hostile-input validation before release.
    """
    target, ancestors = _chain(root, relative)
    before = target.lstat()
    _ordinary(before, False)
    if before.st_size > cap:
        raise SnapshotError("file_byte_limit")
    with _opened_ordinary(target, ancestors) as descriptor:
        opened = os.fstat(descriptor)
        _ordinary(opened, False)
        if _identity(before) != _identity(opened):
            raise SnapshotError("file_identity_changed")
        chunks = []
        remaining = cap + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > cap or len(data) != opened.st_size:
            raise SnapshotError("file_byte_limit_or_size_changed")
        if _identity(os.fstat(descriptor)) != _identity(opened):
            raise SnapshotError("file_changed_during_read")
    if _identity(target.lstat()) != _identity(before):
        raise SnapshotError("file_replaced_during_read")
    for ancestor, identity in ancestors:
        after = ancestor.lstat()
        _ordinary(after, True)
        if _identity(after) != identity:
            raise SnapshotError("ancestor_changed_during_read")
    return data


def text_error(data: bytes, readme: bool = False) -> str | None:
    if len(data) > (MAX_README_BYTES if readme else MAX_FILE_BYTES):
        return "file_byte_limit"
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return "unsupported_encoding"
    if b"\x00" in data:
        return "binary_content"
    if b"\r" in data.replace(b"\r\n", b""):
        return "unsupported_lone_cr_line_endings"
    lines = data.splitlines(keepends=True)
    if len(lines) > MAX_LINES or any(len(line) > MAX_LINE_BYTES for line in lines):
        return "line_limit"
    if data.startswith(b"version https://git-lfs.github.com/spec/v1\n") or data.startswith(b"version https://git-lfs.github.com/spec/v1\r\n"):
        return "lfs_pointer_unavailable"
    return None


def fresh_directory(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    # mkdir without exist_ok makes stale/incomplete outputs non-reusable.
    path.mkdir(parents=False, exist_ok=False)
    return path
