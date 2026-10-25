"""Future ordinary-handle refusal controls; real hostile race validation stays separate."""

import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from claim_auditor.snapshot.safeio import SnapshotError, read_ordinary


def changed(info, **fields):
    values = {key: getattr(info, key) for key in ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns")}
    values["st_file_attributes"] = getattr(info, "st_file_attributes", 0)
    values.update(fields)
    return SimpleNamespace(**values)


class HostilePathTests(unittest.TestCase):
    def test_traversal_windows_streams_and_reserved_paths_refuse_before_open(self):
        """what_bug_this_catches: normalizing attacker paths into traversal, device names or alternate streams."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in ("../escape", "C:/escape", "file.py:stream", "dir/NUL.txt", "dir\\file.py"):
                with self.subTest(relative=relative), patch("claim_auditor.snapshot.safeio.os.open") as open_file:
                    with self.assertRaises(SnapshotError):
                        read_ordinary(root, relative)
                    open_file.assert_not_called()

    def test_real_symlink_never_reads_its_target(self):
        """what_bug_this_catches: a fixture/evidence link escaping the validated ordinary-file tree."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "source"
            root.mkdir()
            target = base / "owned-outside-target.txt"
            target.write_bytes(b"must not be read through link")
            try:
                (root / "link.py").symlink_to(target)
            except OSError as exc:
                raise RuntimeError("Activation prerequisite: actual symlink capability; refusal proof is not skipped") from exc
            with patch("claim_auditor.snapshot.safeio.os.read") as read:
                with self.assertRaises(SnapshotError) as caught:
                    read_ordinary(root, "link.py")
                self.assertIn("symlink_or_reparse_point", str(caught.exception))
                read.assert_not_called()
            self.assertEqual(target.read_bytes(), b"must not be read through link")

    def test_reparse_ancestor_metadata_is_rejected_before_handle_open(self):
        """what_bug_this_catches: an ancestor junction/reparse observation being treated as an ordinary directory."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data.py").write_bytes(b"pass\n")
            original = Path.lstat

            def observe(path, *args, **kwargs):
                info = original(path, *args, **kwargs)
                return changed(info, st_file_attributes=getattr(info, "st_file_attributes", 0) | 0x400) if path == root else info

            with patch.object(Path, "lstat", autospec=True, side_effect=observe), patch("claim_auditor.snapshot.safeio.os.open") as open_file:
                with self.assertRaises(SnapshotError) as caught:
                    read_ordinary(root, "data.py")
                self.assertIn("symlink_or_reparse_point", str(caught.exception))
                open_file.assert_not_called()

    def test_opened_file_change_is_not_returned_as_stable_bytes(self):
        """what_bug_this_catches: mutation observed after a handle read still producing trusted source bytes."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data.py").write_bytes(b"pass\n")
            original = os.fstat
            calls = 0

            def observe(descriptor):
                nonlocal calls
                calls += 1
                info = original(descriptor)
                return changed(info, st_mtime_ns=info.st_mtime_ns + 1) if calls >= 2 else info

            with patch("claim_auditor.snapshot.safeio.os.fstat", side_effect=observe):
                with self.assertRaises(SnapshotError) as caught:
                    read_ordinary(root, "data.py")
            self.assertIn("file_changed_during_read", str(caught.exception))

    def test_observed_ancestor_swap_after_read_fails_closed(self):
        """what_bug_this_catches: returning evidence after its ancestor identity changed during acquisition."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data.py").write_bytes(b"pass\n")
            original = Path.lstat
            root_observations = 0

            def observe(path, *args, **kwargs):
                nonlocal root_observations
                info = original(path, *args, **kwargs)
                if path == root:
                    root_observations += 1
                    if root_observations >= 2:
                        # Object replacement changes inode, whereas creating an
                        # unrelated sibling may legitimately change only mtime.
                        return changed(info, st_ino=info.st_ino + 1)
                return info

            with patch.object(Path, "lstat", autospec=True, side_effect=observe):
                with self.assertRaises(SnapshotError) as caught:
                    read_ordinary(root, "data.py")
            self.assertIn("ancestor_changed_during_read", str(caught.exception))
