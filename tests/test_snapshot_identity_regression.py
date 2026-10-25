"""Ordinary file reads distinguish object replacement from directory activity."""

from contextlib import contextmanager
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from claim_auditor.snapshot import safeio
from claim_auditor.contracts import AuditError
from claim_auditor.snapshot.git import _trusted_git, acquire_git


class SnapshotIdentityRegressionTests(unittest.TestCase):
    def test_unrelated_sibling_creation_does_not_invalidate_held_ancestor(self):
        """what_bug_this_catches: directory mtime/size used as replacement identity blocks normal concurrent work."""
        with TemporaryDirectory(prefix="m2-identity-") as directory:
            base = Path(directory)
            root = base / "source"
            root.mkdir()
            (root / "README.md").write_bytes(b"ordinary unchanged bytes\n")
            original = safeio._opened_ordinary

            @contextmanager
            def held(target, ancestors):
                with original(target, ancestors) as descriptor:
                    # An unrelated sibling changes directory mtime, not the open
                    # ancestor's identity or any source byte being validated.
                    (root / "unrelated-sibling.txt").write_bytes(b"concurrent activity")
                    yield descriptor

            with patch.object(safeio, "_opened_ordinary", held):
                self.assertEqual(safeio.read_ordinary(root, "README.md"), b"ordinary unchanged bytes\n")

    @unittest.skipUnless(os.name == "nt", "Windows junction regression")
    def test_git_path_junction_resolves_to_actual_executable(self):
        """what_bug_this_catches: lexical Git PATH outside target conceals an executable physically in target."""
        import _winapi

        with TemporaryDirectory(prefix="m2-junction-") as directory:
            base = Path(directory)
            target = base / "target"
            target.mkdir()
            executable = target / "git.exe"
            executable.write_bytes(b"inert fixture: never execute")
            alias = base / "alias"
            _winapi.CreateJunction(str(target), str(alias))
            with patch.dict(os.environ, {"PATH": str(alias)}):
                selected = _trusted_git()
            self.assertEqual(selected, executable.resolve())
            self.assertIn(target.resolve(), selected.parents)

    @unittest.skipUnless(os.name == "nt", "Windows junction regression")
    def test_target_git_behind_path_junction_refuses_before_any_process(self):
        """what_bug_this_catches: target-controlled Git reached through an outside PATH junction."""
        import _winapi

        with TemporaryDirectory(prefix="m2-git-containment-") as directory:
            base = Path(directory).resolve()
            target = base / "target"
            target.mkdir()
            (target / ".git").mkdir()
            (target / "git.exe").write_bytes(b"never execute this inert fixture")
            alias = base / "outside-alias"
            _winapi.CreateJunction(str(target), str(alias))
            with patch.dict(os.environ, {"PATH": str(alias)}), \
                    patch("claim_auditor.snapshot.git.read_ordinary", return_value=b""), \
                    patch("claim_auditor.snapshot.git._run", side_effect=AssertionError("target Git process launch")) as run:
                with self.assertRaises(AuditError) as caught:
                    acquire_git(target, "a" * 40, base / "out")
                self.assertIn("git_binary_must_not_come_from_target", caught.exception.detail)
                run.assert_not_called()
