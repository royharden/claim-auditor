"""A target-owned executable must never become the workflow helper's Git."""

import importlib.util
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from ..git_fixture import GitFixture
from .. import test_workflow as workflow


# An independent review may bind exact git-show helper bytes without editing the
# author checkout. Normal integrated execution reads the repository's helper.
HELPER_PATH = None


class WorkflowGitBinaryBoundaryTests(unittest.TestCase):
    def probe(self, *, junction=False, trusted=False):
        helper_path = HELPER_PATH or workflow.PROJECT / "scripts" / "workflow_audit.py"
        spec = importlib.util.spec_from_file_location("workflow_binary_boundary", helper_path)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with TemporaryDirectory(prefix="m2-workflow-binary-") as directory:
            base = Path(directory)
            target = GitFixture(base / "target")
            binary = target.root / ("git.exe" if os.name == "nt" else "git")
            binary.write_bytes(b"INERT TEST INPUT: NEVER EXECUTE\n")
            binary.chmod(0o755)
            search = target.root
            if junction:
                import _winapi
                search = base / "outside-target-junction"
                _winapi.CreateJunction(str(target.root), str(search))
                self.assertTrue(search.samefile(target.root))
            if trusted:
                search = Path(target.executable).resolve().parent
            metadata = subprocess.run(
                [target.executable, "-C", str(workflow.PROJECT), "rev-parse", "HEAD"],
                cwd=base, env=target.env, capture_output=True, timeout=30, check=True,
            ).stdout.decode("ascii").strip()
            calls = []

            def intercept(argv, **kwargs):
                # Intercept ALL launches. Even the benign host control executes
                # no subprocess while this trap is installed.
                calls.append(Path(argv[0]).resolve())
                return subprocess.CompletedProcess(argv, 1, b"", b"controlled launch interception")

            args = ["audit", "--mode", "self", "--tool-root", str(workflow.PROJECT),
                    "--tool-revision", metadata, "--workflow-revision", "a" * 40,
                    "--trigger-revision", "b" * 40, "--repository", "owned-fixture/auditor",
                    "--run-id", "123456", "--target-repo", str(target.root),
                    "--target-sha", target.head, "--out", str(base / "out")]
            with patch.dict(os.environ, {"PATH": str(search)}), \
                    patch.object(os, "get_exec_path", return_value=[str(search)]), \
                    patch.object(subprocess, "run", side_effect=intercept):
                result = helper.main(args)
            self.assertIn(result, (2, 4))  # Controlled setup/refusal, never a clean report.
            physical_target = target.root.resolve()
            self.assertFalse(any(path == physical_target or physical_target in path.parents for path in calls),
                             f"target executable launch attempted: {calls}")
            if trusted:
                self.assertTrue(calls, "trusted installed Git control was rejected before selection")
                self.assertTrue(all(path == Path(target.executable).resolve() for path in calls))
            self.assertFalse((base / "out" / "artifact" / "workflow-receipt.json").exists())

    def test_direct_target_path_binary_is_refused_before_launch(self):
        """what_bug_this_catches: helper Git identity preflight launching target/git.exe before canonical admission."""
        self.probe()

    @unittest.skipUnless(os.name == "nt", "Windows junction boundary")
    def test_outside_path_junction_into_target_is_refused_before_launch(self):
        """what_bug_this_catches: lexical-only containment accepting an outside alias of target-owned Git."""
        self.probe(junction=True)

    def test_benign_installed_git_remains_selectable(self):
        """what_bug_this_catches: fixing target execution by rejecting every Git executable indiscriminately."""
        self.probe(trusted=True)
