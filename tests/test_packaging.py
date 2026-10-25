"""Real local build/lock checks for the trusted auditor, never target projects."""

import configparser
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile


PROJECT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_wheel_has_package_and_exact_console_entrypoint(self):
        """what_bug_this_catches: a successful build shipping an empty/wrong package or unusable CLI entry point."""
        with TemporaryDirectory(prefix="m2-wheel-") as directory:
            result = subprocess.run(
                [sys.executable, "-I", "-m", "build", "--wheel", "--no-isolation",
                 "--outdir", directory, str(PROJECT)],
                cwd=directory, capture_output=True, timeout=180,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
            wheels = list(Path(directory).glob("*.whl"))
            self.assertEqual(len(wheels), 1)
            with ZipFile(wheels[0]) as wheel:
                names = wheel.namelist()
                self.assertIn("claim_auditor/__main__.py", names)
                self.assertIn("claim_auditor/cli.py", names)
                self.assertIn("claim_auditor/contracts.py", names)
                entrypoints = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
                self.assertEqual(len(entrypoints), 1)
                parser = configparser.ConfigParser()
                parser.read_string(wheel.read(entrypoints[0]).decode("utf-8"))
                self.assertEqual(parser["console_scripts"]["claim-auditor"], "claim_auditor.cli:main")
                self.assertFalse(any(name.startswith(("tests/", ".agent-work/", ".env")) for name in names))

    def test_stale_project_refuses_locked_resolution_without_rewriting_lock(self):
        """what_bug_this_catches: bootstrap silently re-resolving a stale lock and claiming reproducible setup."""
        uv = shutil.which("uv")
        self.assertIsNotNone(uv, "uv is required for the locked packaging gate")
        original_lock = (PROJECT / "uv.lock").read_bytes()
        project = (PROJECT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "0.1.0"', project)
        with TemporaryDirectory(prefix="m2-stale-lock-") as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text(
                project.replace('version = "0.1.0"', 'version = "9.9.9"', 1), encoding="utf-8",
            )
            (root / "uv.lock").write_bytes(original_lock)
            environment = os.environ.copy()
            # Resolve without any network/provider work or project installation.
            environment["UV_PYTHON_DOWNLOADS"] = "never"
            result = subprocess.run(
                [uv, "--no-config", "lock", "--check", "--offline", "--project", str(root),
                 "--python", sys.executable],
                cwd=root, env=environment, capture_output=True, timeout=60,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"lockfile", result.stderr.lower())
            self.assertEqual((root / "uv.lock").read_bytes(), original_lock)
