"""Offline public-fixture journeys through the real Python CLI entry point."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


class CLIJourneyTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="m2-cli-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def cli(self, *arguments, expected=0):
        # Run outside target/tool directories; never put target code on sys.path.
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        result = subprocess.run(
            [sys.executable, "-I", "-m", "claim_auditor", *map(str, arguments)],
            cwd=self.base, env=environment, capture_output=True, timeout=150,
        )
        self.assertEqual(result.returncode, expected, result.stderr.decode("utf-8", "replace"))
        self.assertNotIn(b"Traceback", result.stderr)
        return result

    def snapshot(self):
        source = self.base / "source"
        source.mkdir()
        (source / "README.md").write_bytes(
            b"The function `present` is declared in module `sample`.\n\n"
            b"The function `invented` is declared in module `sample`.\n\n"
            b"The service handles 10000 requests per second.\n"
        )
        # If acquisition/indexing imports target files, this visible marker exposes it.
        marker = self.base / "TARGET_EXECUTED"
        (source / "sample.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
            "def present():\n    return 3\n", encoding="utf-8",
        )
        (source / "sitecustomize.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('startup')\n",
            encoding="utf-8",
        )
        snapshot = self.base / "snapshot"
        self.cli("snapshot", "--fixture", source, "--out", snapshot)
        return snapshot, marker

    def test_snapshot_audit_verify_export_are_pinned_and_never_execute_target(self):
        """what_bug_this_catches: CLI seams diverge or import target code to prove declarations."""
        snapshot, marker = self.snapshot()
        run = self.base / "run"
        self.cli("audit", "--snapshot", snapshot, "--mode", "rules", "--out", run)
        self.cli("verify-report", run)
        report = json.loads((run / "report.json").read_bytes())
        by_quote = {item["claim"]["span"]["quote"]: item for item in report["findings"]}
        for name, verdict in (("present", "verified"), ("invented", "missing")):
            matches = [row for quote, row in by_quote.items() if f"`{name}`" in quote]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["verdict"], verdict)
        operational = [row for quote, row in by_quote.items() if "requests per second" in quote]
        self.assertEqual(len(operational), 1)
        self.assertEqual(operational[0]["verdict"], "unknown")
        for filename in ("report.json", "report.md", "report.html", "RUN.json"):
            self.assertTrue((run / filename).is_file(), filename)
        pin = hashlib.sha256((run / "RUN.json").read_bytes()).hexdigest()
        exported = self.base / "export"
        self.cli("export-report", "--run", run, "--manifest-digest", pin, "--out", exported)
        self.cli("verify-report", exported / "run")
        self.assertEqual((run / "RUN.json").read_bytes(), (exported / "run" / "RUN.json").read_bytes())
        self.assertFalse(marker.exists(), "target code executed")

    def test_fail_on_missing_cannot_mask_changed_snapshot_integrity(self):
        """what_bug_this_catches: accusation exit 5 overriding pinned-input tamper exit 4."""
        snapshot, marker = self.snapshot()
        self.cli("audit", "--snapshot", snapshot, "--out", self.base / "policy-run",
                 "--fail-on", "missing", expected=5)
        (snapshot / "files" / "sample.py").write_bytes(b"def altered():\n    pass\n")
        self.cli("audit", "--snapshot", snapshot, "--out", self.base / "tampered-run",
                 "--fail-on", "missing", expected=4)
        self.assertFalse(marker.exists())

    def test_demo_fresh_output_and_report_tamper_refusal(self):
        """what_bug_this_catches: a demo overwriting prior evidence or accepting modified report bytes."""
        demo = self.base / "demo"
        self.cli("demo", "--offline", "--out", demo)
        self.cli("verify-report", demo / "run")
        before = (demo / "run" / "RUN.json").read_bytes()
        self.cli("demo", "--offline", "--out", demo, expected=2)
        self.assertEqual((demo / "run" / "RUN.json").read_bytes(), before)
        report = demo / "run" / "report.md"
        report.write_bytes(report.read_bytes() + b"changed\n")
        self.cli("verify-report", demo / "run", expected=4)

    def test_missing_snapshot_and_unadmitted_live_fail_without_outputs(self):
        """what_bug_this_catches: missing setup becoming clean success or live silently becoming rules/replay."""
        missing_out = self.base / "missing-output"
        self.cli("audit", "--snapshot", self.base / "missing", "--out", missing_out, expected=2)
        self.assertFalse(missing_out.exists())
        snapshot, _ = self.snapshot()
        live_out = self.base / "live-output"
        self.cli("audit", "--snapshot", snapshot, "--mode", "live", "--out", live_out, expected=2)
        self.assertFalse(live_out.exists())
