"""CA10 local step controls; these do not attest that a GitHub Action ran."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from .git_fixture import GitFixture, config_value


PROJECT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "workflow"


class WorkflowSourceTests(unittest.TestCase):
    def test_trigger_permissions_action_pins_and_selected_artifact_contract(self):
        """what_bug_this_catches: PR triggers, write permission, moving actions or whole-workspace uploads.

        Bounded source-contract checks complement actual local step controls;
        they are neither a general YAML parser nor Action runtime evidence.
        """
        text = (PROJECT / ".github" / "workflows" / "claim-audit.yml").read_text(encoding="utf-8")
        source = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        for job in ("self-audit", "fixture-audit"):
            self.assertRegex(source, rf"(?m)^  {job}:\s*$")
            block = re.search(rf"(?ms)^  {job}:\s*\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)", source).group(1)
            self.assertRegex(block, r"(?m)^    if:")
            self.assertIn("github.actor == github.repository_owner", block)
            self.assertRegex(block, r"fetch-depth:\s*0")
            self.assertRegex(block, r"persist-credentials:\s*false")
            self.assertRegex(block, r"retention-days:\s*7")
            self.assertRegex(block, r"include-hidden-files:\s*true")
            self.assertRegex(block, r"(?m)^\s+path:.*artifact")
        self.assertRegex(source, r"(?m)^  push:\s*$")
        self.assertRegex(source, r"(?m)^  workflow_dispatch:\s*$")
        self.assertNotRegex(source, r"(?m)^  (?:pull_request(?:_target)?|workflow_run|workflow_call):")
        self.assertIn("github.actor == github.repository_owner", source)
        self.assertRegex(source, r"contents:\s*read")
        self.assertNotRegex(source, r"(?:contents|id-token|actions|deployments):\s*write|write-all")
        self.assertNotIn("secrets.", source)
        actions = re.findall(r"(?m)^\s+(?:-\s+)?uses:\s*([^\s#]+)", source)
        self.assertTrue(actions)
        for action in actions:
            self.assertRegex(action, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[a-f0-9]{40}$")
        self.assertNotRegex(source, r"uses:\s*actions/cache@")
        self.assertRegex(source, r"fetch-depth:\s*0")
        self.assertRegex(source, r"persist-credentials:\s*false")
        self.assertRegex(source, r"retention-days:\s*7")
        self.assertRegex(source, r"include-hidden-files:\s*true")
        uploads = re.findall(r"(?m)^\s+path:\s*(.+)$", source)
        self.assertTrue(any("artifact" in value for value in uploads))
        for value in uploads:
            self.assertNotIn("github.workspace", value)
            self.assertNotEqual(value.strip(" '\""), ".")


class WorkflowStepTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="m2-workflow-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def target(self):
        files = {name: (FIXTURES / name).read_bytes() for name in ("README.md", "target_module.py")}
        files[".gitattributes"] = b"target_module.py filter=workflow-sentinel\n"
        fixture = GitFixture(self.base / "target", files)
        self.original_source = files["target_module.py"]
        marker = fixture.root / "FILTER_EXECUTED"
        script = fixture.root / ".git" / "filter-sentinel.py"
        script.write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).write_text('unexpected filter')\n",
            encoding="utf-8",
        )
        command = f'"{Path(sys.executable).as_posix()}" "{script.as_posix()}"'
        with (fixture.root / ".git" / "config").open("a", encoding="utf-8") as stream:
            stream.write('\n[filter "workflow-sentinel"]\n clean = ' + config_value(command)
                         + "\n smudge = " + config_value(command) + "\n required = true\n")
        # No GitFixture Git call after hostile config was installed.
        return fixture

    def tool_revision(self):
        executable = shutil.which("git")
        self.assertIsNotNone(executable)
        environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                           GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT="0")
        result = subprocess.run([executable, "-C", str(PROJECT), "rev-parse", "HEAD"],
                                env=environment, cwd=self.base, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode("ascii").strip()

    def audit(self, target, *, mode="self", target_sha=None, tool_revision=None,
              target_root=None, output="out", expected=0):
        out = self.base / output
        result = subprocess.run(
            [sys.executable, "-I", str(PROJECT / "scripts" / "workflow_audit.py"), "audit",
             "--mode", mode, "--tool-root", str(PROJECT),
             "--tool-revision", tool_revision or self.tool_revision(),
             "--workflow-revision", "a" * 40, "--trigger-revision", "b" * 40,
             "--repository", "owned-fixture/auditor", "--run-id", "123456",
             "--target-repo", str(target_root or target.root),
             "--target-sha", target_sha or target.head, "--out", str(out)],
            cwd=self.base, capture_output=True, timeout=180,
        )
        self.assertEqual(result.returncode, expected, result.stderr.decode("utf-8", "replace"))
        self.assertNotIn(b"Traceback", result.stderr)
        if expected:
            self.assertFalse((out / "artifact" / "workflow-receipt.json").exists())
        return out

    def test_self_audit_uses_exact_commit_no_target_execution_and_closed_artifact(self):
        """what_bug_this_catches: auditing mutable files, executing target/filter code, or uploading the checkout."""
        target = self.target()
        (target.root / "target_module.py").write_bytes(b"raise RuntimeError('mutable checkout')\n")
        out = self.audit(target)
        artifact = out / "artifact"
        self.assertEqual({path.name for path in artifact.iterdir()}, {"report-export", "workflow-receipt.json"})
        receipt = json.loads((artifact / "workflow-receipt.json").read_bytes())
        self.assertEqual(receipt["requested_target_revision"], target.head)
        self.assertEqual(receipt["snapshot_commit"], target.head)
        self.assertEqual(receipt["tool_revision"], self.tool_revision())
        self.assertEqual(receipt["workflow_revision"], "a" * 40)
        self.assertEqual(receipt["trigger_revision"], "b" * 40)
        self.assertEqual(receipt["action_execution"], "not_observed_by_helper")
        self.assertEqual(receipt["human_live_comparison"], "not_measured")
        exported_run = artifact / "report-export" / "run"
        manifest_raw = (exported_run / "RUN.json").read_bytes()
        self.assertEqual(hashlib.sha256(manifest_raw).hexdigest(), receipt["run_manifest_sha256"])
        manifest = json.loads(manifest_raw)
        self.assertEqual(manifest["state"], "complete")
        self.assertEqual(manifest["attempts"], [])
        for item in receipt["artifacts"]:
            self.assertEqual(hashlib.sha256((artifact / item["path"]).read_bytes()).hexdigest(), item["sha256"])
        actual_export_files = {path.relative_to(artifact).as_posix()
                               for path in (artifact / "report-export").rglob("*") if path.is_file()}
        self.assertEqual({item["path"] for item in receipt["artifacts"]}, actual_export_files)
        for path in artifact.rglob("*"):
            self.assertFalse(path.is_symlink())
            self.assertFalse({".git", ".venv"}.intersection(path.relative_to(artifact).parts))
        self.assertFalse(list(self.base.rglob("TARGET_CODE_EXECUTED")))
        self.assertFalse((target.root / "FILTER_EXECUTED").exists())
        copied = list(artifact.rglob("target_module.py"))
        self.assertTrue(copied)
        self.assertTrue(all(path.read_bytes() == self.original_source for path in copied))
        canonical_copy = exported_run / "snapshot" / "files" / "target_module.py"
        self.assertEqual(canonical_copy.read_bytes(), self.original_source)
        canonical_copy.write_bytes(b"changed frozen source\n")
        tampered = subprocess.run([sys.executable, "-I", "-m", "claim_auditor", "verify-report", str(exported_run)],
                                  cwd=self.base, capture_output=True, timeout=180)
        self.assertEqual(tampered.returncode, 4, tampered.stderr.decode("utf-8", "replace"))

    def test_fixture_snapshot_identity_never_becomes_trigger_or_target_commit(self):
        """what_bug_this_catches: labeling fixed owned fixture evidence as audited Git/trigger revision."""
        target = self.target()
        out = self.audit(target, mode="fixture")
        receipt = json.loads((out / "artifact" / "workflow-receipt.json").read_bytes())
        self.assertEqual(receipt["snapshot_source_kind"], "fixture_inventory")
        self.assertIsNone(receipt["snapshot_commit"])
        self.assertEqual(receipt["requested_target_revision"], target.head)
        self.assertEqual(receipt["trigger_revision"], "b" * 40)

    def test_bad_sha_tool_pin_and_shallow_store_never_publish_closed_artifact(self):
        """what_bug_this_catches: invalid setup becoming a clean successful workflow report."""
        target = self.target()
        for index, bad in enumerate(("HEAD", "A" * 40)):
            with self.subTest(sha=bad):
                self.audit(target, target_sha=bad, output=f"bad-sha-{index}", expected=2)
        self.audit(target, target_sha="0" * 40, output="absent-object", expected=2)
        self.audit(target, mode="fixture", target_sha="0" * 40, output="fixture-absent-object", expected=2)
        self.audit(target, tool_revision="0" * 40, output="wrong-tool", expected=4)
        (target.root / ".git" / "shallow").write_text(target.head + "\n", encoding="ascii")
        self.audit(target, output="shallow", expected=2)

    def test_tool_target_alias_is_refused_without_closed_output(self):
        """what_bug_this_catches: using the trusted tool checkout as the hostile audit target."""
        target = self.target()
        self.audit(target, target_root=PROJECT, output="alias", expected=2)
