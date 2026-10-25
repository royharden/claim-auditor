"""CA10 local step controls; these do not attest that a GitHub Action ran."""

import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from .git_fixture import GitFixture, config_value


PROJECT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "workflow"


class WorkflowSourceTests(unittest.TestCase):
    def document(self, text=None):
        # BaseLoader preserves GitHub's `on` key and treats all scalars as
        # strings. It constructs data only, never Python objects or code.
        import yaml

        class UniqueLoader(yaml.BaseLoader):
            def construct_mapping(self, node, deep=False):
                result = {}
                for key_node, value_node in node.value:
                    key = self.construct_object(key_node, deep=deep)
                    if not isinstance(key, str) or key in result:
                        raise ValueError("workflow mapping key must be unique text")
                    result[key] = self.construct_object(value_node, deep=deep)
                return result

        if text is None:
            text = (PROJECT / ".github" / "workflows" / "claim-audit.yml").read_text(encoding="utf-8")
        return yaml.load(text, Loader=UniqueLoader)

    def predicate(self, expression, context):
        # This is a deliberately restricted, data-only interpreter for the
        # contract's comparisons and Boolean operators, never eval/exec.
        expression = expression.strip()
        if expression.startswith("${{") and expression.endswith("}}"):
            expression = expression[3:-2]
        node = ast.parse("(" + expression.replace("&&", " and ").replace("||", " or ") + ")", mode="eval")

        def evaluate(value):
            if isinstance(value, ast.Expression):
                return evaluate(value.body)
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                return value.value
            if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
                self.assertEqual(value.value.id, "github")
                self.assertIn(value.attr, context)
                return context[value.attr]
            if isinstance(value, ast.Compare):
                self.assertEqual(len(value.ops), 1)
                self.assertIsInstance(value.ops[0], ast.Eq)
                left, right = evaluate(value.left), evaluate(value.comparators[0])
                self.assertIsInstance(left, str)
                self.assertIsInstance(right, str)
                # GitHub expression string equality ignores case.
                return left.casefold() == right.casefold()
            if isinstance(value, ast.BoolOp):
                items = [evaluate(item) for item in value.values]
                self.assertTrue(all(isinstance(item, bool) for item in items))
                if isinstance(value.op, ast.And):
                    return all(items)
                if isinstance(value.op, ast.Or):
                    return any(items)
            self.fail(f"unsupported workflow predicate node: {type(value).__name__}")

        result = evaluate(node)
        self.assertIsInstance(result, bool)
        return result

    def command(self, step):
        """Parse the one allowed Bash command as data, without launching a shell."""
        self.assertEqual(step["shell"], "bash")
        lines = step["run"].replace("\\\n", "").splitlines()
        self.assertEqual(lines[0].strip(), "set -euo pipefail")
        self.assertEqual(len(lines), 2)
        # shlex discards quote kind. Single quotes would prevent the checked
        # environment variables from expanding in the real Bash invocation.
        self.assertNotIn("'", lines[1])
        return shlex.split(lines[1], comments=False, posix=True)

    def check_contract(self, document):
        self.assertNotIn("secrets.", json.dumps(document).lower())
        self.assertEqual(set(document["on"]), {"push", "workflow_dispatch"})
        self.assertEqual(document["on"]["push"], {"branches": ["main"]})
        self.assertEqual(document["permissions"], {"contents": "read"})
        self.assertEqual(set(document["jobs"]), {"self-audit", "fixture-audit"})
        pin = document["env"]["TOOL_REVISION"]
        self.assertRegex(pin, r"\A[a-f0-9]{40}\Z")
        cases = [(ref, event, actor, owner,
                  ref == "refs/heads/main" and
                  (event == "push" or (event == "workflow_dispatch" and actor == owner)))
                 for ref in ("refs/heads/main", "refs/heads/untrusted", "refs/tags/v1")
                 for event in ("push", "workflow_dispatch", "pull_request", "schedule")
                 for actor in ("owner", "maintainer", "other")
                 for owner in ("owner", "maintainer")]
        for name, job in document["jobs"].items():
            self.check_job(name, job, document, pin, cases)

    def check_job(self, name, job, document, pin, cases):
        self.assertEqual(job.get("permissions", document["permissions"]), {"contents": "read"})
        env = {**document["env"], **job.get("env", {})}
        self.assertEqual(env["TOOL_REVISION"], pin)
        for ref, event, actor, owner, expected in cases:
            context = dict(ref=ref, event_name=event, actor=actor, repository_owner=owner)
            self.assertEqual(self.predicate(job["if"], context), expected, (name, context))
        # The bounded eight-step layout makes a correct-looking command in a
        # comment or an unused extra step insufficient to satisfy the contract.
        steps = job["steps"]
        self.assertEqual(len(steps), 8)
        for index, action_name in ((0, "actions/checkout"), (1, "actions/checkout"),
                                   (2, "astral-sh/setup-uv"), (6, "actions/upload-artifact")):
            self.assertEqual(steps[index]["uses"].split("@")[0], action_name)
        for index in (3, 4, 5, 7):
            self.assertIn("run", steps[index])
            self.assertNotIn("uses", steps[index])
        tool_checkouts, workflow_checkouts, setups, uploads = [], [], [], []
        for step in job["steps"]:
            step_env = {**env, **step.get("env", {})}
            self.assertEqual(step_env["TOOL_REVISION"], pin)
            if "uses" in step:
                action = step["uses"]
                self.assertRegex(action, r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[a-f0-9]{40}\Z")
                self.assertNotEqual(action.split("@")[0], "actions/cache")
                if action.startswith("actions/checkout@"):
                    self.assertEqual(step["with"]["fetch-depth"], "0")
                    self.assertEqual(step["with"]["persist-credentials"].lower(), "false")
                    self.assertEqual(step["with"]["submodules"].lower(), "false")
                    self.assertEqual(step["with"]["lfs"].lower(), "false")
                    if step["with"].get("path") == "trusted-tool":
                        self.assertIn(step["with"]["ref"], (pin, "${{ env.TOOL_REVISION }}"))
                        tool_checkouts.append(step)
                    elif step["with"].get("path") == "workflow-source":
                        self.assertEqual(step["with"]["ref"], "${{ github.workflow_sha }}")
                        workflow_checkouts.append(step)
                    else:
                        self.fail("checkout destination is outside the declared workflow layout")
                if action.startswith("astral-sh/setup-uv@"):
                    self.assertEqual(step["with"]["enable-cache"].lower(), "false")
                    self.assertRegex(step["with"]["version"], r"^\d+\.\d+\.\d+$")
                    self.assertRegex(step["with"]["checksum"], r"^[a-f0-9]{64}$")
                    self.assertEqual(step["with"]["working-directory"], "trusted-tool")
                    setups.append(step)
                if action.startswith("actions/upload-artifact@"):
                    settings = step["with"]
                    self.assertEqual(settings["retention-days"], "7")
                    self.assertEqual(settings["include-hidden-files"].lower(), "true")
                    self.assertEqual(settings["if-no-files-found"], "error")
                    self.assertRegex(settings["path"], r"^\$\{\{ runner\.temp \}\}/[A-Za-z0-9_-]+/artifact/$")
                    uploads.append(step)
        self.assertEqual(len(tool_checkouts), 1)
        self.assertEqual(len(workflow_checkouts), 1)
        self.assertEqual(len(setups), 1)
        self.assertEqual(len(uploads), 1)
        install = steps[3]
        self.assertEqual(install["shell"], "bash")
        self.assertEqual(install["run"].splitlines(), [
            "set -euo pipefail",
            'test "$(git -C "$GITHUB_WORKSPACE/trusted-tool" rev-parse HEAD)" = "$TOOL_REVISION"',
            'sh "$GITHUB_WORKSPACE/trusted-tool/scripts/bootstrap.sh"',
        ])
        invocation = ["$GITHUB_WORKSPACE/trusted-tool/.venv/bin/python", "-I",
                      "$GITHUB_WORKSPACE/workflow-source/scripts/workflow_audit.py"]
        self.assertEqual(self.command(steps[4]), invocation + [
            "fetch", "--repository", "$REPOSITORY", "--target-sha", "$TARGET_SHA",
            "--out", "$RUNNER_TEMP/ca10-target",
        ])
        mode = {"self-audit": "self", "fixture-audit": "fixture"}[name]
        self.assertEqual(uploads[0]["with"]["path"], "${{ runner.temp }}/ca10-" + mode + "/artifact/")
        self.assertEqual(self.command(steps[5]), invocation + [
            "audit", "--mode", mode, "--tool-root", "$GITHUB_WORKSPACE/trusted-tool",
            "--tool-revision", "$TOOL_REVISION", "--workflow-revision", "$WORKFLOW_REVISION",
            "--trigger-revision", "$TRIGGER_REVISION", "--trigger-kind", "$TRIGGER_KIND",
            "--repository", "$REPOSITORY", "--run-id", "$ACTION_RUN_ID",
            "--target-repo", "$RUNNER_TEMP/ca10-target", "--target-sha", "$TARGET_SHA",
            "--out", f"$RUNNER_TEMP/ca10-{mode}",
        ])
        expected_env = {"REPOSITORY": "${{ github.repository }}",
                        "TARGET_SHA": "${{ inputs.target_sha || github.sha }}"}
        self.assertEqual(steps[4]["env"], {**expected_env, "WORKFLOW_READ_TOKEN": "${{ github.token }}"})
        self.assertEqual(steps[5]["env"], {**expected_env,
            "WORKFLOW_REVISION": "${{ github.workflow_sha }}", "TRIGGER_REVISION": "${{ github.sha }}",
            "TRIGGER_KIND": "${{ github.event_name }}", "ACTION_RUN_ID": "${{ github.run_id }}"})

    def test_trigger_permissions_action_pins_and_selected_artifact_contract(self):
        """what_bug_this_catches: PR triggers, write permission, moving actions or whole-workspace uploads.

        Bounded source-contract checks complement actual local step controls;
        they do not constitute Action runtime evidence.
        """
        self.check_contract(self.document())

    def test_demonstrated_workflow_mutations_are_rejected(self):
        """what_bug_this_catches: five independent review mutations staying green behind token-presence checks."""
        text = (PROJECT / ".github" / "workflows" / "claim-audit.yml").read_text(encoding="utf-8")
        original = self.document(text)
        self.check_contract(original)  # Positive control: original real workflow passes.
        pin = original["env"]["TOOL_REVISION"]
        mutations = {
            "nonowner-dispatch": ("&& github.actor", "|| github.actor", 2),
            "untrusted-branch": ("branches: [main]", "branches: [main, untrusted]", 1),
            "moving-tool": (pin, "main", 1),
            "setup-cache": ("enable-cache: false", "enable-cache: true", 2),
            "write-scope": ("permissions:\n  contents: read", "permissions:\n  contents: read\n  packages: write", 1),
        }
        for mutation, (old, new, count) in mutations.items():
            with self.subTest(mutation=mutation):
                self.assertEqual(text.count(old), count, "mutation must alter the actual workflow")
                with self.assertRaises(AssertionError):
                    self.check_contract(self.document(text.replace(old, new)))

    def test_each_job_rejects_predicate_cache_permission_and_wiring_mutations(self):
        """what_bug_this_catches: one compliant job or a token in a comment hiding unsafe effective wiring."""
        original = self.document()
        self.check_contract(original)
        for name in original["jobs"]:
            for mutation in ("owner-or", "branch-or", "hardcoded-owner", "setup-cache", "job-write", "write-all",
                             "job-tool-env", "step-tool-env", "moving-checkout", "unused-pin",
                             "wrong-tool-root", "wrong-tool-python", "moving-workflow-glue",
                             "commented-invocation", "fetch-wrong-glue", "install-wrong-tool",
                             "literal-pin", "artifact-mismatch"):
                document = copy.deepcopy(original)
                job = document["jobs"][name]
                steps = job["steps"]
                if mutation == "owner-or":
                    job["if"] = job["if"].replace("&& github.actor", "|| github.actor")
                elif mutation == "branch-or":
                    job["if"] = job["if"].replace("&&", "||", 1)
                elif mutation == "hardcoded-owner":
                    job["if"] = job["if"].replace("github.repository_owner", "'owner'")
                elif mutation == "setup-cache":
                    steps[2]["with"]["enable-cache"] = "true"
                elif mutation == "job-write":
                    job["permissions"]["packages"] = "write"
                elif mutation == "write-all":
                    job["permissions"] = "write-all"
                elif mutation == "job-tool-env":
                    job["env"] = {"TOOL_REVISION": "0" * 40}
                elif mutation == "step-tool-env":
                    steps[5]["env"]["TOOL_REVISION"] = "0" * 40
                elif mutation == "moving-checkout":
                    steps[1]["with"]["ref"] = "main"
                elif mutation == "unused-pin":
                    steps[5]["run"] = steps[5]["run"].replace('"$TOOL_REVISION"', '"main"')
                elif mutation == "wrong-tool-root":
                    steps[5]["run"] = steps[5]["run"].replace(
                        '--tool-root "$GITHUB_WORKSPACE/trusted-tool"', '--tool-root "$RUNNER_TEMP/ca10-target"')
                elif mutation == "wrong-tool-python":
                    steps[5]["run"] = steps[5]["run"].replace("trusted-tool/.venv/bin/python", "target/.venv/bin/python")
                elif mutation == "moving-workflow-glue":
                    steps[0]["with"]["ref"] = "main"
                elif mutation == "commented-invocation":
                    steps[5]["run"] = "set -euo pipefail\n# " + steps[5]["run"].replace("\\\n", "").splitlines()[1] + "\n"
                elif mutation == "fetch-wrong-glue":
                    steps[4]["run"] = steps[4]["run"].replace("workflow-source/scripts/", "target/scripts/")
                elif mutation == "install-wrong-tool":
                    steps[3]["run"] = steps[3]["run"].replace("trusted-tool/scripts/bootstrap.sh", "target/scripts/bootstrap.sh")
                elif mutation == "literal-pin":
                    steps[5]["run"] = steps[5]["run"].replace('"$TOOL_REVISION"', "'$TOOL_REVISION'")
                else:
                    steps[6]["with"]["path"] = "${{ runner.temp }}/unrelated/artifact/"
                with self.subTest(job=name, mutation=mutation):
                    self.assertNotEqual(document, original, "control must actually mutate the workflow")
                    with self.assertRaises(AssertionError):
                        self.check_contract(document)

    def test_duplicate_permission_keys_fail_closed(self):
        """what_bug_this_catches: a YAML parser silently discarding an earlier permission declaration."""
        text = (PROJECT / ".github" / "workflows" / "claim-audit.yml").read_text(encoding="utf-8")
        mutations = [text + "\npermissions:\n  contents: read\n",
                     text.replace("    permissions:\n      contents: read",
                                  "    permissions:\n      packages: write\n    permissions:\n      contents: read", 1),
                     text.replace("  TOOL_REVISION:", "  TOOL_REVISION: main\n  TOOL_REVISION:", 1)]
        for index, mutated in enumerate(mutations):
            with self.subTest(mapping=index), self.assertRaises(ValueError):
                self.document(mutated)


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
