"""Trusted workflow glue; target bytes enter only the canonical offline CLI.

No target checkout/import/build, generic URL, credential file or alternate verifier.
The fetch command is for future authorized Actions execution, never local validation.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

SHA = re.compile(r"[a-f0-9]{40}")
REPOSITORY = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*")
MAX_STORE_BYTES = 500 * 1024 * 1024
FIXTURE = Path("fixtures/corpus-dev/ledger-cli/source")


class Refusal(Exception):
    def __init__(self, reason: str, code: int = 2):
        self.reason, self.code = reason, code


def _sha(value: str) -> str:
    if not SHA.fullmatch(value):
        raise Refusal("full_lowercase_sha1_required")
    return value


def _ordinary(path: Path) -> None:
    for parent in [*reversed(path.absolute().parents), path.absolute()]:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise Refusal("ordinary_directory_required")


def _separate(first: Path, second: Path) -> None:
    a, b = first.resolve(), second.resolve()
    if a == b or a in b.parents or b in a.parents:
        raise Refusal("tool_target_output_must_be_disjoint")


def _git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.pop("WORKFLOW_READ_TOKEN", None)
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_NO_REPLACE_OBJECTS="1", GIT_CONFIG_COUNT="0",
               GIT_ALLOW_PROTOCOL="https", GIT_OPTIONAL_LOCKS="0")
    return env


def _git(target: Path) -> str:
    # Both sides must be physical identities: a PATH junction or Windows 8.3
    # spelling must not disguise an executable inside the untrusted target.
    target_identity = target.resolve(strict=True)
    cwd = Path.cwd().resolve(strict=True)
    name = "git.exe" if os.name == "nt" else "git"
    for entry in os.get_exec_path():
        directory = Path(entry)
        if not directory.is_absolute():
            continue
        try:
            executable = (directory / name).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if (executable == target_identity or target_identity in executable.parents
                or executable.parent == cwd):
            continue
        if os.name == "nt" and executable.suffix.casefold() != ".exe":
            continue
        if executable.is_file() and (os.name == "nt" or os.access(executable, os.X_OK)):
            return str(executable)
    raise Refusal("trusted_git_unavailable")


def _git_read(root: Path, *args: str, target: Path) -> str:
    result = subprocess.run([_git(target), "-C", str(root), *args], env=_git_env(),
                            capture_output=True, timeout=30, check=False)
    if result.returncode or len(result.stdout) > 4096:
        raise Refusal("git_identity_refused")
    return result.stdout.decode("ascii").strip()


def fetch(repository: str, target_sha: str, out: Path) -> None:
    """Fetch only this GitHub repository into a new no-checkout object store."""
    _sha(target_sha)
    if not REPOSITORY.fullmatch(repository):
        raise Refusal("invalid_repository")
    _ordinary(out.parent)
    out.mkdir(exist_ok=False)
    template = out / "empty-template"
    template.mkdir()
    store = out / ".git"
    env = _git_env()
    command = [_git(out), "init", "--bare", "--object-format=sha1", f"--template={template}", str(store)]
    result = subprocess.run(command, env=env, cwd=out.parent, capture_output=True, timeout=30)
    if result.returncode:
        raise Refusal("git_store_setup_failed")
    # Only the future runner's built-in read-only token; never persisted in config.
    token = os.environ.get("WORKFLOW_READ_TOKEN")
    if token:
        header = base64.b64encode(("x-access-token:" + token).encode()).decode("ascii")
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                   GIT_CONFIG_VALUE_0="AUTHORIZATION: basic " + header)
    args = [_git(out), f"--git-dir={store}", "-c", "credential.helper=", "-c", "gc.auto=0",
            "-c", "fetch.recurseSubmodules=false", "fetch", "--quiet", "--no-tags",
            "--no-recurse-submodules", "--no-write-fetch-head",
            f"https://github.com/{repository}.git", f"{target_sha}:refs/heads/audited"]
    # Capture errors outside logs; transfer timeout/store cap fail closed.
    with tempfile.TemporaryFile() as diagnostics:
        process = subprocess.Popen(args, cwd=out.parent, env=env, stdout=diagnostics, stderr=diagnostics)
        started = time.monotonic()
        try:
            while process.poll() is None:
                total = sum(p.stat().st_size for p in store.rglob("*") if p.is_file())
                if (total > MAX_STORE_BYTES or diagnostics.tell() > 1024 * 1024
                        or time.monotonic() - started > 120):
                    raise Refusal("fetch_resource_limit", 3)
                time.sleep(0.1)
            if process.returncode:
                raise Refusal("git_fetch_failed", 3)
            if sum(p.stat().st_size for p in store.rglob("*") if p.is_file()) > MAX_STORE_BYTES:
                raise Refusal("fetch_resource_limit", 3)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    result = subprocess.run([_git(out), f"--git-dir={store}", "symbolic-ref", "HEAD", "refs/heads/audited"],
                            cwd=out.parent, env=_git_env(), capture_output=True, timeout=30)
    if result.returncode or _git_read(out, "rev-parse", "HEAD", target=out) != target_sha:
        raise Refusal("fetched_target_identity_mismatch", 4)
    if _git_read(out, "rev-parse", "--is-shallow-repository", target=out) != "false":
        raise Refusal("complete_nonshallow_store_required")


def audit(args: argparse.Namespace) -> None:
    for value in (args.tool_revision, args.target_sha, args.workflow_revision, args.trigger_revision):
        _sha(value)
    if not REPOSITORY.fullmatch(args.repository) or not re.fullmatch(r"[1-9][0-9]*", args.run_id):
        raise Refusal("invalid_workflow_metadata")
    for root in (args.tool_root, args.target_repo):
        _ordinary(root)
    _ordinary(args.target_repo / ".git")
    _separate(args.tool_root, args.target_repo)
    for root in (args.tool_root, args.target_repo):
        _separate(root, args.out)
    if args.out.exists() or args.out.is_symlink():
        raise Refusal("fresh_output_required")
    if _git_read(args.tool_root, "rev-parse", "HEAD", target=args.target_repo) != args.tool_revision:
        raise Refusal("trusted_tool_revision_mismatch", 4)
    if _git_read(args.tool_root, "status", "--porcelain", "--untracked-files=all", "--",
                 "src/claim_auditor", "pyproject.toml", "uv.lock", target=args.target_repo):
        raise Refusal("trusted_tool_source_dirty", 4)
    ignored = _git_read(args.tool_root, "ls-files", "--others", "--ignored", "--exclude-standard",
                        "--", ":(glob)src/claim_auditor/**/*.py", target=args.target_repo)
    if any(path.endswith(".py") for path in ignored.splitlines()):
        raise Refusal("untracked_trusted_python_source", 4)
    # Do not run even rev-parse against target-controlled repository config.
    # The canonical isolated object reader validates the requested commit below.
    if os.path.lexists(args.target_repo / ".git" / "shallow"):
        raise Refusal("complete_nonshallow_store_required")
    import claim_auditor
    from claim_auditor.cli import main as cli
    from claim_auditor.contracts import canonical_json

    origin = Path(claim_auditor.__file__).resolve()
    if args.tool_root.resolve() / "src" not in origin.parents:
        raise Refusal("installed_tool_origin_mismatch", 4)
    args.out.mkdir(parents=True, exist_ok=False)
    log = io.StringIO()

    def invoke(argv: list[str]) -> None:
        with redirect_stdout(log), redirect_stderr(log):
            status = cli(argv)
        (args.out / "step-diagnostics.txt").write_text(log.getvalue(), encoding="utf-8")
        if status:
            raise Refusal("canonical_cli_step_refused", status)

    declarations = dict(owner_id="trusted-workflow", tool_revision=args.tool_revision,
                        workflow_revision=args.workflow_revision, trigger_revision=args.trigger_revision,
                        trigger_kind=args.trigger_kind,
                        workflow_run_url=f"https://github.com/{args.repository}/actions/runs/{args.run_id}")
    declaration_path = args.out / "declarations.json"
    declaration_path.write_bytes(canonical_json(declarations))
    snapshot, run = args.out / "snapshot", args.out / "run"
    if args.mode == "fixture":
        # Prove the fetched target identity without labeling fixture bytes as it.
        # This temporary target snapshot is never part of the uploaded fixture run.
        target_admission = args.out / "target-admission"
        invoke(["snapshot", "--repo", str(args.target_repo), "--commit", args.target_sha,
                "--out", str(target_admission)])
        if json.loads((target_admission / "manifest.json").read_bytes())["commit"] != args.target_sha:
            raise Refusal("snapshot_target_identity_mismatch", 4)
    source_args = (["--repo", str(args.target_repo), "--commit", args.target_sha] if args.mode == "self"
                   else ["--fixture", str(args.tool_root / FIXTURE)])
    invoke(["snapshot", *source_args, "--out", str(snapshot)])
    invoke(["audit", "--snapshot", str(snapshot), "--mode", "rules", "--readme", "README.md",
            "--declarations", str(declaration_path), "--out", str(run)])
    invoke(["verify-report", str(run)])
    manifest_raw = (run / "RUN.json").read_bytes()
    manifest = json.loads(manifest_raw)
    report = json.loads((run / "report.json").read_bytes())
    target = report["snapshot"]
    if args.mode == "self" and target["commit"] != args.target_sha:
        raise Refusal("snapshot_target_identity_mismatch", 4)
    if args.mode == "fixture" and (target["source_kind"] != "fixture_inventory" or target["commit"] is not None):
        raise Refusal("fixture_identity_mismatch", 4)
    pin = hashlib.sha256(manifest_raw).hexdigest()
    artifact = args.out / "artifact"
    artifact.mkdir()
    exported = artifact / "report-export"
    invoke(["export-report", "--run", str(run), "--manifest-digest", pin, "--out", str(exported)])
    invoke(["verify-report", str(exported / "run")])
    inventory = []
    for path in sorted(exported.rglob("*")):
        if path.is_symlink():
            raise Refusal("unexpected_export_link", 4)
        if path.is_file():
            inventory.append(dict(path=path.relative_to(artifact).as_posix(),
                                  sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    receipt = dict(format="workflow-step/1", mode=args.mode, tool_revision=args.tool_revision,
                   workflow_revision=args.workflow_revision, trigger_revision=args.trigger_revision,
                   requested_target_revision=args.target_sha, snapshot_source_kind=target["source_kind"],
                   snapshot_commit=target["commit"], snapshot_manifest_digest=target["manifest_digest"],
                   run_id=manifest["run_id"], run_manifest_sha256=pin, artifacts=inventory,
                   workflow_metadata_basis="owner_declared; local simulation is not an Action run",
                   action_execution="not_observed_by_helper", human_live_comparison="not_measured")
    (artifact / "workflow-receipt.json").write_bytes(canonical_json(receipt) + b"\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    remote = commands.add_parser("fetch")
    for command in (remote,):
        command.add_argument("--repository", required=True)
        command.add_argument("--target-sha", required=True)
        command.add_argument("--out", required=True, type=Path)
    local = commands.add_parser("audit")
    local.add_argument("--mode", required=True, choices=("self", "fixture"))
    for name in ("tool-root", "target-repo", "out"):
        local.add_argument("--" + name, type=Path, required=True)
    for name in ("tool-revision", "workflow-revision", "trigger-revision", "repository", "run-id", "target-sha"):
        local.add_argument("--" + name, required=True)
    local.add_argument("--trigger-kind", choices=("push", "workflow_dispatch"), default="workflow_dispatch")
    args = parser.parse_args(argv)
    try:
        if args.command == "fetch":
            fetch(args.repository, args.target_sha, args.out)
        else:
            audit(args)
        print('{"workflow_step":"complete"}')
        return 0
    except Refusal as exc:
        print(json.dumps({"error": exc.reason}, ensure_ascii=True), file=sys.stderr)
        return exc.code
    except (OSError, ValueError, ImportError, subprocess.SubprocessError):
        print('{"error":"workflow_setup_or_io_refused"}', file=sys.stderr)
        return 2
    except Exception:
        print('{"error":"workflow_step_incomplete"}', file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
