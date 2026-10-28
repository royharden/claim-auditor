"""Local-only CLI; external acquisition, live model calls and publication absent."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pydantic import ValidationError

from .contracts import AuditError, canonical_json


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit bounded static README propositions against frozen Python source.")
    commands = parser.add_subparsers(dest="command", required=True)
    snapshot = commands.add_parser("snapshot", help="Create a fresh loose-file snapshot from one local full Git commit or fixture source.")
    sources = snapshot.add_mutually_exclusive_group(required=True)
    sources.add_argument("--repo", type=Path)
    sources.add_argument("--fixture", type=Path)
    snapshot.add_argument("--commit")
    snapshot.add_argument("--out", type=Path, required=True)
    audit = commands.add_parser("audit", help="Write a fresh offline report; unsupported semantics remain unknown.")
    audit.add_argument("--snapshot", type=Path, required=True)
    audit.add_argument("--readme", default="README.md")
    audit.add_argument("--mode", choices=("rules", "replay", "live"), default="rules")
    audit.add_argument("--replay", type=Path)
    audit.add_argument("--prompt-digest")
    audit.add_argument("--model")
    audit.add_argument("--out", type=Path, required=True)
    audit.add_argument("--fail-on", choices=("missing",))
    verify = commands.add_parser("verify-report", help="Reopen frozen files, citations, coverage and report hashes.")
    verify.add_argument("run", type=Path)
    demo = commands.add_parser("demo", help="Create owned fixture source, snapshot and audit report without keys.")
    demo.add_argument("--offline", action="store_true", required=True)
    demo.add_argument("--out", type=Path, required=True)
    evaluation = commands.add_parser("eval", help="Validate admitted protocol and prepare source-only packet; no live calls.")
    evaluation.add_argument("--protocol", type=Path, required=True)
    evaluation.add_argument("--input", type=Path, required=True)
    evaluation.add_argument("--out", type=Path, required=True)
    score = commands.add_parser("score", help="Score closed predictions against separately supplied labels; no inference.")
    score.add_argument("--predictions", type=Path, required=True)
    score.add_argument("--gold", type=Path, required=True)
    score.add_argument("--out", type=Path, required=True)
    return parser


def _exit_for_manifest(manifest: object) -> int:
    state = getattr(manifest, "state")
    return {"complete": 0, "failed_input": 2, "incomplete": 3, "failed_integrity": 4}.get(state, 3)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "snapshot":
            from .snapshot import create_fixture_snapshot, create_git_snapshot

            if args.repo is not None:
                if args.commit is None:
                    raise AuditError("commit_required", "Git acquisition requires operator-supplied full commit ID.")
                result = create_git_snapshot(args.repo, args.commit, args.out)
            else:
                if args.commit is not None:
                    raise AuditError("fixture_commit_forbidden", "Fixture source cannot claim a Git commit.")
                result = create_fixture_snapshot(args.fixture, args.out)
            print(canonical_json(result).decode("utf-8"))
            return 0
        if args.command == "audit":
            from .audit import audit_snapshot
            from .contracts import AuditReport

            result = audit_snapshot(
                args.snapshot, args.readme, args.mode, args.out,
                replay_path=args.replay, prompt_digest=args.prompt_digest, model=args.model,
            )
            print(canonical_json(result).decode("utf-8"))
            status = _exit_for_manifest(result)
            if status == 0 and args.fail_on == "missing":
                report = AuditReport.model_validate_json((args.out / "report.json").read_bytes())
                if any(finding.verdict == "missing" for finding in report.findings):
                    return 5
            return status
        if args.command == "verify-report":
            from .citations import verify_report

            result = verify_report(args.run)
            print(canonical_json(result).decode("utf-8"))
            return _exit_for_manifest(result)
        if args.command == "demo":
            from .audit import audit_snapshot
            from .report import create_demo_source
            from .snapshot import create_fixture_snapshot

            try:
                args.out.mkdir(parents=True, exist_ok=False)
            except FileExistsError as exc:
                raise AuditError("output_exists", "Demo requires a fresh output directory.") from exc
            source = create_demo_source(args.out / "source")
            create_fixture_snapshot(source, args.out / "snapshot")
            result = audit_snapshot(args.out / "snapshot", "README.md", "rules", args.out / "run")
            print(canonical_json(result).decode("utf-8"))
            print("Runtime/product acceptance unverified; comparative results not measured.", file=sys.stderr)
            return _exit_for_manifest(result)
        if args.command == "eval":
            from .evaluation import prepare_evaluation

            result = prepare_evaluation(args.protocol, args.input, args.out)
            print(canonical_json(result).decode("utf-8"))
            print("not measured / comparative acceptance incomplete", file=sys.stderr)
            return 3  # preparing a packet is not a completed comparison
        if args.command == "score":
            from .evaluation import score_predictions

            result = score_predictions(args.predictions, args.gold, args.out)
            print(canonical_json(result).decode("utf-8"))
            return 0
        raise AuditError("unknown_command", "No handler for requested command.")
    except AuditError as exc:
        print(canonical_json({"error": exc.reason, "detail": exc.detail}).decode("utf-8"), file=sys.stderr)
        return exc.exit_code
    except (ValidationError, ValueError, UnicodeError, OSError) as exc:
        print(canonical_json({"error": "invalid_input", "detail": str(exc)}).decode("utf-8"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
