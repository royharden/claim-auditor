"""Local-only CLI; external acquisition, live model calls and publication absent."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from .contracts import AuditError, ManualAnnotation, RunDeclarations, canonical_json

if TYPE_CHECKING:
    from .providers.experiment import LiveOwnerContext


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
    audit.add_argument("--declarations", type=Path, help="Explicit owner RunDeclarations JSON; never proof of workflow/Git execution.")
    audit.add_argument("--out", type=Path, required=True)
    audit.add_argument("--fail-on", choices=("missing",))
    verify = commands.add_parser("verify-report", help="Reopen frozen files, citations, coverage and report hashes.")
    verify.add_argument("run", type=Path)
    report_export = commands.add_parser("export-report", help="Copy only a verified pinned report/source closure to fresh local output; not publication.")
    report_export.add_argument("--run", type=Path, required=True)
    report_export.add_argument("--manifest-digest", required=True, help="Independently retained raw RUN.json SHA256.")
    report_export.add_argument("--out", type=Path, required=True)
    demo = commands.add_parser("demo", help="Create owned fixture source, snapshot and audit report without keys.")
    demo.add_argument("--offline", action="store_true", required=True)
    demo.add_argument("--out", type=Path, required=True)
    demo.add_argument("--declarations", type=Path, help="Optional explicit owner provenance statements.")
    evaluation = commands.add_parser("eval", help="Validate admitted protocol and prepare source-only packet; no live calls.")
    evaluation.add_argument("--protocol", type=Path, required=True)
    evaluation.add_argument("--input", type=Path, required=True)
    evaluation.add_argument("--out", type=Path, required=True)
    score = commands.add_parser("score", help="Score closed predictions against separately supplied labels; no inference.")
    score.add_argument("--predictions", type=Path, required=True)
    score.add_argument("--gold", type=Path, required=True)
    score.add_argument("--out", type=Path, required=True)
    paired = commands.add_parser("paired-run", help="Future fake/replay assembly only; comparative acceptance remains incomplete.")
    paired.add_argument("--packet", type=Path, required=True)
    paired.add_argument("--snapshot", type=Path, required=True)
    paired.add_argument("--config", type=Path, required=True)
    paired.add_argument("--out", type=Path, required=True)
    annotation = commands.add_parser("annotation-package", help="Prepare full source-first review (--snapshot) or separately labeled assisted review (--run).")
    annotation_sources = annotation.add_mutually_exclusive_group(required=True)
    annotation_sources.add_argument("--snapshot", type=Path)
    annotation_sources.add_argument("--run", type=Path)
    annotation.add_argument("--readme", default="README.md")
    annotation.add_argument("--family-id", required=True)
    annotation.add_argument("--out", type=Path, required=True)
    ruling_import = commands.add_parser("rulings-import", help="Append validated judgments; never manufacture human review.")
    ruling_import.add_argument("--ledger", type=Path, required=True)
    ruling_import.add_argument("--input", type=Path, required=True)
    ruling_import.add_argument("--confirm-human-action", action="store_true",
                               help="Operator explicitly confirms actual human actions identified in incoming records.")
    ruling_export = commands.add_parser("rulings-export", help="Export full append-only ruling history to a fresh file.")
    ruling_export.add_argument("--ledger", type=Path, required=True)
    ruling_export.add_argument("--out", type=Path, required=True)
    paired_verify = commands.add_parser("paired-verify", help="Verify closed paired artifacts/citations; absent external pin is self-consistency only.")
    paired_verify.add_argument("--run", type=Path, required=True)
    paired_verify.add_argument("--snapshot", type=Path, required=True)
    paired_verify.add_argument("--manifest-digest")
    paired_score = commands.add_parser("paired-score", help="Verify paired inference before reading separate gold; fresh output required.")
    paired_score.add_argument("--run", type=Path, required=True)
    paired_score.add_argument("--snapshot", type=Path, required=True)
    paired_score.add_argument("--gold", type=Path, required=True)
    paired_score.add_argument("--out", type=Path, required=True)
    paired_score.add_argument("--manifest-digest")
    dev_stage = commands.add_parser("dev-stage", help="Stage disclosed DEV source with explicit provenance/access receipts; never heldout admission.")
    dev_stage.add_argument("--source", type=Path, required=True)
    dev_stage.add_argument("--out", type=Path, required=True)
    dev_stage.add_argument("--alias", required=True, help="Opaque f- plus 16 lowercase hexadecimal digits.")
    dev_stage.add_argument("--provenance", type=Path, required=True)
    dev_stage.add_argument("--access-receipt", type=Path, required=True)
    dev_export = commands.add_parser("dev-export", help="Verify a pinned DEV seal and export only source to fresh output.")
    dev_export.add_argument("--stage", type=Path, required=True)
    dev_export.add_argument("--seal-digest", required=True)
    dev_export.add_argument("--out", type=Path, required=True)
    paired_input = commands.add_parser("paired-input", help="Write a fresh fake config template with explicit missing-fixture failures, no model output.")
    paired_input.add_argument("--packet", type=Path, required=True)
    paired_input.add_argument("--out", type=Path, required=True)
    dev_packet = commands.add_parser("dev-packet", help="Prepare a DEV-only source packet without inventing a research LOCK or custody.")
    dev_packet.add_argument("--snapshot", type=Path, required=True)
    dev_packet.add_argument("--out", type=Path, required=True)
    annotation_record = commands.add_parser("annotation-record", help="Record an explicitly authored source-first inventory, never candidate-derived human gold.")
    annotation_record.add_argument("--snapshot", type=Path, required=True)
    annotation_record.add_argument("--input", type=Path, required=True)
    annotation_record.add_argument("--out", type=Path, required=True)
    annotation_record.add_argument("--previous", type=Path)
    annotation_record.add_argument("--confirm-human-action", action="store_true")
    annotation_ruling = commands.add_parser("annotation-ruling", help="Bind an explicit judgment/evidence bundle to a source-first manual atom.")
    annotation_ruling.add_argument("--snapshot", type=Path, required=True)
    annotation_ruling.add_argument("--annotation", type=Path, required=True)
    annotation_ruling.add_argument("--ledger", type=Path, required=True)
    annotation_ruling.add_argument("--atom", type=Path, required=True)
    annotation_ruling.add_argument("--evidence", type=Path, required=True)
    annotation_ruling.add_argument("--recorded-at", required=True)
    annotation_ruling.add_argument("--human-action-id")
    annotation_ruling.add_argument("--supersedes-ruling-id")
    annotation_ruling.add_argument("--confirm-human-action", action="store_true")
    annotation_export = commands.add_parser("annotation-export", help="Export explicitly selected agent proposals; human gold needs separate explicit action.")
    annotation_export.add_argument("--snapshot", type=Path, required=True)
    annotation_export.add_argument("--annotation", type=Path, required=True)
    annotation_export.add_argument("--ledger", type=Path, required=True)
    annotation_export.add_argument("--selection", type=Path, required=True)
    annotation_export.add_argument("--out", type=Path, required=True)
    annotation_export.add_argument("--human-gold", action="store_true")
    annotation_export.add_argument("--confirm-human-action", action="store_true")
    live_experiment = commands.add_parser("live-experiment", help="Dormant locked experiment; requires an injected trusted owner context, never reads keys.")
    live_experiment.add_argument("--protocol", type=Path, required=True)
    live_experiment.add_argument("--protocol-digest", required=True)
    live_experiment.add_argument("--snapshot", type=Path, required=True)
    live_experiment.add_argument("--config", type=Path, required=True)
    live_experiment.add_argument("--out", type=Path, required=True)
    dataset = commands.add_parser("dataset-score", help="Preflight every pinned case before reading gold, then aggregate with existing scorer authority.")
    dataset.add_argument("--manifest", type=Path, required=True)
    dataset.add_argument("--manifest-digest", required=True)
    dataset.add_argument("--out", type=Path)
    dataset.add_argument("--preflight", action="store_true", help="Verify global source/run closure only; no score output or gold reads.")
    budget_reconcile = commands.add_parser("budget-reconcile", help="Dormant explicit owner receipt reconciliation; never reset unresolved liability.")
    budget_reconcile.add_argument("--record", type=Path, required=True)
    budget_reconcile.add_argument("--config", type=Path, required=True)
    budget_reconcile.add_argument("--role", choices=("extraction", "single_pass"), required=True)
    budget_reconcile.add_argument("--usage-receipt", type=Path, required=True)
    budget_reconcile.add_argument("--pricing-receipt", type=Path, required=True)
    return parser


def _exit_for_manifest(manifest: object) -> int:
    state = getattr(manifest, "state")
    return {"complete": 0, "failed_input": 2, "incomplete": 3, "failed_integrity": 4}.get(state, 3)


def _manual_draft(snapshot_root: Path, path: Path) -> ManualAnnotation:
    """Validate draft inputs through the sole ManualAnnotation wire authority.

    The service supplies content-addressed ID/supersession when recording. No
    status, completion observation, identity or action is inferred in this helper.
    """
    from .snapshot import load_snapshot
    from .snapshot.safeio import read_ordinary

    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate draft JSON field")
            result[key] = value
        return result

    fields = json.loads(read_ordinary(path.parent, path.name, cap=4 * 1024 * 1024), object_pairs_hook=unique)
    required = set(ManualAnnotation.model_fields) - {"annotation_id", "supersedes_annotation_id"}
    if not isinstance(fields, dict) or set(fields) != required:
        raise AuditError("invalid_manual_draft", "Supply exactly ManualAnnotation fields except service-owned annotation_id and supersedes_annotation_id.")
    draft = ManualAnnotation.model_validate_json(canonical_json({
        **fields, "annotation_id": "draft:not-recorded", "supersedes_annotation_id": None,
    }))
    if draft.source_manifest_digest != load_snapshot(snapshot_root).manifest_digest:
        raise AuditError("manual_source_mismatch", "Draft source differs from the selected frozen snapshot.", 4)
    return draft


def _run_declarations(path: Path | None) -> RunDeclarations | None:
    """Read only explicit bounded owner statements; omitted fields are not inferred."""
    if path is None:
        return None
    from .snapshot.safeio import read_ordinary

    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate declaration JSON field")
            result[key] = value
        return result

    def invalid_constant(value: str) -> object:
        raise ValueError("nonfinite declaration JSON value")

    fields = json.loads(read_ordinary(path.parent, path.name, cap=64 * 1024),
                        object_pairs_hook=unique, parse_constant=invalid_constant)
    return RunDeclarations.model_validate_json(canonical_json(fields))


def main(argv: list[str] | None = None, *, owner_context: LiveOwnerContext | None = None) -> int:
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
                declarations=_run_declarations(args.declarations),
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
        if args.command == "export-report":
            from .report.export import export_report

            print("Local export includes frozen source that may be private; no publication permission is granted.", file=sys.stderr)
            result = export_report(args.run, args.out, manifest_digest=args.manifest_digest)
            print(canonical_json(result).decode("utf-8"))
            return 0
        if args.command == "demo":
            from .audit import audit_snapshot
            from .report import create_demo_source
            from .snapshot import create_fixture_snapshot

            declarations = _run_declarations(args.declarations)
            try:
                args.out.mkdir(parents=True, exist_ok=False)
            except FileExistsError as exc:
                raise AuditError("output_exists", "Demo requires a fresh output directory.") from exc
            source = create_demo_source(args.out / "source")
            create_fixture_snapshot(source, args.out / "snapshot")
            result = audit_snapshot(args.out / "snapshot", "README.md", "rules", args.out / "run",
                                    declarations=declarations)
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
        if args.command == "paired-run":
            from .contracts import EvaluationPacket, PairedRunConfig
            from .evaluation.runner import run_paired
            from .providers import FakeTransport, ReplayTransport
            from .snapshot.safeio import read_ordinary

            packet = EvaluationPacket.model_validate_json(read_ordinary(args.packet.parent, args.packet.name, cap=4 * 1024 * 1024))
            config = PairedRunConfig.model_validate_json(read_ordinary(args.config.parent, args.config.name, cap=8 * 1024 * 1024))
            if config.mode == "fake":
                transports = {arm: FakeTransport(fixtures) for arm, fixtures in config.fixtures.items()}
            else:
                transports = {arm: ReplayTransport([args.config.parent.joinpath(*path.split("/")) for path in paths])
                              for arm, paths in config.replay_files.items()}
            result = run_paired(packet, args.snapshot, args.out, transports=transports,
                                caps=config.caps, prompts=config.prompts, models=config.models,
                                include_full_index=config.include_full_index)
            print(canonical_json(result).decode("utf-8"))
            print("fake/replay source assembly; runtime unverified; not measured / comparative acceptance incomplete", file=sys.stderr)
            return 3
        if args.command == "annotation-package":
            if args.snapshot is not None:
                from .evaluation.annotation import prepare_source_annotation

                digest = prepare_source_annotation(args.snapshot, args.out, family_id=args.family_id,
                                                   readme_path=args.readme)
                review_mode = "source_first"
            else:
                from .evaluation.rulings import prepare_annotation_package

                if args.readme != "README.md":
                    raise AuditError("unexpected_readme_option", "Assisted review uses the verified report's own README identity.")
                digest = prepare_annotation_package(args.run, args.out, family_id=args.family_id)
                review_mode = "report_assisted"
            print(canonical_json({"package_digest": digest, "human_review_performed": False,
                                  "gold_created": False, "review_mode": review_mode}).decode("utf-8"))
            return 0
        if args.command == "rulings-import":
            from .evaluation.rulings import import_rulings

            added = import_rulings(args.ledger, args.input, human_confirmation=args.confirm_human_action)
            print(canonical_json({"appended": len(added), "consensus_created": False}).decode("utf-8"))
            return 0
        if args.command == "rulings-export":
            from .evaluation.rulings import export_rulings

            print(canonical_json({"export_digest": export_rulings(args.ledger, args.out)}).decode("utf-8"))
            return 0
        if args.command == "paired-verify":
            from .evaluation import verify_paired

            result = verify_paired(args.run, args.snapshot, manifest_digest=args.manifest_digest)
            print(canonical_json({"manifest_digest": result["manifest_digest"],
                                  "externally_pinned": args.manifest_digest is not None,
                                  "comparative_complete": False,
                                  "human_adjudicated": False}).decode("utf-8"))
            return 0
        if args.command == "paired-score":
            from .evaluation import score_paired

            result = score_paired(args.run, args.snapshot, args.gold, args.out,
                                  manifest_digest=args.manifest_digest)
            print(canonical_json(result).decode("utf-8"))
            print("scoring does not complete actual live/human comparative acceptance", file=sys.stderr)
            return 3
        if args.command == "dev-stage":
            from .evaluation.custody import stage_dev_family

            digest = stage_dev_family(args.source, args.out, alias=args.alias,
                                      provenance_path=args.provenance,
                                      access_receipt_path=args.access_receipt,
                                      designation="DEV_ONLY", admission_requested=False)
            print(canonical_json({"seal_digest": digest, "designation": "DEV_ONLY",
                                  "custody_verified": False, "heldout": False,
                                  "admitted": False}).decode("utf-8"))
            return 0
        if args.command == "dev-export":
            from .evaluation.custody import export_dev_source

            digest = export_dev_source(args.stage, args.out, expected_seal_digest=args.seal_digest)
            print(canonical_json({"source_manifest_digest": digest, "designation": "DEV_ONLY",
                                  "custody_verified": False, "heldout": False,
                                  "admitted": False}).decode("utf-8"))
            return 0
        if args.command == "paired-input":
            from .providers.config import write_fake_config

            write_fake_config(args.packet, args.out)
            print(canonical_json({"mode": "fake", "fixture_status": "fixture_not_supplied",
                                  "predictions_created": False, "comparative_complete": False}).decode("utf-8"))
            return 0
        if args.command == "dev-packet":
            from .evaluation.packet import prepare_dev_packet

            packet = prepare_dev_packet(args.snapshot, args.out)
            print(canonical_json({"packet_digest": packet.packet_digest, "designation": "DEV_ONLY",
                                  "source_only": True, "admitted": False,
                                  "comparative_complete": False}).decode("utf-8"))
            return 0
        if args.command == "annotation-record":
            from .evaluation.annotation import record_manual_annotation

            draft = _manual_draft(args.snapshot, args.input)
            result = record_manual_annotation(args.snapshot, args.out, family_id=draft.family_id,
                                               inventory=draft.inventory, parent_spans=draft.parent_spans,
                                               annotator_type=draft.annotator_type, annotator_id=draft.annotator_id,
                                               recorded_at=draft.recorded_at, action_id=draft.action_id,
                                               previous_path=args.previous,
                                               human_confirmation=args.confirm_human_action)
            print(canonical_json(result).decode("utf-8"))
            return 0
        if args.command == "annotation-ruling":
            from .contracts import GoldAtom
            from .evaluation.annotation import record_manual_ruling
            from .snapshot.safeio import read_ordinary

            atom = GoldAtom.model_validate_json(read_ordinary(args.atom.parent, args.atom.name, cap=256 * 1024))
            row = record_manual_ruling(args.snapshot, args.annotation, args.ledger, atom=atom,
                                       evidence_path=args.evidence, recorded_at=args.recorded_at,
                                       human_action_id=args.human_action_id,
                                       supersedes_ruling_id=args.supersedes_ruling_id,
                                       human_confirmation=args.confirm_human_action)
            print(canonical_json(row).decode("utf-8"))
            return 0
        if args.command == "annotation-export":
            from .contracts import ManualExportConfig
            from .evaluation.annotation import export_manual_gold, export_manual_proposals
            from .snapshot.safeio import read_ordinary

            config = ManualExportConfig.model_validate_json(read_ordinary(args.selection.parent, args.selection.name, cap=4 * 1024 * 1024))
            evidence = {key: args.selection.parent.joinpath(*value.split("/"))
                        for key, value in config.evidence_files.items()}
            if args.human_gold:
                if (config.operator_id is None or config.action_id is None or config.recorded_at is None
                        or config.adjudication_rationale is None):
                    raise AuditError("human_action_required", "Human export requires explicit operator/action/date/rationale inputs.")
                digest = export_manual_gold(args.snapshot, args.annotation, args.ledger, args.out,
                                             evidence_files=evidence, ruling_ids=config.ruling_ids,
                                             operator_id=config.operator_id, action_id=config.action_id,
                                             recorded_at=config.recorded_at,
                                             adjudication_rationale=config.adjudication_rationale,
                                             human_confirmation=args.confirm_human_action)
                release_kind = "human_confirmed_gold"
            else:
                if args.confirm_human_action or config.operator_id is not None:
                    raise AuditError("unexpected_human_export_fields", "Proposal export must use null human action fields and no human confirmation flag.")
                digest = export_manual_proposals(args.snapshot, args.annotation, args.ledger, args.out,
                                                  evidence_files=evidence, ruling_ids=config.ruling_ids)
                release_kind = "agent_preliminary_proposals"
            print(canonical_json({"export_digest": digest, "mode": release_kind,
                                  "custody_verified": False, "heldout": False,
                                  "admitted": False, "comparative_complete": False}).decode("utf-8"))
            return 0
        if args.command == "live-experiment":
            from .providers.experiment import LiveOwnerContext, run_configured_live

            # Even owner-config/protocol/snapshot bytes remain unopened until
            # the trusted launcher supplies its explicit in-memory activation.
            if type(owner_context) is not LiveOwnerContext or not owner_context.activated:
                raise AuditError("live_not_authorized", "A future trusted owner launcher must inject activation and credentials; CLI/ENV/config cannot supply them.")
            roles = {"extraction", "single_pass"}
            headers = owner_context.credential_headers
            if headers is None or set(headers) != roles or any(not headers[role] for role in roles):
                raise AuditError("live_not_authorized", "Both roles require explicit owner credential injection before configuration/source reads.")
            if owner_context.ledger_root is None or owner_context.budget_admission is None:
                raise AuditError("durable_budget_admission_required", "Actual owner context must select and bind a durable ledger root.", 3)
            from .contracts import LiveExperimentConfig
            from .snapshot.safeio import read_ordinary

            config = LiveExperimentConfig.model_validate_json(read_ordinary(args.config.parent, args.config.name, cap=2 * 1024 * 1024))
            result = run_configured_live(args.protocol, args.snapshot, args.out,
                                         protocol_digest=args.protocol_digest, config=config,
                                         credential_headers=owner_context.credential_headers,
                                         owner_activation=owner_context.activated,
                                         ledger_root=owner_context.ledger_root,
                                         budget_admission=owner_context.budget_admission,
                                         settlement_observers=owner_context.settlement_observers)
            print(canonical_json(result).decode("utf-8"))
            print("owner-enabled experiment source; comparative/human/product acceptance remains incomplete", file=sys.stderr)
            return 3
        if args.command == "dataset-score":
            from .evaluation.dataset import evaluate_dataset, preflight_dataset

            if args.preflight:
                if args.out is not None:
                    raise AuditError("unexpected_output_option", "Dataset preflight does not write scores; omit --out.")
                preflight_dataset(args.manifest, manifest_digest=args.manifest_digest)
                print(canonical_json({"manifest_digest": args.manifest_digest,
                                      "mode": "preflight_only", "scores_created": False,
                                      "comparative_complete": False}).decode("utf-8"))
                return 0
            if args.out is None:
                raise AuditError("output_required", "Dataset scoring requires a fresh --out directory.")
            result = evaluate_dataset(args.manifest, args.out, manifest_digest=args.manifest_digest)
            print(canonical_json(result).decode("utf-8"))
            print("dataset output is not independent product or custody acceptance", file=sys.stderr)
            return 3
        if args.command == "budget-reconcile":
            from .providers.experiment import LiveOwnerContext, reconcile_configured_budget

            if (type(owner_context) is not LiveOwnerContext or not owner_context.activated
                    or owner_context.ledger_root is None or owner_context.budget_admission is None):
                raise AuditError("live_not_authorized", "Explicit trusted owner budget context required before record/ledger reads.")
            from .contracts import LiveExperimentConfig, ReservationReconciliation
            from .snapshot.safeio import read_ordinary

            config = LiveExperimentConfig.model_validate_json(read_ordinary(args.config.parent, args.config.name, cap=2 * 1024 * 1024))
            record = ReservationReconciliation.model_validate_json(read_ordinary(args.record.parent, args.record.name, cap=16 * 1024 * 1024))
            usage_receipt_data = read_ordinary(args.usage_receipt.parent, args.usage_receipt.name, cap=8 * 1024 * 1024)
            pricing_receipt_data = read_ordinary(args.pricing_receipt.parent, args.pricing_receipt.name, cap=2 * 1024 * 1024)
            state = reconcile_configured_budget(owner_context=owner_context, config=config, role=args.role,
                                                record=record, usage_receipt_data=usage_receipt_data,
                                                pricing_receipt_data=pricing_receipt_data)
            print(canonical_json(state).decode("utf-8"))
            return 0
        raise AuditError("unknown_command", "No handler for requested command.")
    except AuditError as exc:
        print(canonical_json({"error": exc.reason, "detail": exc.detail}).decode("utf-8"), file=sys.stderr)
        return exc.exit_code
    except (ValidationError, ValueError, UnicodeError, OSError, RecursionError, MemoryError) as exc:
        print(canonical_json({"error": "invalid_input", "detail": str(exc)}).decode("utf-8"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
