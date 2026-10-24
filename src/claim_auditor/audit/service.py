"""Offline run lifecycle; no target imports, target commands, or network."""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from ..contracts import (
    Attempt, AuditError, AuditReport, Evidence, Inventory, Limits, PipelineError,
    POLICY_VERSION, PredicateResult, RunDeclarations, RunManifest, TOOL_VERSION, canonical_json, sha256,
)
from ..providers import load_replay, require_no_live
from ..provenance import capture_run_context, context_bytes, guard_tool_paths, legacy_dependencies
from .policy import decide_finding


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _publish_manifest(root: Path, manifest: RunManifest) -> None:
    temp = root / f".RUN-{uuid.uuid4().hex}.tmp"
    with temp.open("xb") as stream:
        stream.write(canonical_json(manifest))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, root / "RUN.json")


def _replay_inventory(
    inventory: Inventory, snapshot: object, snapshot_root: Path,
    replay_path: Path, prompt_digest: str, model: str,
) -> Inventory:
    from ..citations import validate_span

    proposals = load_replay(
        replay_path, input_digest=inventory.readme_sha256, prompt_digest=prompt_digest,
        model=model, readme_text="\n".join(block.span.quote for block in inventory.blocks),
    )
    # Replay may transport only atoms independently recognized by this version's
    # bounded grammar. New semantic extraction remains an unmeasured live arm.
    admitted = {claim.claim_id: claim for claim in inventory.claims}
    if len({claim.claim_id for claim in proposals}) != len(proposals):
        raise AuditError("invalid_replay_claim", "Duplicate proposed atom IDs.", 3)
    for proposal in proposals:
        validate_span(snapshot, snapshot_root, proposal.span)
        canonical = admitted.get(proposal.claim_id)
        if canonical is None or proposal != canonical:
            raise AuditError("unvalidated_model_atom", "Replay proposal differs from independently parsed atom.", 3)
    if {claim.claim_id for claim in proposals} != set(admitted):
        raise AuditError("replay_omission", "Replay omitted inventoried atoms; input accounting cannot drop them.", 3)
    return inventory.model_copy(update={"claims": proposals})


def audit_snapshot(
    snapshot_root: Path,
    readme: str,
    mode: str,
    out: Path,
    *,
    replay_path: Path | None = None,
    prompt_digest: str | None = None,
    model: str | None = None,
    declarations: RunDeclarations | None = None,
) -> RunManifest:
    from ..citations import validate_evidence, validate_span
    from ..index import build_index, resolve
    from ..inventory import extract_inventory
    from ..report import write_reports
    from ..snapshot import load_snapshot, read_source, require_snapshot_root

    require_no_live(mode)
    if mode not in {"rules", "replay"}:
        raise AuditError("invalid_mode", "Use rules or explicitly bound replay; live is unavailable.")
    if mode == "rules" and any(value is not None for value in (replay_path, prompt_digest, model)):
        raise AuditError("unexpected_replay_parameters", "Rules mode cannot record replay/model identity.")
    if mode == "replay" and (replay_path is None or prompt_digest is None or model is None):
        raise AuditError("replay_identity_required", "Replay requires file, prompt digest, and model.")
    # Keep the original path chain so snapshot loader can reject reparse points;
    # resolving here would erase a forbidden symlink supplied as the root.
    source_root = Path(os.path.abspath(snapshot_root))
    destination = Path(out).absolute()
    prospective = destination.resolve()
    if prospective == source_root or source_root in prospective.parents:
        raise AuditError("output_inside_snapshot", "Run output must be separate from the frozen snapshot.")
    guard_tool_paths(source_root, destination)
    require_snapshot_root(source_root)
    snapshot = load_snapshot(source_root)
    limits = Limits()
    started_clock = time.monotonic()
    run_id, started_at = uuid.uuid4().hex, _now()
    context, provenance_errors = capture_run_context(
        run_id=run_id, started_at=started_at, snapshot=snapshot, mode=mode,
        provider="fixture-replay" if mode == "replay" else None, model=model,
        prompt_digest=prompt_digest, packet_digest=None, declarations=declarations,
    )
    try:
        destination.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise AuditError("output_exists", "A run requires a fresh output directory.") from exc
    manifest = RunManifest(
        run_id=run_id, tool_version=TOOL_VERSION, dependencies=legacy_dependencies(context),
        snapshot_id=snapshot.snapshot_id, snapshot_manifest_digest=snapshot.manifest_digest,
        mode=mode, provider="fixture-replay" if mode == "replay" else None, model=model,
        prompt_digest=prompt_digest, packet_digest=None, started_at=started_at, completed_at=None,
        state="created", limits=limits, attempts=[], errors=list(provenance_errors), report_hashes={},
        source_revision=context.tool_revision.value, workflow_revision=context.workflow_revision.value,
        workflow_run_url=context.workflow_run_url.value, run_context=context,
        context_digest=sha256(context_bytes(context)),
    )
    _publish_manifest(destination, manifest)

    def check_deadline() -> None:
        if time.monotonic() - started_clock > limits.audit_seconds:
            raise AuditError("audit_deadline", "Total offline audit deadline exceeded.", 3)

    def transition(state: str) -> None:
        nonlocal manifest
        check_deadline()
        manifest = manifest.model_copy(update={"state": state})
        _publish_manifest(destination, manifest)

    errors: list[PipelineError] = list(provenance_errors)
    try:
        frozen_root = destination / "snapshot"
        frozen_root.mkdir()
        (frozen_root / "files").mkdir()
        for entry in snapshot.entries:
            check_deadline()
            if entry.status != "included":
                continue
            raw = read_source(snapshot, source_root, entry.path)
            target = frozen_root / "files" / entry.path
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(raw)
        (frozen_root / "manifest.json").write_bytes(canonical_json(snapshot))
        frozen = load_snapshot(frozen_root)
        transition("input_validated")
        inventory = extract_inventory(frozen, frozen_root, readme)
        if mode == "replay":
            assert replay_path is not None and prompt_digest is not None and model is not None
            replay_started = time.monotonic()
            inventory = _replay_inventory(inventory, frozen, frozen_root, replay_path, prompt_digest, model)
            manifest = manifest.model_copy(update={"attempts": [Attempt(
                attempt_id=uuid.uuid4().hex, mode="replay", provider="fixture-replay", model=model,
                input_digest=inventory.readme_sha256, prompt_digest=prompt_digest,
                policy_version=POLICY_VERSION, status="replayed", input_tokens=None,
                output_tokens=None, cost_usd=0.0, elapsed_seconds=time.monotonic() - replay_started,
                error=None,
            )]})
        errors = [*provenance_errors, *inventory.errors]
        transition("inventoried")
        static_index = build_index(frozen, frozen_root)
        errors.extend(static_index.errors)
        findings = []
        evidence_by_id: dict[str, Evidence] = {}
        coverage_by_id = {}
        integrity_failed = False
        for claim in inventory.claims:
            check_deadline()
            results: list[PredicateResult] = []
            valid = True
            local_evidence: dict[str, Evidence] = {}
            local_coverage = {}
            # Invalid original claim pointers cannot be emitted in any report.
            # Evidence-only failure below can still retain a valid claim diagnostic.
            validate_span(frozen, frozen_root, claim.span)
            try:
                for predicate in claim.predicates:
                    check_deadline()
                    result = resolve(static_index, predicate)
                    if result.predicate_id != predicate.predicate_id:
                        raise AuditError("predicate_identity_mismatch", "Resolver returned different predicate.", 4)
                    for item in result.evidence:
                        if item.query != predicate:
                            raise AuditError("evidence_query_mismatch", "Evidence is bound to another proposition.", 4)
                        validate_evidence(frozen, frozen_root, item, result.coverage, static_index)
                        if item.evidence_id in local_evidence and local_evidence[item.evidence_id] != item:
                            raise AuditError("evidence_id_collision", "Conflicting evidence identity.", 4)
                        local_evidence[item.evidence_id] = item
                    for coverage in result.coverage:
                        if coverage.query != predicate or coverage.snapshot_id != frozen.snapshot_id:
                            raise AuditError("coverage_identity_mismatch", "Coverage does not bind exact query/snapshot.", 4)
                        local_coverage[coverage.coverage_id] = coverage
                    results.append(result)
            except AuditError as exc:
                if exc.exit_code != 4:
                    raise  # Deadline/setup/parser failure is not citation corruption.
                valid = False
                integrity_failed = True
                errors.append(PipelineError(stage="citations", reason=exc.reason, detail=exc.detail))
            finding = decide_finding(claim, results, citation_valid=valid)
            findings.append(finding)
            if valid:
                for identity, item in local_evidence.items():
                    if identity in evidence_by_id and evidence_by_id[identity] != item:
                        raise AuditError("evidence_id_collision", "Evidence changed across claims.", 4)
                    evidence_by_id[identity] = item
                coverage_by_id.update(local_coverage)
        transition("resolved")
        transition("citations_validated")
        report = AuditReport(
            snapshot=frozen, inventory=inventory, findings=findings,
            evidence=list(evidence_by_id.values()), coverage=list(coverage_by_id.values()),
            errors=errors, mode=mode,
            evaluation_status="not measured / comparative acceptance incomplete; human-adjudicated evaluation not measured; workflow execution not observed",
            run_context=context,
        )
        hashes = write_reports(report, destination)
        if any(hashes.get(name) != manifest.context_digest for name in ("context.json", "context.jsonl")):
            raise AuditError("run_context_digest", "written metadata differs from the immutable pre-render context", 4)
        check_deadline()
        state = "failed_integrity" if integrity_failed else "incomplete" if errors or not inventory.complete else "complete"
        manifest = manifest.model_copy(update={
            "state": state, "completed_at": _now(), "errors": errors, "report_hashes": hashes,
        })
        _publish_manifest(destination, manifest)
        return manifest
    except (AuditError, ValidationError, UnicodeError, OSError, ValueError) as exc:
        error = exc if isinstance(exc, AuditError) else AuditError("pipeline_failure", str(exc), 3)
        state = "failed_integrity" if error.exit_code == 4 else "failed_input" if error.exit_code == 2 else "incomplete"
        manifest = manifest.model_copy(update={
            "state": state, "completed_at": _now(),
            "errors": [*errors, PipelineError(stage="pipeline", reason=error.reason, detail=error.detail)],
        })
        _publish_manifest(destination, manifest)
        if error is exc:
            raise
        raise error from exc
