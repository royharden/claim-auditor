"""Trusted-tool source observations and immutable pre-render run context.

No Git process, environment credential lookup, target import, network call or
workflow discovery occurs. Owner declarations never become observed execution.
"""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.metadata
import os
from pathlib import Path
import re
import sys

from claim_auditor.contracts import (
    AuditError, AuditReport, PipelineError, ProvenanceIdentity, RunContext,
    RunDeclarations, RunManifest, Snapshot, TOOL_VERSION, canonical_json, sha256, stable_id,
)

CONTEXT_VERSION = "run-context/1"
CODE_DIGEST_METHOD = "trusted-package-py-sha256/1"
_DISTRIBUTIONS = ("claim-auditor", "pydantic", "markdown-it-py")
_COMMIT = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")
_DIGEST = re.compile(r"[a-f0-9]{64}")
_ACTION_URL = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+")


def code_digest() -> str:
    """Single authority, unchanged packet.py algorithm over trusted package *.py.

    Root expression changes only because this module sits one directory above
    evaluation/packet.py. File ordering, input tuples, serialization and refusal
    behavior are identical. A digest is not an immutable-install/Git proof.
    """
    package = Path(__file__).resolve().parent
    entries = []
    for source in sorted(package.rglob("*.py")):
        if source.is_symlink():
            raise AuditError("unsafe_tool_source", "tool source must contain ordinary files")
        entries.append([source.relative_to(package).as_posix(), sha256(source.read_bytes())])
    return sha256(canonical_json(entries))


def guard_tool_paths(snapshot_root: Path, out: Path) -> None:
    """Keep copied target *.py and generated runs outside trusted tool scope.

    Resolution is only for this exclusion check; original snapshot paths are
    preserved for the existing ordinary-file/reparse protections at actual reads.
    """
    tool = Path(__file__).resolve().parent
    for value in (snapshot_root, out):
        path = Path(os.path.abspath(value)).resolve()
        if path == tool or tool in path.parents:
            raise AuditError("audit_path_inside_tool_source", "target snapshots/run outputs must not enter trusted tool package source")


def _identity(value: str | None, basis: str, source: str) -> ProvenanceIdentity:
    return ProvenanceIdentity(value=value, basis=basis if value is not None else "unknown", source=source)


def _date(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed > datetime.now(timezone.utc):
            raise ValueError("aware nonfuture date required")
    except ValueError as exc:
        raise AuditError("invalid_run_context_date", "run start must be an actual aware nonfuture timestamp", 4) from exc


def _declarations(value: RunDeclarations | None) -> dict[str, ProvenanceIdentity]:
    names = ("tool_revision", "workflow_revision", "workflow_run_url", "trigger_revision", "trigger_kind")
    if value is None:
        return {name: _identity(None, "unknown", "not supplied; no Git/environment/workflow discovery") for name in names}
    value = RunDeclarations.model_validate_json(canonical_json(value))
    if not value.owner_id.strip() or len(value.owner_id) > 200:
        raise AuditError("invalid_run_declarations", "explicit bounded owner identity required")
    result = {}
    for name in names:
        item = getattr(value, name)
        if item is not None and (not item.strip() or len(item) > 2048):
            raise AuditError("invalid_run_declarations", "declarations must be nonblank bounded values or null")
        if name.endswith("revision") and item is not None and not _COMMIT.fullmatch(item):
            raise AuditError("invalid_run_declarations", "revision declarations require full lowercase SHA1/SHA256 identity")
        if name == "workflow_run_url" and item is not None and not _ACTION_URL.fullmatch(item):
            raise AuditError("invalid_run_declarations", "workflow reference must be a plain GitHub Actions run URL without credentials/query/fragment")
        source = (f"owner {value.owner_id} supplied no {name}; unknown" if item is None
                  else f"owner declaration by {value.owner_id}; not observed execution")
        result[name] = _identity(item, "owner_declared", source)
    return result


def capture_run_context(
    *, run_id: str, started_at: str, snapshot: Snapshot, mode: str,
    provider: str | None, model: str | None, prompt_digest: str | None,
    packet_digest: str | None, declarations: RunDeclarations | None = None,
) -> tuple[RunContext, list[PipelineError]]:
    """Observe trusted installed source/runtime metadata only when audit is run.

    No call is made during source construction. A failed source observation stays
    unknown and produces a pipeline error, rather than inventing a clean identity.
    """
    if mode not in {"rules", "replay"}:
        raise AuditError("unsupported_provenance_mode", "offline capture cannot claim a live execution observation")
    errors = []
    try:
        tool_code = _identity(code_digest(), "observed", CODE_DIGEST_METHOD)
    except (AuditError, OSError, ValueError) as exc:
        tool_code = _identity(None, "unknown", f"tool source observation unavailable: {type(exc).__name__}")
        errors.append(PipelineError(stage="provenance", reason="tool_code_unavailable",
                                    detail="trusted source digest could not be observed; run cannot be complete"))
    dependencies = {}
    for distribution in _DISTRIBUTIONS:
        try:
            version = importlib.metadata.version(distribution)
            dependencies[distribution] = _identity(version, "observed", "installed distribution metadata; no dependency execution proof")
        except importlib.metadata.PackageNotFoundError:
            dependencies[distribution] = _identity(None, "unknown", "installed distribution metadata unavailable")
        except (OSError, ValueError) as exc:
            dependencies[distribution] = _identity(None, "unknown", f"metadata observation unavailable: {type(exc).__name__}")
            errors.append(PipelineError(stage="provenance", reason="dependency_metadata_unavailable",
                                        detail=f"could not observe {distribution} metadata"))
    declared = _declarations(declarations)
    python_version = getattr(sys, "version", None)
    python_implementation = getattr(getattr(sys, "implementation", None), "name", None)
    if python_version is None or python_implementation is None:
        errors.append(PipelineError(stage="provenance", reason="python_identity_unavailable",
                                    detail="actual interpreter identity could not be observed"))
    fields = dict(context_version=CONTEXT_VERSION, run_id=run_id, started_at=started_at,
                  snapshot_id=snapshot.snapshot_id, snapshot_manifest_digest=snapshot.manifest_digest,
                  tool_version=TOOL_VERSION, tool_code=tool_code,
                  python_version=_identity(python_version, "observed", "current interpreter sys.version or explicitly unavailable"),
                  python_implementation=_identity(python_implementation, "observed", "current interpreter sys.implementation.name or explicitly unavailable"),
                  dependencies=dependencies, mode=mode,
                  provider=_identity(provider, "owner_declared", "declared local replay adapter label; no remote provider execution" if provider else "deterministic mode has no provider"),
                  model=_identity(model, "owner_declared", "caller-supplied replay model label; no resolved live model observed" if model else "no model identity supplied for standalone deterministic mode"),
                  prompt_digest=_identity(prompt_digest, "owner_declared", "caller-supplied replay prompt identity; prompt bytes not observed" if prompt_digest else "no prompt identity supplied for standalone deterministic mode"),
                  packet_digest=_identity(packet_digest, "owner_declared", "caller-supplied packet identity" if packet_digest else "standalone audit has no evaluation packet"),
                  **declared)
    context = RunContext(context_id=stable_id("run-context", fields), **fields)
    return validate_run_context(context), errors


def validate_run_context(context: RunContext) -> RunContext:
    """Strict content/identity validation; never upgrades a declared observation."""
    context = RunContext.model_validate_json(canonical_json(context))
    if context.mode not in {"rules", "replay"}:
        raise AuditError("unsupported_report_mode", "standalone offline report context cannot certify live execution", 4)
    fields = context.model_dump(mode="json", exclude={"context_id"})
    if context.context_id != stable_id("run-context", fields) or context.context_version != CONTEXT_VERSION:
        raise AuditError("run_context_identity", "immutable pre-render context content identity differs", 4)
    if context.tool_version != TOOL_VERSION:
        raise AuditError("run_context_tool_version", "release label differs from this trusted tool source", 4)
    if not context.run_id.strip():
        raise AuditError("run_context_identity", "run identity cannot be blank", 4)
    _date(context.started_at)
    for name in ("tool_code", "prompt_digest", "packet_digest"):
        identity = getattr(context, name)
        if identity.value is not None and not _DIGEST.fullmatch(identity.value):
            raise AuditError("run_context_digest", f"{name} must be a full lowercase SHA256", 4)
    for name in ("tool_code", "python_version", "python_implementation"):
        if getattr(context, name).basis not in {"observed", "unknown"}:
            raise AuditError("run_context_observation", f"{name} cannot be supplied as an owner declaration", 4)
    if context.tool_code.basis == "observed" and context.tool_code.source != CODE_DIGEST_METHOD:
        raise AuditError("run_context_observation", "observed tool code must use the sole trusted hash authority", 4)
    if any(identity.basis not in {"observed", "unknown"} for identity in context.dependencies.values()):
        raise AuditError("run_context_observation", "dependency observations cannot be owner-declared", 4)
    for name in ("tool_revision", "workflow_revision", "workflow_run_url", "trigger_revision", "trigger_kind"):
        identity = getattr(context, name)
        if identity.basis not in {"owner_declared", "unknown"}:
            raise AuditError("run_context_observation", "Git/workflow/trigger identities are not observed by this offline auditor", 4)
        if name.endswith("revision") and identity.value is not None and not _COMMIT.fullmatch(identity.value):
            raise AuditError("run_context_revision", "revision declaration is not a full SHA", 4)
    if context.workflow_run_url.value is not None and not _ACTION_URL.fullmatch(context.workflow_run_url.value):
        raise AuditError("run_context_workflow_reference", "workflow URL is only a plain declared GitHub run reference", 4)
    if context.mode == "rules" and any(identity.value is not None for identity in (context.provider, context.model, context.prompt_digest, context.packet_digest)):
        raise AuditError("run_context_mode", "standalone rules mode cannot invent provider/model/prompt/packet identities", 4)
    if context.mode == "replay" and (context.provider.value != "fixture-replay" or context.provider.basis != "owner_declared"
                                     or context.model.value is None or context.model.basis != "owner_declared"
                                     or context.prompt_digest.value is None or context.prompt_digest.basis != "owner_declared"):
        raise AuditError("run_context_mode", "replay must retain its declared model/prompt and local adapter identity", 4)
    return context


def context_bytes(context: RunContext) -> bytes:
    """Identical canonical JSON/one-row JSONL metadata, with a single LF."""
    return canonical_json(validate_run_context(context)) + b"\n"


def legacy_dependencies(context: RunContext) -> dict[str, str]:
    """Compatibility aliases retain explicit unavailable rather than fake versions."""
    return {name: identity.value if identity.value is not None else "unavailable"
            for name, identity in context.dependencies.items()}


def validate_report_context(report: AuditReport) -> RunContext:
    if report.run_context is None:
        raise AuditError("report_context_missing", "new standalone reports require a strict pre-render context", 4)
    context = validate_run_context(report.run_context)
    if (context.snapshot_id != report.snapshot.snapshot_id
            or context.snapshot_manifest_digest != report.snapshot.manifest_digest or context.mode != report.mode):
        raise AuditError("report_context_mismatch", "report/context target or mode identity differs", 4)
    return context


def validate_manifest_context(manifest: RunManifest, report: AuditReport, raw: bytes) -> RunContext:
    """Cross-check immutable context, legacy aliases and exact pre-render bytes."""
    context = validate_report_context(report)
    if manifest.run_context is None or manifest.run_context != context or raw != context_bytes(context):
        raise AuditError("report_context_mismatch", "manifest/report/context artifacts differ", 4)
    digest = sha256(raw)
    if (manifest.context_digest != digest or manifest.report_hashes.get("context.json") != digest
            or manifest.report_hashes.get("context.jsonl") != digest):
        raise AuditError("report_context_digest", "context byte pin or JSON/JSONL artifact hash differs", 4)
    expected = (context.run_id, context.started_at, context.snapshot_id, context.snapshot_manifest_digest,
                context.tool_version, context.mode, context.provider.value, context.model.value,
                context.prompt_digest.value, context.packet_digest.value, context.tool_revision.value,
                context.workflow_revision.value, context.workflow_run_url.value)
    actual = (manifest.run_id, manifest.started_at, manifest.snapshot_id, manifest.snapshot_manifest_digest,
              manifest.tool_version, manifest.mode, manifest.provider, manifest.model,
              manifest.prompt_digest, manifest.packet_digest, manifest.source_revision,
              manifest.workflow_revision, manifest.workflow_run_url)
    if actual != expected or manifest.dependencies != legacy_dependencies(context):
        raise AuditError("report_context_mismatch", "manifest observations/declared aliases differ from immutable context", 4)
    if context.tool_code.basis != "observed" or context.tool_code.value != code_digest():
        raise AuditError("report_tool_identity", "complete report must match this exact trusted tool source closure", 4)
    return context
