"""Append-only local annotation history; no inference or human impersonation.

Operator-controlled ledgers bind one frozen source manifest. Rulings are judgments,
not verified evidence; callers must reopen source and evidence before accepting one.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import stat
from typing import Iterator

from pydantic import ValidationError

from claim_auditor.contracts import (
    AnnotationRuling, AuditError, AuditReport, GoldAtom, canonical_json, sha256, stable_id,
)
from claim_auditor.snapshot.safeio import SnapshotError, read_ordinary

MAX_LEDGER_BYTES = 10 * 1024 * 1024
MAX_RULING_BYTES = 256 * 1024
MAX_RULINGS = 5000


def _timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result > datetime.now(timezone.utc):
            raise ValueError("timestamp must be timezone-aware and not future dated")
        return result
    except ValueError as exc:
        raise AuditError("invalid_ruling_date", str(exc)) from exc


def _key(row: AnnotationRuling) -> tuple[str, str, str, str]:
    return (row.atom.family_id, row.atom.gold_id, row.atom.annotator_type, row.atom.annotator_id)


def _fields(row: AnnotationRuling) -> dict[str, object]:
    return row.model_dump(mode="json", exclude={"ruling_id"})


def _validate(row: AnnotationRuling) -> AnnotationRuling:
    # Revalidate even callers that constructed a model with unchecked model_copy.
    try:
        row = AnnotationRuling.model_validate_json(canonical_json(row))
    except (ValidationError, ValueError) as exc:
        raise AuditError("invalid_ruling", "closed-schema ruling validation failed") from exc
    if row.ruling_id != stable_id("ruling", _fields(row)):
        raise AuditError("ruling_digest_mismatch", "ruling_id must bind every other field")
    if sha256(canonical_json(row.atom.claim)) != row.claim_digest:
        raise AuditError("ruling_claim_changed", "claim bytes differ from bound digest")
    recorded = _timestamp(row.recorded_at)
    atom = row.atom
    if not atom.gold_id.strip() or not atom.family_id.strip() or not atom.claim.claim_id.strip():
        raise AuditError("invalid_ruling_identity", "family, annotation subject and claim IDs are required")
    predicate_ids = [predicate.predicate_id for predicate in atom.claim.predicates]
    if len(set(predicate_ids)) != len(predicate_ids) or not predicate_ids:
        raise AuditError("invalid_ruling_predicates", "claim must have unique, nonempty predicates")
    for identifiers in (atom.supported_predicate_ids, atom.unresolved_predicate_ids, atom.accused_predicate_ids):
        if len(set(identifiers)) != len(identifiers) or not set(identifiers) <= set(predicate_ids):
            raise AuditError("invalid_ruling_predicates", "judgment contains duplicate or foreign predicate IDs")
    if set(atom.supported_predicate_ids) & (set(atom.unresolved_predicate_ids) | set(atom.accused_predicate_ids)):
        raise AuditError("invalid_ruling_predicates", "supported predicates cannot also be unresolved or accused")
    if set(atom.supported_predicate_ids) | set(atom.unresolved_predicate_ids) | set(atom.accused_predicate_ids) != set(predicate_ids):
        raise AuditError("incomplete_ruling_predicates", "retain every predicate in the judgment")
    if atom.verdict in {"verified", "unknown"} and atom.accused_predicate_ids:
        raise AuditError("invalid_ruling_verdict", "verified/unknown cannot accuse predicates")
    if atom.verdict == "verified" and set(atom.supported_predicate_ids) != set(predicate_ids):
        raise AuditError("invalid_ruling_verdict", "verified must establish every predicate")
    if atom.verdict == "missing" and not atom.accused_predicate_ids:
        raise AuditError("invalid_ruling_verdict", "missing requires an explicitly accused predicate")
    if atom.verdict == "partial" and (not atom.supported_predicate_ids or not (atom.unresolved_predicate_ids or atom.accused_predicate_ids)):
        raise AuditError("invalid_ruling_verdict", "partial requires both real support and a remaining predicate")
    if atom.adjudicated_at is not None and _timestamp(atom.adjudicated_at) > recorded:
        raise AuditError("invalid_ruling_date", "judgment date cannot follow recording date")
    if atom.annotator_type == "human" and atom.adjudicated_at is None:
        raise AuditError("human_action_required", "human judgment requires actual adjudication date")
    return row


def make_ruling(
    atom: GoldAtom, *, source_manifest_digest: str, evidence_digest: str,
    recorded_at: str, supersedes_ruling_id: str | None = None,
    human_action_id: str | None = None,
) -> AnnotationRuling:
    """Construct a content-addressed judgment; never infer a human action."""
    fields = dict(source_manifest_digest=source_manifest_digest,
                  claim_digest=sha256(canonical_json(atom.claim)), evidence_digest=evidence_digest,
                  atom=atom, recorded_at=recorded_at, supersedes_ruling_id=supersedes_ruling_id,
                  human_action_id=human_action_id)
    try:
        row = AnnotationRuling(ruling_id=stable_id("ruling", fields), **fields)
    except (ValidationError, ValueError) as exc:
        raise AuditError("invalid_ruling", "invalid annotation fields") from exc
    return _validate(row)


def _extend(history: list[AnnotationRuling], incoming: list[AnnotationRuling]) -> list[AnnotationRuling]:
    by_id = {row.ruling_id: row for row in history}
    latest = {_key(row): row for row in history}
    # All annotators of a stable subject must judge identical source/claim/evidence.
    bindings = {(row.atom.family_id, row.atom.gold_id):
                (row.source_manifest_digest, row.claim_digest, row.evidence_digest) for row in history}
    subjects = {(row.atom.family_id, row.atom.claim.claim_id): row.atom.gold_id for row in history}
    manifests = {row.source_manifest_digest for row in history}
    added = []
    for original in incoming:
        row = _validate(original)
        if row.ruling_id in by_id:
            if canonical_json(row) != canonical_json(by_id[row.ruling_id]):
                raise AuditError("ruling_identity_conflict", "one ID has different bytes")
            continue  # Exact re-import is idempotent, not a second judgment.
        if manifests and row.source_manifest_digest not in manifests:
            raise AuditError("ruling_source_changed", "use a fresh ledger for a new source manifest; preserve this history")
        subject = (row.atom.family_id, row.atom.gold_id)
        claim_key = (row.atom.family_id, row.atom.claim.claim_id)
        if claim_key in subjects and subjects[claim_key] != row.atom.gold_id:
            raise AuditError("ruling_subject_conflict", "all annotators must retain one stable subject identity for the same claim")
        binding = (row.source_manifest_digest, row.claim_digest, row.evidence_digest)
        if subject in bindings and bindings[subject] != binding:
            raise AuditError("ruling_binding_changed", "source/claim/evidence changed; require fresh review in a fresh ledger")
        previous = latest.get(_key(row))
        expected = previous.ruling_id if previous is not None else None
        if row.supersedes_ruling_id != expected:
            raise AuditError("ruling_revision_conflict", "revision must supersede this annotator's latest exact subject ruling")
        if previous is not None:
            if _timestamp(row.recorded_at) < _timestamp(previous.recorded_at):
                raise AuditError("ruling_revision_conflict", "revision cannot predate its predecessor")
            if not set(previous.atom.disagreements) <= set(row.atom.disagreements):
                raise AuditError("ruling_disagreement_lost", "revisions must retain all recorded disagreement text")
        manifests.add(row.source_manifest_digest)
        bindings[subject] = binding
        subjects[claim_key] = row.atom.gold_id
        latest[_key(row)] = row
        by_id[row.ruling_id] = row
        added.append(row)
    return added


def load_rulings(path: Path) -> list[AnnotationRuling]:
    """Validate bounded full history, including content IDs and revision links."""
    path = Path(path)
    try:
        raw = read_ordinary(path.parent, path.name, cap=MAX_LEDGER_BYTES)
    except (OSError, SnapshotError) as exc:
        raise AuditError("invalid_ruling_ledger", "ledger must be a bounded ordinary file") from exc
    if raw and not raw.endswith(b"\n"):
        raise AuditError("incomplete_ruling_append", "unterminated tail requires operator recovery; no automatic truncation")
    history: list[AnnotationRuling] = []
    for line in raw.splitlines():
        if not line or len(line) > MAX_RULING_BYTES or len(history) >= MAX_RULINGS:
            raise AuditError("ruling_ledger_limit", "blank/oversized row or history limit exceeded")
        try:
            row = AnnotationRuling.model_validate_json(line)
        except (ValidationError, ValueError) as exc:
            raise AuditError("invalid_ruling", "ruling JSONL failed closed-schema validation") from exc
        if any(previous.ruling_id == row.ruling_id for previous in history):
            raise AuditError("duplicate_ruling", "physical history must not contain duplicate IDs")
        history.extend(_extend(history, [row]))
    return history


def _ordinary_directory(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    for component in [*reversed(absolute.parents), absolute]:
        info = component.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise AuditError("unsafe_ruling_directory", "operator ledger ancestors must be ordinary directories")


@contextmanager
def _writer(path: Path) -> Iterator[None]:
    _ordinary_directory(path.parent)
    lock = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise AuditError("ruling_writer_busy", "lock exists; never steal or remove it by age") from exc
    try:
        yield
    finally:
        os.close(descriptor)
        lock.unlink()  # Only this invocation's exclusively created lock.


def _append_many(path: Path, incoming: list[AnnotationRuling], *, human_confirmation: bool) -> list[AnnotationRuling]:
    path = Path(path)
    validated = [_validate(row) for row in incoming]
    if any(row.atom.annotator_type == "human" for row in validated) and human_confirmation is not True:
        raise AuditError("human_action_required", "explicit operator confirmation is required for human imports/appends")
    with _writer(path):
        present = path.exists() or path.is_symlink()
        history = load_rulings(path) if present else []
        added = _extend(history, validated)
        if not added:
            return []
        lines = [canonical_json(row) + b"\n" for row in added]
        if len(history) + len(added) > MAX_RULINGS or any(len(line) - 1 > MAX_RULING_BYTES for line in lines):
            raise AuditError("ruling_ledger_limit", "row count/size exceeds bounded history")
        data = b"".join(lines)
        existing_size = path.stat().st_size if present else 0
        if existing_size + len(data) > MAX_LEDGER_BYTES:
            raise AuditError("ruling_ledger_limit", "append exceeds byte cap")
        # Exclusive sidecar serializes cooperating operators. Path ACLs and directory
        # ownership are required; this is not a hostile multi-user storage service.
        flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        if not present:
            flags |= os.O_CREAT | os.O_EXCL
        before = path.lstat() if present else None
        descriptor = os.open(path, flags, 0o600)
        try:
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_size != existing_size
                    or getattr(opened, "st_file_attributes", 0) & 0x400
                    or (before is not None and (before.st_dev, before.st_ino, before.st_mtime_ns)
                        != (opened.st_dev, opened.st_ino, opened.st_mtime_ns))):
                raise AuditError("ruling_ledger_changed", "ledger changed before append")
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise AuditError("incomplete_ruling_append", "append stopped; preserve ledger for operator recovery")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return added


def append_ruling(path: Path, ruling: AnnotationRuling, *, human_confirmation: bool = False) -> AnnotationRuling:
    _append_many(path, [ruling], human_confirmation=human_confirmation)
    return ruling


def import_rulings(path: Path, incoming: Path, *, human_confirmation: bool = False) -> list[AnnotationRuling]:
    """Prevalidate a full incoming history, then append only new exact records."""
    return _append_many(path, load_rulings(incoming), human_confirmation=human_confirmation)


def export_rulings(path: Path, out: Path) -> str:
    """Export full history to a fresh file; return exact exported-byte SHA256."""
    history = load_rulings(path)
    data = b"".join(canonical_json(row) + b"\n" for row in history)
    _ordinary_directory(Path(out).parent)
    with Path(out).open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return sha256(data)


def current_rulings(
    path: Path, *, source_manifest_digest: str,
    claim_digests: dict[str, str], evidence_digests: dict[str, str],
) -> list[AnnotationRuling]:
    """Return each annotator's latest judgment, never automatic consensus/gold.

    Maps are keyed by exact claim_id. The caller derives current digests from
    reopened source/claim/evidence bytes; never pass a ledger's own values back.
    """
    latest = {_key(row): row for row in load_rulings(path)}
    for row in latest.values():
        claim_id = row.atom.claim.claim_id
        if (row.source_manifest_digest != source_manifest_digest
                or claim_digests.get(claim_id) != row.claim_digest
                or evidence_digests.get(claim_id) != row.evidence_digest):
            raise AuditError("ruling_binding_changed", "current reopened source/claim/evidence does not match judgment")
    return list(latest.values())


def prepare_annotation_package(run_root: Path, out: Path, *, family_id: str) -> str:
    """Prepare assisted candidate review, never a complete manual denominator.

    This future operator operation invokes existing report integrity verification;
    it is not run during static-only construction. PACKAGE.json is written last.
    """
    from claim_auditor.citations import verify_report
    from claim_auditor.snapshot import read_source

    if not family_id.strip():
        raise AuditError("invalid_ruling_identity", "an operator-assigned DEV family identity is required")
    manifest = verify_report(Path(run_root))
    raw = read_ordinary(Path(run_root), "report.json", cap=64 * 1024 * 1024)
    if sha256(raw) != manifest.report_hashes["report.json"]:
        raise AuditError("annotation_report_changed", "report bytes changed after integrity verification")
    report = AuditReport.model_validate_json(raw)
    if report.snapshot.manifest_digest != manifest.snapshot_manifest_digest:
        raise AuditError("annotation_source_changed", "report snapshot differs from verified run")
    out = Path(out)
    run_absolute = Path(os.path.abspath(run_root))
    out_absolute = Path(os.path.abspath(out))
    if out_absolute == run_absolute or run_absolute in out_absolute.parents:
        raise AuditError("annotation_output_inside_run", "package must not modify the frozen input run")
    _ordinary_directory(out.parent)
    out.mkdir(exist_ok=False)
    source_out = out / "source"
    source_out.mkdir()
    for entry in report.snapshot.entries:
        if entry.status != "included":
            continue
        data = read_source(report.snapshot, Path(run_root) / "snapshot", entry.path)
        target = source_out.joinpath(*entry.path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
    subjects = out / "subjects"
    subjects.mkdir()
    rows = []
    for claim in report.inventory.claims:
        stem = sha256(claim.claim_id.encode("utf-8"))
        predicate_ids = {predicate.predicate_id for predicate in claim.predicates}
        bundle = {
            "evidence": sorted([item for item in report.evidence if item.query.predicate_id in predicate_ids],
                               key=lambda item: item.evidence_id),
            "coverage": sorted([item for item in report.coverage if item.query.predicate_id in predicate_ids],
                               key=lambda item: item.coverage_id),
        }
        evidence_raw = canonical_json(bundle) + b"\n"
        claim_raw = canonical_json(claim)
        for name, data in ((stem + ".claim.json", claim_raw + b"\n"),
                           (stem + ".evidence.json", evidence_raw)):
            with (subjects / name).open("xb") as stream:
                stream.write(data)
        rows.append({"claim_id": claim.claim_id, "claim_file": f"subjects/{stem}.claim.json",
                     "claim_digest": sha256(claim_raw), "evidence_file": f"subjects/{stem}.evidence.json",
                     "evidence_digest": sha256(evidence_raw),
                     "annotation_subject_id": stable_id("annotation-subject", family_id, claim.claim_id)})
    package = {
        "format": "annotation-package/1", "designation": "DEV_ONLY",
        "review_mode": "assisted_candidate_findings",
        "complete_manual_inventory": False,
        "family_id": family_id, "source_manifest_digest": report.snapshot.manifest_digest,
        "snapshot": report.snapshot, "inventory": report.inventory,
        "subjects": rows, "human_review_performed": False, "gold_created": False,
        "status": "prepared_for_operator_review_only",
        "instructions": [
            "This candidate-based package cannot establish end-to-end manual inventory or extraction recall.",
            "Use evaluation.annotation.prepare_source_annotation on raw Snapshot bytes for an independent denominator.",
            "Review source/README.md first; account for every assertion and extractor omissions.",
            "Open exact source/evidence bytes; integrity verification is not semantic acceptance.",
            "No verdicts, human identities or human actions are prepopulated.",
            "Retain distinct annotators and disagreements; current_rulings is not consensus or gold.",
            "Incomplete folders without PACKAGE.json are not ready; preserve failed artifacts.",
            "Source is exposed DEV material; no heldout blindness, rights or custody is certified.",
        ],
    }
    data = canonical_json(package) + b"\n"
    with (out / "PACKAGE.json").open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return sha256(data)
