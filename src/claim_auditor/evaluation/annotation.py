"""Source-first manual annotation source, independent of candidate extraction.

All human actions are explicit future operator inputs. No operation in this module
establishes custody, blindness, semantic correctness or comparative acceptance.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from claim_auditor.contracts import (
    AnnotationRuling, AuditError, Claim, ClaimKind, CoverageReport, Evidence, GoldAtom,
    Inventory, InventoryBlock, Limits, ManualAnnotation, PipelineError, Predicate,
    Snapshot, Span, canonical_json, sha256, stable_id,
)
from claim_auditor.citations import validate_coverage, validate_evidence, validate_span
from claim_auditor.evaluation.custody import MAX_STAGE_BYTES, _object, _read
from claim_auditor.evaluation.rulings import (
    _ordinary_directory, _timestamp, append_ruling, current_rulings, load_rulings, make_ruling,
)
from claim_auditor.index import StaticIndex, build_index
from claim_auditor.inventory.raw import RawDocument
from claim_auditor.snapshot import copy_snapshot, load_snapshot, read_source
from claim_auditor.snapshot.safeio import read_ordinary

MANUAL_VERSION = "manual-source/1"
MAX_ANNOTATION_BYTES = 16 * 1024 * 1024


def _context(snapshot_root: Path, readme_path: str) -> tuple[Snapshot, RawDocument]:
    snapshot = load_snapshot(Path(snapshot_root))
    raw = read_source(snapshot, Path(snapshot_root), readme_path)
    if len(raw) > Limits().max_readme_bytes:
        raise AuditError("manual_readme_limit", "README exceeds the original-byte policy cap")
    try:
        document = RawDocument.decode(raw)
    except UnicodeDecodeError as exc:
        raise AuditError("manual_readme_encoding", "strict UTF-8 is required; no normalization or replacement") from exc
    if (len(document.line_bytes) - 1 > Limits().max_lines
            or any(len(raw[a:b].rstrip(b"\r\n")) > Limits().max_line_bytes
                   for a, b in zip(document.line_bytes, document.line_bytes[1:]))):
        raise AuditError("manual_readme_limit", "raw README line limits exceeded")
    return snapshot, document


def _span(snapshot: Snapshot, document: RawDocument, path: str, start: int, end: int) -> Span:
    if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(document.raw):
        raise AuditError("manual_span_bounds", "an explicit nonempty half-open raw-byte range is required")
    try:
        quote = document.raw[start:end].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuditError("manual_utf8_boundary", "selection splits an original UTF-8 code point") from exc
    first, last = document.line_bounds(start, end)
    return Span(snapshot_id=snapshot.snapshot_id, file_sha256=sha256(document.raw), path=path,
                start_byte=start, end_byte=end, start_line=first, end_line=last,
                quote=quote, quote_sha256=sha256(document.raw[start:end]))


def select_manual_span(snapshot_root: Path, *, start_byte: int, end_byte: int, readme_path: str = "README.md") -> Span:
    """Use coordinates only; never guess which repeated quote the operator meant."""
    snapshot, document = _context(snapshot_root, readme_path)
    return _span(snapshot, document, readme_path, start_byte, end_byte)


def _claim(
    snapshot: Snapshot, document: RawDocument, readme_path: str, *, start_byte: int,
    end_byte: int, parent_start_byte: int, parent_end_byte: int, atom_ordinal: int,
    kind: ClaimKind, normalized: str, predicates: list[Predicate], uncertainty: list[str],
) -> Claim:
    atom = _span(snapshot, document, readme_path, start_byte, end_byte)
    parent = _span(snapshot, document, readme_path, parent_start_byte, parent_end_byte)
    if not parent.start_byte <= atom.start_byte < atom.end_byte <= parent.end_byte:
        raise AuditError("manual_parent_bounds", "atom must retain a containing original parent context")
    if type(atom_ordinal) is not int or not 0 <= atom_ordinal < Limits().max_atoms:
        raise AuditError("manual_atom_ordinal", "explicit bounded parent-local atom ordinal is required")
    if not normalized.strip() or not atom.quote.strip() or not predicates or len(predicates) > Limits().max_atoms:
        raise AuditError("manual_atom_incomplete", "nonempty exact quote, normalization and structured predicates required")
    parent_id = stable_id("sentence", snapshot.snapshot_id, readme_path, parent.start_byte, parent.end_byte)
    claim_id = stable_id("claim", parent_id, atom_ordinal)
    admitted = []
    for original in predicates:
        try:
            predicate = Predicate.model_validate_json(canonical_json(original))
        except ValidationError as exc:
            raise AuditError("invalid_manual_predicate", "closed structured predicate required") from exc
        fields = predicate.model_dump(mode="json", exclude={"predicate_id"})
        # IDs are derived, never copied from a candidate extractor or free text.
        admitted.append(Predicate(predicate_id=stable_id("predicate", claim_id, fields), **fields))
    if len({canonical_json(item.model_dump(mode="json", exclude={"predicate_id"})) for item in admitted}) != len(admitted):
        raise AuditError("duplicate_manual_predicate", "duplicate structured predicates cannot inflate an atom")
    return Claim(claim_id=claim_id, parent_id=parent_id, atom_ordinal=atom_ordinal, kind=kind,
                 normalized=normalized, span=atom, predicates=admitted,
                 extraction_method="manual", extraction_version=MANUAL_VERSION, uncertainty=uncertainty)


def select_manual_atom(
    snapshot_root: Path, *, start_byte: int, end_byte: int, parent_start_byte: int,
    parent_end_byte: int, atom_ordinal: int, kind: ClaimKind, normalized: str,
    predicates: list[Predicate], uncertainty: list[str], readme_path: str = "README.md",
) -> Claim:
    """Preserve operator-selected qualifiers/negation without inferring a label.

    Incoming predicate IDs are ignored and derived from the manual source claim.
    Predicate meaning must still be reviewed against the retained parent context.
    """
    snapshot, document = _context(snapshot_root, readme_path)
    return _claim(snapshot, document, readme_path, start_byte=start_byte, end_byte=end_byte,
                  parent_start_byte=parent_start_byte, parent_end_byte=parent_end_byte,
                  atom_ordinal=atom_ordinal, kind=kind, normalized=normalized,
                  predicates=predicates, uncertainty=uncertainty)


def _raw_blocks(snapshot: Snapshot, document: RawDocument, path: str) -> list[InventoryBlock]:
    return [InventoryBlock(block_id=stable_id("block", snapshot.snapshot_id, path, first, after),
                           block_kind="manual_raw_line", span=_span(snapshot, document, path, first, after),
                           claim_ids=[], status="unparsed", reason="awaiting_explicit_manual_review")
            for first, after in zip(document.line_bytes, document.line_bytes[1:])]


def _inventory(
    snapshot: Snapshot, document: RawDocument, readme_path: str, claims: list[Claim],
    parent_spans: list[Span], reviews: dict[str, tuple[str, str]],
) -> Inventory:
    from claim_auditor.evaluation.scoring import _claim_key

    if len(claims) > Limits().max_atoms or len(parent_spans) > Limits().max_atoms:
        raise AuditError("manual_atom_limit", "manual atoms/parent contexts exceed policy cap")
    parents: dict[str, Span] = {}
    for parent in parent_spans:
        expected = _span(snapshot, document, readme_path, parent.start_byte, parent.end_byte)
        if parent != expected:
            raise AuditError("manual_parent_changed", "retained parent bytes/coordinates differ from README", 4)
        parent_id = stable_id("sentence", snapshot.snapshot_id, readme_path, parent.start_byte, parent.end_byte)
        if parent_id in parents:
            raise AuditError("duplicate_manual_parent", "retain each parent context once")
        parents[parent_id] = parent
    identifiers: set[str] = set()
    signatures: set[bytes] = set()
    slots: set[bytes] = set()
    matcher_keys: set[bytes] = set()
    for claim in claims:
        if claim.claim_id in identifiers or claim.parent_id not in parents:
            raise AuditError("manual_atom_conflict", "duplicate claim identity or unretained parent context")
        parent = parents[claim.parent_id]
        expected = _claim(snapshot, document, readme_path, start_byte=claim.span.start_byte,
                          end_byte=claim.span.end_byte, parent_start_byte=parent.start_byte,
                          parent_end_byte=parent.end_byte, atom_ordinal=claim.atom_ordinal,
                          kind=claim.kind, normalized=claim.normalized, predicates=claim.predicates,
                          uncertainty=claim.uncertainty)
        if claim != expected:
            raise AuditError("manual_atom_changed", "manual claim bytes, predicate identities or method changed", 4)
        fields = [item.model_dump(mode="json", exclude={"predicate_id"}) for item in claim.predicates]
        signature = canonical_json([claim.span.start_byte, claim.span.end_byte, claim.kind,
                                    sorted(canonical_json(item).decode("utf-8") for item in fields)])
        slot_fields = [{key: value for key, value in item.items() if key != "expected"} for item in fields]
        slot = canonical_json([claim.span.start_byte, claim.span.end_byte, claim.kind,
                               sorted(canonical_json(item).decode("utf-8") for item in slot_fields)])
        matcher_key = _claim_key(claim)
        if signature in signatures or slot in slots or matcher_key in matcher_keys:
            raise AuditError("manual_atom_conflict", "duplicate or conflicting exact-span structured atoms require explicit resolution")
        identifiers.add(claim.claim_id)
        signatures.add(signature)
        slots.add(slot)
        matcher_keys.add(matcher_key)
    if set(parents) != {claim.parent_id for claim in claims}:
        raise AuditError("manual_parent_unassigned", "every retained parent must belong to a selected atom")
    claims = sorted(claims, key=lambda item: (item.span.start_byte, item.span.end_byte, item.parent_id, item.atom_ordinal))
    raw_blocks = _raw_blocks(snapshot, document, readme_path)
    if set(reviews) - {block.block_id for block in raw_blocks}:
        raise AuditError("manual_block_unknown", "review refers to a different or absent raw source block")
    blocks = []
    for block in raw_blocks:
        status, reason = reviews.get(block.block_id, ("unparsed", "awaiting_explicit_manual_review"))
        if status not in {"extracted", "nonassertion", "unsupported", "unparsed"} or not reason.strip():
            raise AuditError("invalid_manual_block_review", "explicit known review status and nonempty rationale required")
        members = [claim.claim_id for claim in claims
                   if claim.span.start_byte < block.span.end_byte and block.span.start_byte < claim.span.end_byte]
        if (status == "extracted" and not members) or (status == "nonassertion" and members):
            raise AuditError("manual_block_conflict", "extracted blocks need atoms; nonassertion blocks cannot discard selected atoms")
        blocks.append(InventoryBlock(block_id=block.block_id, block_kind=block.block_kind, span=block.span,
                                     claim_ids=members, status=status, reason=reason))
    pending = sum(block.status in {"unparsed", "unsupported"} for block in blocks)
    errors = [PipelineError(stage="manual_inventory", reason="manual_review_incomplete",
                            detail=f"{pending} raw blocks remain unparsed/unsupported")] if pending else []
    return Inventory(snapshot_id=snapshot.snapshot_id, readme_path=readme_path,
                     readme_sha256=sha256(document.raw), claims=claims, blocks=blocks,
                     complete=not pending, errors=errors, extraction_version=MANUAL_VERSION)


def make_manual_inventory(
    snapshot_root: Path, *, claims: list[Claim], parent_spans: list[Span],
    block_reviews: dict[str, tuple[str, str]], readme_path: str = "README.md",
) -> Inventory:
    """Retain every raw line; missing reviews remain visibly incomplete."""
    snapshot, document = _context(snapshot_root, readme_path)
    return _inventory(snapshot, document, readme_path, claims, parent_spans, block_reviews)


def _write(path: Path, raw: bytes) -> None:
    _ordinary_directory(path.parent)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _outside_source(snapshot_root: Path, out: Path) -> None:
    source = Path(os.path.abspath(snapshot_root))
    target = Path(os.path.abspath(out))
    if target == source or source in target.parents:
        raise AuditError("manual_output_inside_source", "annotation/label material must stay outside inference snapshot")


def prepare_source_annotation(
    snapshot_root: Path, out: Path, *, family_id: str, readme_path: str = "README.md",
) -> str:
    """Prepare raw source/review coverage with no candidate/model/label prefill."""
    if not family_id.strip():
        raise AuditError("manual_family_required", "explicit actual DEV family identity required")
    snapshot, document = _context(snapshot_root, readme_path)
    out = Path(os.path.abspath(out))
    source = Path(os.path.abspath(snapshot_root))
    if out == source or source in out.parents:
        raise AuditError("manual_output_inside_source", "source-first package must not modify input snapshot")
    _ordinary_directory(out.parent)
    out.mkdir(exist_ok=False)
    copy_snapshot(snapshot, Path(snapshot_root), out / "snapshot")
    inventory = _inventory(snapshot, document, readme_path, [], [], {})
    package = {"format": "source-annotation-package/1", "designation": "DEV_ONLY",
               "family_id": family_id, "source_manifest_digest": snapshot.manifest_digest,
               "snapshot": snapshot, "raw_inventory": inventory, "source_entries": snapshot.entries,
               "evidence_source_scope_gaps": snapshot.exclusions,
               "status": "awaiting_source_first_manual_review", "candidate_extractor_invoked": False,
               "candidate_findings_used": False, "human_review_performed": False, "gold_created": False,
               "instructions": [
                   "Read every original README byte, including code/HTML/headings and unsupported/unparsed blocks.",
                   "Select atoms by explicit byte ranges; retain containing parent context and all qualifiers/negation.",
                   "No candidate list defines the denominator; manual inventory may include any original assertion.",
                   "All raw block dispositions require explicit review; unparsed/unsupported remains incomplete.",
                   "Keep this review package and later label material outside inference inputs.",
                   "DEV metadata and hashes do not certify human action, rights, custody or blindness.",
               ]}
    raw = canonical_json(package) + b"\n"
    _write(out / "SOURCE.json", raw)
    return sha256(raw)


def _actor(annotator_type: str, annotator_id: str, recorded_at: str, action_id: str | None) -> None:
    if annotator_type not in {"agent", "human"} or not annotator_id.strip():
        raise AuditError("manual_actor_required", "explicit actual agent/human identity required")
    _timestamp(recorded_at)
    if (annotator_type == "human" and not (action_id or "").strip()) or (annotator_type == "agent" and action_id is not None):
        raise AuditError("manual_action_required", "human action must be explicit; agent proposal cannot impersonate one")


def _validate_annotation(snapshot_root: Path, record: ManualAnnotation) -> ManualAnnotation:
    try:
        record = ManualAnnotation.model_validate_json(canonical_json(record))
    except ValidationError as exc:
        raise AuditError("invalid_manual_annotation", "closed ManualAnnotation wire validation failed") from exc
    _actor(record.annotator_type, record.annotator_id, record.recorded_at, record.action_id)
    if not record.family_id.strip():
        raise AuditError("manual_family_required", "family identity cannot be blank")
    fields = record.model_dump(mode="json", exclude={"annotation_id"})
    if record.annotation_id != stable_id("manual-annotation", fields):
        raise AuditError("manual_annotation_digest", "annotation content identity changed", 4)
    snapshot, document = _context(snapshot_root, record.inventory.readme_path)
    if record.source_manifest_digest != snapshot.manifest_digest:
        raise AuditError("manual_source_changed", "annotation belongs to a different source manifest", 4)
    reviews = {block.block_id: (block.status, block.reason or "") for block in record.inventory.blocks}
    inventory = _inventory(snapshot, document, record.inventory.readme_path,
                           record.inventory.claims, record.parent_spans, reviews)
    if record.inventory != inventory:
        raise AuditError("manual_inventory_changed", "raw coverage, claims, statuses or complete flag changed", 4)
    return record


def load_manual_annotation(snapshot_root: Path, path: Path) -> ManualAnnotation:
    try:
        record = ManualAnnotation.model_validate_json(read_ordinary(Path(path).parent, Path(path).name, MAX_ANNOTATION_BYTES))
    except (ValidationError, ValueError, OSError) as exc:
        raise AuditError("invalid_manual_annotation", "bounded ordinary ManualAnnotation JSON required") from exc
    return _validate_annotation(snapshot_root, record)


def record_manual_annotation(
    snapshot_root: Path, out: Path, *, family_id: str, inventory: Inventory,
    parent_spans: list[Span], annotator_type: Literal["agent", "human"], annotator_id: str,
    recorded_at: str, action_id: str | None = None, previous_path: Path | None = None,
    human_confirmation: bool = False,
) -> ManualAnnotation:
    """Write a new immutable manual record; never silently upgrade agent work."""
    if annotator_type == "human" and human_confirmation is not True:
        raise AuditError("human_action_required", "recording human inventory requires actual-action confirmation")
    snapshot = load_snapshot(Path(snapshot_root))
    previous = load_manual_annotation(snapshot_root, previous_path) if previous_path is not None else None
    if previous is not None:
        if (previous.family_id, previous.annotator_type, previous.annotator_id) != (family_id, annotator_type, annotator_id):
            raise AuditError("manual_revision_conflict", "revision must retain actual author/family; human review is a separate record")
        if _timestamp(recorded_at) < _timestamp(previous.recorded_at):
            raise AuditError("manual_revision_date", "revision cannot predate its retained predecessor")
    fields = dict(source_manifest_digest=snapshot.manifest_digest, family_id=family_id, inventory=inventory,
                  parent_spans=parent_spans, annotator_type=annotator_type, annotator_id=annotator_id,
                  recorded_at=recorded_at, action_id=action_id,
                  supersedes_annotation_id=previous.annotation_id if previous is not None else None)
    record = ManualAnnotation(annotation_id=stable_id("manual-annotation", fields), **fields)
    record = _validate_annotation(snapshot_root, record)
    raw = canonical_json(record) + b"\n"
    if len(raw) > MAX_ANNOTATION_BYTES:
        raise AuditError("manual_annotation_limit", "manual record exceeds bounded artifact size")
    _outside_source(snapshot_root, Path(out))
    _write(Path(out), raw)
    return record


def _bundle(
    snapshot: Snapshot, snapshot_root: Path, claim: Claim, path: Path,
    index: StaticIndex | None, *, require_evidence: bool,
) -> tuple[bytes, StaticIndex | None]:
    raw = _read(Path(path))
    value = _object(raw)
    if set(value) != {"evidence", "coverage"} or not all(isinstance(value[key], list) for key in ("evidence", "coverage")):
        raise AuditError("manual_evidence_shape", "exact evidence/coverage arrays are required")
    if len(value["evidence"]) + len(value["coverage"]) > 5000:
        raise AuditError("manual_evidence_limit", "bounded evidence/coverage object count exceeded")
    try:
        evidence = [Evidence.model_validate_json(canonical_json(item)) for item in value["evidence"]]
        coverage = [CoverageReport.model_validate_json(canonical_json(item)) for item in value["coverage"]]
    except ValidationError as exc:
        raise AuditError("invalid_manual_evidence", "closed evidence/coverage records required") from exc
    if require_evidence and not evidence:
        raise AuditError("manual_evidence_missing", "nonunknown judgment requires reopened evidence")
    if len({item.evidence_id for item in evidence}) != len(evidence) or len({item.coverage_id for item in coverage}) != len(coverage):
        raise AuditError("duplicate_manual_evidence", "evidence and coverage IDs must be unique")
    predicates = {item.predicate_id: item for item in claim.predicates}
    if any(predicates.get(item.query.predicate_id) != item.query for item in [*evidence, *coverage]):
        raise AuditError("manual_evidence_foreign", "query must retain exact manual predicate/qualifiers")
    if evidence or coverage:
        if index is None:
            index = build_index(snapshot, snapshot_root)
        for item in coverage:
            validate_coverage(snapshot, item, index)
        for item in evidence:
            validate_evidence(snapshot, snapshot_root, item, coverage, index)
    return raw, index


def _subject(record: ManualAnnotation, atom: GoldAtom) -> Claim:
    claims = {claim.claim_id: claim for claim in record.inventory.claims}
    claim = claims.get(atom.claim.claim_id)
    if (claim is None or atom.claim != claim or atom.family_id != record.family_id
            or atom.gold_id != stable_id("annotation-subject", record.family_id, claim.claim_id)):
        raise AuditError("manual_ruling_subject", "ruling must bind an exact manual atom and stable family/subject identity")
    return claim


def record_manual_ruling(
    snapshot_root: Path, annotation_path: Path, ledger_path: Path, *, atom: GoldAtom,
    evidence_path: Path, recorded_at: str, human_action_id: str | None = None,
    supersedes_ruling_id: str | None = None, human_confirmation: bool = False,
) -> AnnotationRuling:
    """Connect actual supplied judgment to source-first coverage and history."""
    record = load_manual_annotation(snapshot_root, annotation_path)
    claim = _subject(record, atom)
    if atom.annotator_type != record.annotator_type:
        raise AuditError("manual_actor_conflict", "human inventory review must be explicit before human rulings; never bulk-upgrade agent work")
    if _timestamp(recorded_at) < _timestamp(record.recorded_at):
        raise AuditError("manual_ruling_date", "recording cannot predate retained manual inventory")
    if atom.annotator_type == "human" and human_confirmation is not True:
        raise AuditError("human_action_required", "actual human ruling requires explicit confirmation")
    snapshot = load_snapshot(Path(snapshot_root))
    validate_span(snapshot, Path(snapshot_root), claim.span)
    raw, _ = _bundle(snapshot, Path(snapshot_root), claim, evidence_path, None,
                     require_evidence=atom.verdict != "unknown")
    row = make_ruling(atom, source_manifest_digest=snapshot.manifest_digest, evidence_digest=sha256(raw),
                      recorded_at=recorded_at, supersedes_ruling_id=supersedes_ruling_id,
                      human_action_id=human_action_id)
    _outside_source(snapshot_root, Path(ledger_path))
    return append_ruling(ledger_path, row, human_confirmation=human_confirmation)


def _judgment(row: AnnotationRuling) -> bytes:
    atom = row.atom
    return canonical_json([atom.verdict, atom.support_relation, atom.answerable,
                           sorted(atom.supported_predicate_ids), sorted(atom.unresolved_predicate_ids),
                           sorted(atom.accused_predicate_ids)])


def _export_labels(
    snapshot_root: Path, annotation_path: Path, ledger_path: Path, out: Path, *,
    evidence_files: dict[str, Path], ruling_ids: dict[str, str], human: bool,
    human_confirmation: bool = False, operator_id: str | None = None,
    action_id: str | None = None, recorded_at: str | None = None,
    adjudication_rationale: str | None = None,
) -> str:
    record = load_manual_annotation(snapshot_root, annotation_path)
    expected_type = "human" if human else "agent"
    if record.annotator_type != expected_type:
        raise AuditError("manual_actor_conflict", "human and preliminary-agent inventory exports remain separate")
    claims = {claim.claim_id: claim for claim in record.inventory.claims}
    if not claims or not ruling_ids:
        raise AuditError("manual_annotation_pending", "unannotated source stays pending; no empty gold/proposal release")
    if human:
        if human_confirmation is not True:
            raise AuditError("human_action_required", "gold export requires an actual explicit human operator action")
        _actor("human", operator_id or "", recorded_at or "", action_id)
        if not (adjudication_rationale or "").strip():
            raise AuditError("manual_adjudication_pending", "actual export/adjudication rationale is required")
        if not record.inventory.complete or set(ruling_ids) != set(claims):
            raise AuditError("manual_annotation_incomplete", "human gold requires full raw-block review and one selected ruling for every manual atom")
    elif not set(ruling_ids) <= set(claims):
        raise AuditError("manual_ruling_subject", "proposal selection contains foreign claims")
    history = load_rulings(ledger_path)
    snapshot = load_snapshot(Path(snapshot_root))
    for row in history:
        _subject(record, row.atom)
        if row.source_manifest_digest != snapshot.manifest_digest:
            raise AuditError("manual_source_changed", "ruling history belongs to different frozen source", 4)
    judged_claims = {row.atom.claim.claim_id for row in history}
    if set(evidence_files) != judged_claims:
        raise AuditError("manual_evidence_scope", "reopen exactly one evidence bundle for every claim in retained history")
    index = None
    bundles = {}
    total = 0
    for claim_id, path in sorted(evidence_files.items()):
        require = any(row.atom.claim.claim_id == claim_id and row.atom.verdict != "unknown" for row in history)
        raw, index = _bundle(snapshot, Path(snapshot_root), claims[claim_id], path, index, require_evidence=require)
        total += len(raw)
        if total > MAX_STAGE_BYTES:
            raise AuditError("manual_evidence_limit", "combined reopened evidence exceeds policy cap")
        bundles[claim_id] = raw
    latest = current_rulings(ledger_path, source_manifest_digest=snapshot.manifest_digest,
                            claim_digests={key: sha256(canonical_json(claims[key])) for key in judged_claims},
                            evidence_digests={key: sha256(raw) for key, raw in bundles.items()})
    if canonical_json(load_rulings(ledger_path)) != canonical_json(history):
        raise AuditError("manual_ruling_history_changed", "history changed during export preparation; retry with a fresh explicit action", 4)
    if len(set(ruling_ids.values())) != len(ruling_ids):
        raise AuditError("duplicate_manual_selection", "one ruling cannot silently fill multiple atoms")
    current = {row.ruling_id: row for row in latest}
    selected = []
    for claim in record.inventory.claims:
        if claim.claim_id not in ruling_ids:
            continue
        row = current.get(ruling_ids[claim.claim_id])
        if row is None or row.atom.claim.claim_id != claim.claim_id or row.atom.annotator_type != expected_type:
            raise AuditError("manual_ruling_selection", "select the latest exact-subject ruling with the required actual annotator type")
        if human:
            if _timestamp(recorded_at or "") < max(_timestamp(record.recorded_at), _timestamp(row.recorded_at)):
                raise AuditError("manual_export_date", "export action cannot predate inventory/ruling records")
            conflicts = {other.ruling_id for other in latest
                         if other.atom.claim.claim_id == claim.claim_id and _judgment(other) != _judgment(row)}
            if not conflicts <= set(row.atom.disagreements):
                raise AuditError("manual_adjudication_pending", "selected human ruling must explicitly preserve every competing latest judgment ID in disagreements")
        selected.append(row)
    out = Path(os.path.abspath(out))
    source = Path(os.path.abspath(snapshot_root))
    if out == source or source in out.parents:
        raise AuditError("manual_output_inside_source", "labels must stay outside inference snapshot")
    _ordinary_directory(out.parent)
    out.mkdir(exist_ok=False)
    (out / "evidence").mkdir()
    evidence_inventory = []
    for claim_id, raw in sorted(bundles.items()):
        name = sha256(claim_id.encode("utf-8")) + ".json"
        _write(out / "evidence" / name, raw)
        evidence_inventory.append({"claim_id": claim_id, "path": f"evidence/{name}", "sha256": sha256(raw)})
    labels_raw = b"".join(canonical_json(row.atom) + b"\n" for row in selected)
    labels_name = "gold.jsonl" if human else "agent-proposals.jsonl"
    ledger_raw = b"".join(canonical_json(row) + b"\n" for row in history)
    annotation_raw = canonical_json(record) + b"\n"
    _write(out / labels_name, labels_raw)
    _write(out / "rulings.jsonl", ledger_raw)
    _write(out / "annotation.json", annotation_raw)
    metadata = {"format": "manual-label-export/1", "designation": "DEV_ONLY",
                "mode": "human_confirmed_gold" if human else "agent_preliminary_proposals",
                "source_manifest_digest": snapshot.manifest_digest, "annotation_id": record.annotation_id,
                "annotation_sha256": sha256(annotation_raw), "rulings_sha256": sha256(ledger_raw),
                "labels_file": labels_name, "labels_sha256": sha256(labels_raw),
                "evidence": evidence_inventory, "selected_ruling_ids": ruling_ids,
                "manual_inventory_complete": record.inventory.complete,
                "pending_claim_ids": sorted(set(claims) - set(ruling_ids)),
                "pending_block_ids": [block.block_id for block in record.inventory.blocks if block.status in {"unsupported", "unparsed"}],
                "operator_id": operator_id, "action_id": action_id, "recorded_at": recorded_at,
                "adjudication_rationale": adjudication_rationale,
                "human_confirmation": human_confirmation, "human_review_independently_verified": False,
                "custody_verified": False, "heldout": False, "admitted": False,
                "comparative_complete": False}
    raw = canonical_json(metadata) + b"\n"
    _write(out / "EXPORT.json", raw)  # Last marker; no cleanup/replacement on failure.
    return sha256(raw)


def export_manual_gold(
    snapshot_root: Path, annotation_path: Path, ledger_path: Path, out: Path, *,
    evidence_files: dict[str, Path], ruling_ids: dict[str, str], operator_id: str,
    action_id: str, recorded_at: str, adjudication_rationale: str,
    human_confirmation: bool = False,
) -> str:
    """Future explicit human action only: export scorer-compatible GoldAtom JSONL."""
    return _export_labels(snapshot_root, annotation_path, ledger_path, out, evidence_files=evidence_files,
                          ruling_ids=ruling_ids, human=True, human_confirmation=human_confirmation,
                          operator_id=operator_id, action_id=action_id, recorded_at=recorded_at,
                          adjudication_rationale=adjudication_rationale)


def export_manual_proposals(
    snapshot_root: Path, annotation_path: Path, ledger_path: Path, out: Path, *,
    evidence_files: dict[str, Path], ruling_ids: dict[str, str],
) -> str:
    """Export explicitly preliminary agent rows and retain pending coverage."""
    return _export_labels(snapshot_root, annotation_path, ledger_path, out, evidence_files=evidence_files,
                          ruling_ids=ruling_ids, human=False)


def audit_manual_omissions(
    snapshot_root: Path, annotation_path: Path, candidate_inventory_path: Path, out: Path,
) -> str:
    """Compare a frozen manual denominator using the existing scorer matcher."""
    from claim_auditor.evaluation.scoring import _claim_key

    record = load_manual_annotation(snapshot_root, annotation_path)
    try:
        candidate = Inventory.model_validate_json(read_ordinary(Path(candidate_inventory_path).parent,
                                                               Path(candidate_inventory_path).name, MAX_ANNOTATION_BYTES))
    except (ValidationError, ValueError, OSError) as exc:
        raise AuditError("invalid_candidate_inventory", "bounded closed Inventory input required") from exc
    if ((candidate.snapshot_id, candidate.readme_path, candidate.readme_sha256)
            != (record.inventory.snapshot_id, record.inventory.readme_path, record.inventory.readme_sha256)):
        raise AuditError("manual_candidate_source_changed", "candidate/manual inventories must share exact source/README identity", 4)
    if len(candidate.claims) > Limits().max_atoms:
        raise AuditError("candidate_inventory_limit", "candidate atom count exceeds bounded source comparison policy")
    if len({claim.claim_id for claim in candidate.claims}) != len(candidate.claims):
        raise AuditError("duplicate_candidate_claim", "candidate identities cannot overwrite omissions")
    snapshot = load_snapshot(Path(snapshot_root))
    by_key: dict[bytes, list[str]] = {}
    for claim in candidate.claims:
        if claim.span.path != candidate.readme_path:
            raise AuditError("manual_candidate_claim_scope", "candidate claim must point into its declared original README")
        validate_span(snapshot, Path(snapshot_root), claim.span)
        by_key.setdefault(_claim_key(claim), []).append(claim.claim_id)
    matched, omitted, ambiguous = [], [], []
    used = set()
    for claim in record.inventory.claims:
        options = by_key.get(_claim_key(claim), [])
        if len(options) == 1:
            matched.append(claim.claim_id)
            used.add(options[0])
        elif options:
            ambiguous.append(claim.claim_id)
        else:
            omitted.append(claim.claim_id)
    result = {"format": "manual-omission-audit/1", "annotation_id": record.annotation_id,
              "source_manifest_digest": record.source_manifest_digest,
              "candidate_inventory_sha256": sha256(canonical_json(candidate)),
              "matcher": "existing evaluation.scoring._claim_key",
              "manual_inventory_complete": record.inventory.complete, "candidate_inventory_complete": candidate.complete,
              "candidate_errors": candidate.errors,
              "candidate_unresolved_block_ids": [block.block_id for block in candidate.blocks if block.status in {"unsupported", "unparsed"}],
              "status": "descriptive_source_comparison" if record.inventory.complete else "provisional_manual_review_incomplete",
              "all_manual_claim_ids": [claim.claim_id for claim in record.inventory.claims],
              "matched_manual_ids": matched, "omitted_manual_ids": omitted, "ambiguous_manual_ids": ambiguous,
              "extra_candidate_ids": [claim.claim_id for claim in candidate.claims if claim.claim_id not in used],
              "pending_block_ids": [block.block_id for block in record.inventory.blocks if block.status in {"unsupported", "unparsed"}],
              "human_review_independently_verified": False, "comparative_complete": False}
    raw = canonical_json(result) + b"\n"
    _outside_source(snapshot_root, Path(out))
    _write(Path(out), raw)
    return sha256(raw)
