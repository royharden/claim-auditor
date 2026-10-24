"""DEV-only staging source. Digests bind bytes; they never establish custody.

No heldout admission, ACL provisioning, human review or external access is supplied.
All operations are dormant until an operator is authorized to run them.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat

from claim_auditor.contracts import (
    AuditError, CoverageReport, Evidence, Snapshot, canonical_json, sha256, validate_relative_path,
)
from claim_auditor.snapshot import copy_snapshot, create_fixture_snapshot, load_snapshot
from claim_auditor.snapshot.safeio import SnapshotError, bounded_scandir, read_ordinary

MAX_STAGE_BYTES = 32 * 1024 * 1024
MAX_STAGE_FILES = 5020
MAX_CONTROL_BYTES = 4 * 1024 * 1024
_ALIAS = re.compile(r"f-[a-f0-9]{16}")


def _fail(reason: str, detail: str, exit_code: int = 2) -> AuditError:
    return AuditError(reason, detail, exit_code)


def _dev_only(designation: str, admission_requested: bool) -> None:
    if designation != "DEV_ONLY" or admission_requested is not False:
        raise _fail("custody_admission_unsupported", "this service stages disclosed DEV bytes only; heldout/admission is external")


def _alias(alias: str) -> str:
    if not _ALIAS.fullmatch(alias):
        raise _fail("unsafe_family_alias", "provide an opaque f- plus 16 lowercase hexadecimal digits; never encode outcomes")
    return alias


def _directory(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    for item in [*reversed(absolute.parents), absolute]:
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise _fail("unsafe_staging_path", "ordinary operator-owned directories are required")


def _fresh(out: Path, inputs: list[Path]) -> Path:
    out = Path(os.path.abspath(out))
    for source in inputs:
        source = Path(os.path.abspath(source))
        if out == source or source in out.parents:
            raise _fail("staging_output_inside_input", "outputs must be fresh and outside preserved input trees")
    _directory(out.parent)
    out.mkdir(exist_ok=False)
    return out


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _nonfinite(value: str) -> object:
    raise ValueError("nonfinite JSON number")


def _object(raw: bytes) -> dict[str, object]:
    try:
        result = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)
        if not isinstance(result, dict):
            raise ValueError("object required")
        return result
    except (ValueError, UnicodeDecodeError) as exc:
        raise _fail("invalid_stage_metadata", "bounded UTF-8 JSON object without duplicate keys is required") from exc


def _read(path: Path, cap: int = MAX_CONTROL_BYTES) -> bytes:
    try:
        return read_ordinary(path.parent, path.name, cap=cap)
    except (OSError, SnapshotError) as exc:
        raise _fail("invalid_stage_input", "ordinary bounded source/control file required") from exc


def _keys(value: dict[str, object], keys: set[str]) -> None:
    if set(value) != keys:
        raise _fail("invalid_stage_metadata", "missing or extra envelope fields")


def _provenance(value: dict[str, object], snapshot: Snapshot) -> None:
    if value.get("designation") != "DEV_ONLY" or value.get("heldout") is not False:
        raise _fail("custody_admission_unsupported", "provenance must declare disclosed DEV material, never heldout")
    if any(key in value and value[key] is not False for key in ("admitted", "custody_verified", "human_gold")):
        raise _fail("custody_admission_unsupported", "provenance cannot certify admission/custody/human gold")
    if value.get("format") != "corpus-dev-provenance/1" or not isinstance(value.get("ancestry"), dict):
        raise _fail("invalid_dev_provenance", "versioned authorship, ancestry and rights provenance is required")
    for field in ("family_id", "author_id", "origin", "rights_basis"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise _fail("invalid_dev_provenance", "nonempty authorship/family/origin/rights fields are required")
    if value.get("author_type") not in {"agent", "human"}:
        raise _fail("invalid_dev_provenance", "explicit actual author type is required")
    entries = [{"path": item.path, "sha256": item.sha256, "size": item.size} for item in snapshot.entries]
    inventory_digest = sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    if (value.get("inventory_digest_method") != "sha256(sorted compact JSON source_inventory, ensure_ascii default)"
            or value.get("source_inventory") != entries or value.get("source_inventory_digest") != inventory_digest):
        raise _fail("dev_source_inventory_changed", "frozen source differs from supplied provenance inventory", 4)
    if not snapshot.complete or snapshot.source_kind != "fixture_inventory":
        raise _fail("incomplete_dev_stage", "this DEV loose-source stage requires a complete fixture inventory")
    for item in snapshot.entries:
        for part in item.path.casefold().split("/"):
            if part.startswith(("gold", "labels", "rulings", "provenance", "review-prompts")):
                raise _fail("annotation_material_in_source", "keep known annotation/provenance material outside inference source")


def _receipt(value: dict[str, object]) -> None:
    _keys(value, {"format", "receipt_id", "operator_id", "recorded_at", "intended_use",
                  "rights_review", "source_contains_annotation_material", "access_control",
                  "custody_verified", "heldout", "admitted"})
    if (value["format"] != "dev-access-receipt/1" or value["intended_use"] != "DEV_ONLY"
            or value["rights_review"] != "operator_attested"
            or value["source_contains_annotation_material"] is not False
            or value["access_control"] != "operator_attestation_only"
            or any(value[key] is not False for key in ("custody_verified", "heldout", "admitted"))):
        raise _fail("unsupported_access_claim", "an operator attestation cannot certify custody, blindness or admission")
    for key in ("receipt_id", "operator_id", "recorded_at"):
        if not isinstance(value[key], str) or not value[key].strip():
            raise _fail("missing_access_receipt", "actual operator identity/date/receipt are required; never prepopulate them")
    try:
        recorded = datetime.fromisoformat(value["recorded_at"].replace("Z", "+00:00"))
        if recorded.tzinfo is None or recorded > datetime.now(timezone.utc):
            raise ValueError("invalid date")
    except ValueError as exc:
        raise _fail("invalid_access_receipt_date", "actual aware nonfuture operator date is required") from exc


def _inventory(root: Path) -> list[dict[str, object]]:
    _directory(root)
    pending = [root]
    entries = []
    total = 0
    observed = 0
    while pending:
        directory = pending.pop()
        _directory(directory)
        for item in bounded_scandir(directory, MAX_STAGE_FILES):
            observed += 1
            if observed > MAX_STAGE_FILES * 2:
                raise _fail("dev_stage_limit", "too many filesystem entries")
            path = Path(item.path)
            relative = path.relative_to(root).as_posix()
            validate_relative_path(relative)
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise _fail("unsafe_staging_path", "no links or reparse points in stage")
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
            elif stat.S_ISREG(info.st_mode):
                if relative in {"STAGE.json", "SEAL.json"}:
                    continue
                if len(entries) >= MAX_STAGE_FILES:
                    raise _fail("dev_stage_limit", "too many stage files")
                raw = read_ordinary(root, relative, cap=MAX_CONTROL_BYTES)
                total += len(raw)
                if total > MAX_STAGE_BYTES:
                    raise _fail("dev_stage_limit", "stage byte ceiling exceeded")
                entries.append({"path": relative, "size": len(raw), "sha256": sha256(raw)})
            else:
                raise _fail("unsafe_staging_path", "ordinary files only")
    return sorted(entries, key=lambda row: row["path"])


def _write(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def stage_dev_family(
    source_root: Path, out: Path, *, alias: str, provenance_path: Path,
    access_receipt_path: Path, designation: str = "DEV_ONLY", admission_requested: bool = False,
) -> str:
    """Future operator operation; return the exact SEAL.json byte SHA256.

    Receipt inputs must already exist from an actual operator action. This function
    never manufactures an access receipt or asserts that a control is effective.
    """
    _dev_only(designation, admission_requested)
    alias = _alias(alias)
    provenance_raw, receipt_raw = _read(Path(provenance_path)), _read(Path(access_receipt_path))
    provenance, receipt = _object(provenance_raw), _object(receipt_raw)
    _receipt(receipt)
    out = _fresh(Path(out), [Path(source_root)])
    (out / "source").mkdir()
    (out / "control").mkdir()
    snapshot = create_fixture_snapshot(Path(source_root), out / "source" / alias)
    _provenance(provenance, snapshot)
    _write(out / "control" / "provenance.json", provenance_raw)
    _write(out / "control" / "access-receipt.json", receipt_raw)
    stage = {"format": "dev-stage/1", "designation": "DEV_ONLY", "alias": alias,
             "source_manifest_digest": snapshot.manifest_digest, "artifacts": _inventory(out),
             "custody_verified": False, "heldout": False, "admitted": False}
    stage_raw = canonical_json(stage) + b"\n"
    _write(out / "STAGE.json", stage_raw)
    seal = {"format": "dev-stage-seal/1", "stage_sha256": sha256(stage_raw),
            "source_manifest_digest": snapshot.manifest_digest, "designation": "DEV_ONLY",
            "custody_verified": False, "heldout": False, "admitted": False}
    seal_raw = canonical_json(seal) + b"\n"
    _write(out / "SEAL.json", seal_raw)  # Last marker; failed directories are preserved.
    return sha256(seal_raw)


def verify_dev_stage(root: Path, *, expected_seal_digest: str) -> Snapshot:
    """Reopen exact DEV files against an independently retained seal digest."""
    root = Path(root)
    if not re.fullmatch(r"[a-f0-9]{64}", expected_seal_digest):
        raise _fail("invalid_dev_seal", "independently retained full seal digest is mandatory")
    seal_raw = _read(root / "SEAL.json")
    if sha256(seal_raw) != expected_seal_digest:
        raise _fail("dev_seal_changed", "seal bytes differ from operator's pinned identity", 4)
    seal = _object(seal_raw)
    _keys(seal, {"format", "stage_sha256", "source_manifest_digest", "designation", "custody_verified", "heldout", "admitted"})
    if seal["format"] != "dev-stage-seal/1" or seal["designation"] != "DEV_ONLY" or any(seal[key] is not False for key in ("custody_verified", "heldout", "admitted")):
        raise _fail("custody_admission_unsupported", "seal cannot certify heldout/custody/admission")
    stage_raw = _read(root / "STAGE.json")
    if sha256(stage_raw) != seal["stage_sha256"]:
        raise _fail("dev_manifest_changed", "stage bytes differ from sealed identity", 4)
    stage = _object(stage_raw)
    _keys(stage, {"format", "designation", "alias", "source_manifest_digest", "artifacts", "custody_verified", "heldout", "admitted"})
    if stage["format"] != "dev-stage/1" or stage["designation"] != "DEV_ONLY" or any(stage[key] is not False for key in ("custody_verified", "heldout", "admitted")):
        raise _fail("custody_admission_unsupported", "manifest cannot certify heldout/custody/admission")
    if not isinstance(stage["alias"], str):
        raise _fail("unsafe_family_alias", "alias must be an opaque string")
    alias = _alias(stage["alias"])
    if _inventory(root) != stage["artifacts"]:
        raise _fail("dev_stage_artifact_changed", "missing, extra or modified stage artifacts", 4)
    expected_paths = {"control/provenance.json", "control/access-receipt.json"}
    for item in stage["artifacts"]:
        if item["path"] not in expected_paths and not item["path"].startswith(f"source/{alias}/"):
            raise _fail("annotation_material_in_source", "stage contains an undeclared control/label scope")
    snapshot = load_snapshot(root / "source" / alias)
    if snapshot.manifest_digest != stage["source_manifest_digest"] or snapshot.manifest_digest != seal["source_manifest_digest"]:
        raise _fail("dev_source_manifest_changed", "source manifest does not match stage/seal", 4)
    _provenance(_object(_read(root / "control" / "provenance.json")), snapshot)
    _receipt(_object(_read(root / "control" / "access-receipt.json")))
    return snapshot


def export_dev_source(root: Path, out: Path, *, expected_seal_digest: str) -> str:
    """Copy only the aliased snapshot, excluding provenance, receipts and labels."""
    snapshot = verify_dev_stage(root, expected_seal_digest=expected_seal_digest)
    stage = _object(_read(Path(root) / "STAGE.json"))
    alias = _alias(stage["alias"])
    out = _fresh(Path(out), [Path(root)])
    copy_snapshot(snapshot, Path(root) / "source" / alias, out / alias)
    return snapshot.manifest_digest


def stage_dev_labels(
    root: Path, ledger_path: Path, out: Path, *, expected_seal_digest: str,
    evidence_files: dict[str, Path], human_confirmation: bool = False,
) -> str:
    """Export existing judgments to a separate fresh label tree, never create gold.

    Full prior history and disagreements survive. Any human attribution needs the
    operator's explicit confirmation of a real action; no new action is invented.
    """
    from claim_auditor.citations import validate_coverage, validate_evidence, validate_span
    from claim_auditor.evaluation.rulings import load_rulings
    from claim_auditor.index import build_index

    snapshot = verify_dev_stage(root, expected_seal_digest=expected_seal_digest)
    stage = _object(_read(Path(root) / "STAGE.json"))
    alias = _alias(stage["alias"])
    snapshot_root = Path(root) / "source" / alias
    provenance = _object(_read(Path(root) / "control" / "provenance.json"))
    rows = load_rulings(Path(ledger_path))
    if any(row.atom.annotator_type == "human" for row in rows) and human_confirmation is not True:
        raise _fail("human_action_required", "existing human attributions still require explicit actual-action confirmation")
    if {row.atom.claim.claim_id for row in rows} != set(evidence_files):
        raise _fail("dev_label_evidence_scope", "provide exactly one reopened evidence bundle per judged claim")
    index = build_index(snapshot, snapshot_root)
    if index.errors:
        raise _fail("dev_label_scope_incomplete", "parser errors prevent citation-integrity staging")
    bundles: dict[str, bytes] = {}
    validated_claims: set[str] = set()
    evidence_claims: set[str] = set()
    bundle_bytes = 0
    for row in rows:
        if row.source_manifest_digest != snapshot.manifest_digest or row.atom.family_id != provenance["family_id"]:
            raise _fail("dev_label_source_changed", "judgment belongs to different frozen source/family", 4)
        validate_span(snapshot, snapshot_root, row.atom.claim.span)
        claim_id = row.atom.claim.claim_id
        if claim_id not in bundles:
            bundles[claim_id] = _read(Path(evidence_files[claim_id]))
            bundle_bytes += len(bundles[claim_id])
            if bundle_bytes > MAX_STAGE_BYTES:
                raise _fail("dev_stage_limit", "combined evidence bundles exceed label-stage byte ceiling")
        raw = bundles[claim_id]
        if sha256(raw) != row.evidence_digest:
            raise _fail("dev_label_evidence_changed", "evidence bytes differ from original judgment binding", 4)
        if claim_id in validated_claims:
            if row.atom.verdict != "unknown" and claim_id not in evidence_claims:
                raise _fail("dev_label_evidence_missing", "nonunknown judgment requires reopened evidence")
            continue
        bundle = _object(raw)
        _keys(bundle, {"evidence", "coverage"})
        if not isinstance(bundle["evidence"], list) or not isinstance(bundle["coverage"], list):
            raise _fail("invalid_dev_label_evidence", "evidence/coverage arrays required")
        if len(bundle["evidence"]) + len(bundle["coverage"]) > 5000:
            raise _fail("dev_stage_limit", "evidence/coverage object count exceeds per-claim ceiling")
        evidence = [Evidence.model_validate_json(canonical_json(item)) for item in bundle["evidence"]]
        coverage = [CoverageReport.model_validate_json(canonical_json(item)) for item in bundle["coverage"]]
        if (len({item.evidence_id for item in evidence}) != len(evidence)
                or len({item.coverage_id for item in coverage}) != len(coverage)):
            raise _fail("duplicate_dev_label_evidence", "evidence/coverage identities must be unique")
        predicates = {item.predicate_id: item for item in row.atom.claim.predicates}
        if any(predicates.get(item.query.predicate_id) != item.query for item in [*evidence, *coverage]):
            raise _fail("dev_label_foreign_evidence", "bundle query must match an exact claim predicate, including qualifiers")
        if row.atom.verdict != "unknown" and not evidence:
            raise _fail("dev_label_evidence_missing", "nonunknown judgment requires reopened supporting/contrary/absence evidence")
        if evidence:
            evidence_claims.add(claim_id)
        for item in coverage:
            validate_coverage(snapshot, item, index)
        for item in evidence:
            validate_evidence(snapshot, snapshot_root, item, coverage, index)
        validated_claims.add(claim_id)
    out = _fresh(Path(out), [Path(root), Path(ledger_path)])
    (out / "evidence").mkdir()
    evidence_inventory = []
    for claim_id, raw in sorted(bundles.items()):
        name = sha256(claim_id.encode("utf-8")) + ".json"
        _write(out / "evidence" / name, raw)
        evidence_inventory.append({"claim_id": claim_id, "path": f"evidence/{name}", "sha256": sha256(raw)})
    ledger_raw = b"".join(canonical_json(row) + b"\n" for row in rows)
    _write(out / "rulings.jsonl", ledger_raw)
    metadata = {"format": "dev-label-stage/1", "designation": "DEV_ONLY",
                "source_manifest_digest": snapshot.manifest_digest, "stage_seal_digest": expected_seal_digest,
                "rulings_sha256": sha256(ledger_raw), "evidence": evidence_inventory,
                "judgment_rows": len(rows), "gold_created": False, "admitted": False,
                "human_review_verified": False, "custody_verified": False}
    raw = canonical_json(metadata) + b"\n"
    _write(out / "LABELS.json", raw)
    return sha256(raw)
