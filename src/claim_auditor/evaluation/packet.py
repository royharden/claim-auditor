"""Label-free bounded packet preparation; no provider is invoked here."""

from __future__ import annotations

import re
from bisect import bisect_right
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from claim_auditor.contracts import (
    AuditError, EvaluationLock, EvaluationPacket, EvaluationPreparation,
    Limits, POLICY_VERSION, SCHEMA_VERSION, PacketExcerpt, ScopeGap, Snapshot, canonical_json, sha256,
)
from claim_auditor.evaluation.scoring import MATCHER_VERSION
from claim_auditor.inventory.raw import RawDocument
from claim_auditor.snapshot import load_snapshot, read_source
from claim_auditor.snapshot.safeio import MAX_FILE_BYTES, read_ordinary

PACKET_VERSION = "readme-anchors/1"
_REQUIRED_ARMS = {"product_full_index", "packet_candidate", "packet_grep", "live_extraction", "live_single_pass"}


def code_digest() -> str:
    """Compatibility API; trusted source identity has one provenance authority."""
    from claim_auditor.provenance import code_digest as trusted_code_digest

    return trusted_code_digest()


def _check_lock(lock: EvaluationLock) -> None:
    if not lock.admitted or not lock.admitted_by or not lock.admitted_at or not lock.custody_receipt.strip() or not lock.source_rights_receipt.strip():
        raise AuditError("evaluation_lock_not_admitted", "admission identity, date, rights and custody receipts are required")
    try:
        admitted = datetime.fromisoformat(lock.admitted_at.replace("Z", "+00:00"))
        if admitted.tzinfo is None or admitted > datetime.now(timezone.utc):
            raise ValueError("admission must be timezone-aware and not in the future")
    except ValueError as exc:
        raise AuditError("invalid_evaluation_lock", "invalid admission timestamp") from exc
    if lock.heldout_accessed:
        raise AuditError("heldout_already_accessed", "retire disclosed families to dev; obtain a fresh independent source seal")
    if lock.taxonomy_version != POLICY_VERSION or lock.matcher_version != MATCHER_VERSION or lock.packet_version != PACKET_VERSION:
        raise AuditError("evaluation_lock_version_mismatch", "locked taxonomy/matcher/packet versions differ")
    if set(lock.arm_names) != _REQUIRED_ARMS or len(set(lock.arm_names)) != len(lock.arm_names):
        raise AuditError("missing_required_arms", "all required paired and separate full-index arms must be named exactly once")
    if any(not lock.provider_models.get(arm, "").strip() for arm in ("live_extraction", "live_single_pass")):
        raise AuditError("unresolved_model_identity", "required live arms need locked explicit provider/model identities")
    if lock.max_input_tokens > 32000 or lock.max_output_tokens > 8000 or lock.max_remote_seconds > 60:
        raise AuditError("evaluation_budget_exceeds_policy", "locked total caps exceed admitted per-README policy")
    if lock.max_cost_usd is None or lock.max_cost_usd < 0:
        raise AuditError("monetary_cap_unknown", "a concrete authorized ceiling is required before evaluation preparation")
    if lock.code_digest != code_digest():
        raise AuditError("evaluation_code_mismatch", "installed source closure differs from admitted lock")


def _build_packet(snapshot: Snapshot, input_path: Path) -> EvaluationPacket:
    """Sole raw-anchor builder shared by DEV and admitted preparation."""
    readme_path = "README.md"
    # Same lookup as inventory.extract_inventory: a README absent from the snapshot is an
    # input error (2); one excluded at snapshot time keeps its gap reason and entry digest.
    # Only included sources reach read_source, whose failures are integrity (4).
    entry = next((item for item in snapshot.entries if item.path == readme_path), None)
    if entry is None:
        raise AuditError("readme_not_in_snapshot", readme_path, 2)
    if entry.status != "included":
        gap = next((item.reason for item in snapshot.exclusions if item.path == readme_path), entry.status)
        # An entry over the per-file read cap was never read: its digest is the snapshot's
        # unread marker, not content. A README between the README and file caps was read.
        label = "unread-marker digest" if entry.size > MAX_FILE_BYTES else "raw sha256"
        detail = f"{gap}; {label} {entry.sha256}"
        if gap == "file_byte_limit":
            raise AuditError("input_too_large", f"mandatory README exceeds policy; every paired arm must retain this failure ({detail})")
        if gap == "unsupported_encoding":
            raise AuditError("unsupported_encoding", f"packet README must be strict UTF-8 ({detail})")
        raise AuditError("readme_excluded", detail, 3)
    readme_raw = read_source(snapshot, input_path, readme_path)
    if len(readme_raw) > Limits().max_readme_bytes:
        raise AuditError("input_too_large", "mandatory README exceeds policy; every paired arm must retain this failure")
    try:
        readme_text = readme_raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuditError("unsupported_encoding", "packet README must be strict UTF-8") from exc
    # Anchors originate in raw README only; no candidate claims, model output,
    # labels, rationale or curator metadata select evidence for the comparator.
    anchors: list[tuple[int, str]] = []
    for match in re.finditer(r"`([^`\n]{1,200})`", readme_text):
        value = match.group(1)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_./-]*", value):
            anchors.append((len(readme_text[:match.start()].encode("utf-8")), value))
    if len(anchors) > 200:
        raise AuditError("packet_anchor_limit", "raw README contains more than 200 admitted anchors")
    anchor_tokens: dict[bytes, list[tuple[int, str]]] = {}
    for occurrence, anchor in anchors:
        token = anchor.rsplit("/", 1)[-1].removesuffix(".py").rsplit(".", 1)[-1].encode("utf-8")
        anchor_tokens.setdefault(token, []).append((occurrence, anchor))
    candidates: list[tuple[int, str, int, int, str, bytes]] = []
    packet_gaps = list(snapshot.exclusions)
    file_entries = [entry for entry in snapshot.entries if entry.status == "included" and entry.path.endswith((".py", ".toml"))]
    for entry in file_entries:
        raw = read_source(snapshot, input_path, entry.path)
        try:
            document = RawDocument.decode(raw)
        except UnicodeDecodeError:
            packet_gaps.append(ScopeGap(path=entry.path, reason="packet_unsupported_encoding"))
            continue
        lines = document.line_bytes
        for occurrence, anchor in anchors:
            if anchor == entry.path:
                end = lines[min(len(lines) - 1, 4)]
                candidates.append((occurrence, entry.path, 0, end, anchor, raw))
        seen_matches: set[tuple[int, int, str]] = set()
        for match in re.finditer(rb"[A-Za-z_][A-Za-z0-9_]*", raw):
            for occurrence, anchor in anchor_tokens.get(match.group(), []):
                line_index = bisect_right(lines, match.start()) - 1
                start = lines[max(0, line_index - 3)]
                end = lines[min(len(lines) - 1, line_index + 4)]
                if (occurrence, start, anchor) in seen_matches:
                    continue
                seen_matches.add((occurrence, start, anchor))
                candidates.append((occurrence, entry.path, start, end, anchor, raw))
                if len(candidates) > 5000:
                    raise AuditError("packet_candidate_limit", "raw static candidate index exceeds 5000 windows")
    candidates.sort(key=lambda value: (value[0], value[1], value[2], value[3]))
    merged: list[tuple[int, str, int, int, str, bytes]] = []
    # Merge in source order first, then restore README-occurrence admission
    # priority. This also handles windows that bridge two older intervals.
    for candidate in sorted(candidates, key=lambda value: (value[1], value[2], value[3])):
        occurrence, path, start, end, anchor, raw = candidate
        if merged and merged[-1][1] == path and start <= merged[-1][3]:
            old = merged[-1]
            merged[-1] = (min(old[0], occurrence), path, old[2], max(old[3], end), anchor if occurrence < old[0] else old[4], raw)
        else:
            merged.append(candidate)
    merged.sort(key=lambda value: (value[0], value[1], value[2]))
    excerpts: list[PacketExcerpt] = []
    admitted_bytes = 0
    omitted = 0
    for _, path, start, end, anchor, raw in merged:
        if end - start > 1024 or admitted_bytes + end - start > 48 * 1024:
            omitted += 1
            continue
        quote = raw[start:end].decode("utf-8", errors="strict")
        excerpts.append(PacketExcerpt(path=path, start_byte=start, end_byte=end, file_sha256=sha256(raw), quote=quote, anchor=anchor))
        admitted_bytes += end - start
    metadata = canonical_json({"entries": snapshot.entries, "exclusions": packet_gaps})
    if len(metadata) > 8 * 1024:
        raise AuditError("input_too_large", "mandatory scope metadata exceeds 8 KiB; no paired semantic arm may silently omit it")
    fields = dict(schema_version=SCHEMA_VERSION, packet_version=PACKET_VERSION, snapshot_id=snapshot.snapshot_id, snapshot_manifest_digest=snapshot.manifest_digest, readme_path=readme_path, readme_sha256=sha256(readme_raw), readme_text=readme_text, excerpts=excerpts, scope_entries=snapshot.entries, exclusions=packet_gaps, candidate_count=len(merged), omitted_count=omitted, complete=snapshot.complete and not packet_gaps and omitted == 0, absence_certificates=False)
    packet = EvaluationPacket(packet_digest=sha256(canonical_json(fields)), **fields)
    return packet


def _source_metadata(root: Path) -> Snapshot:
    """Inspect the sealed control manifest before reading any source file bytes."""
    from claim_auditor.snapshot import _make_snapshot, _manifest_digest

    snapshot = Snapshot.model_validate_json(read_ordinary(root, "manifest.json", cap=4 * 1024 * 1024))
    if _manifest_digest(snapshot.model_dump(mode="json")) != snapshot.manifest_digest:
        raise AuditError("source_seal_mismatch", "source control manifest digest differs", 4)
    expected = _make_snapshot(snapshot.entries, snapshot.exclusions, snapshot.source_kind,
                              snapshot.commit, snapshot.hash_algorithm, snapshot.tree_identity)
    if snapshot != expected:
        raise AuditError("source_seal_mismatch", "source control identities differ", 4)
    return snapshot


def prepare_dev_packet(snapshot_root: Path, out: Path) -> EvaluationPacket:
    """Future keyless DEV operation; never manufactures an admitted experiment."""
    if out.exists() or out.is_symlink():
        raise AuditError("output_exists", "DEV preparation requires a fresh directory")
    if out.resolve() == snapshot_root.resolve() or snapshot_root.resolve() in out.resolve().parents:
        raise AuditError("output_inside_snapshot", "DEV preparation must preserve source")
    snapshot = load_snapshot(snapshot_root)
    packet = _build_packet(snapshot, snapshot_root)
    provenance = dict(designation="DEV_ONLY", source_only=True, admitted=False,
                      human_adjudicated=False, comparative_complete=False, heldout=False,
                      packet_digest=packet.packet_digest, input_digest=sha256(canonical_json(packet)),
                      source_manifest_digest=snapshot.manifest_digest,
                      status="prepared_only", arm_status={name: "not_run" for name in sorted(_REQUIRED_ARMS)},
                      limitations=["Disclosed DEV source only; no LOCK, rights, access or custody receipt is created.",
                                   "Preparation is not inference, human gold, scoring or comparative acceptance."])
    out.mkdir(parents=True, exist_ok=False)
    for name, value in {"packet.json": packet, "DEV.json": provenance}.items():
        with (out / name).open("xb") as handle:
            handle.write(canonical_json(value) + b"\n")
    return packet


def prepare_evaluation(protocol_path: Path, input_path: Path, out: Path) -> EvaluationPreparation:
    try:
        lock = EvaluationLock.model_validate_json(read_ordinary(protocol_path.parent, protocol_path.name, cap=128 * 1024))
    except (ValidationError, ValueError, OSError) as exc:
        raise AuditError("invalid_evaluation_lock", "LOCK must be ordinary bounded closed-schema JSON") from exc
    _check_lock(lock)
    metadata = _source_metadata(input_path)
    if metadata.manifest_digest != lock.source_seal_digest:
        raise AuditError("source_seal_mismatch", "source snapshot differs from admitted source seal", 4)
    snapshot = load_snapshot(input_path)
    if snapshot != metadata:
        raise AuditError("source_seal_mismatch", "source changed after metadata admission", 4)
    packet = _build_packet(snapshot, input_path)
    preparation = EvaluationPreparation(protocol_id=lock.protocol_id, packet_digest=packet.packet_digest, mode="prepared_only", arm_status={name: "not_run" for name in lock.arm_names}, comparative_complete=False, human_adjudicated=False, source_only=True, limitations=[
        "Packet preparation does not run inference or scoring; all required arms remain not measured / comparative acceptance incomplete.",
        "Human-adjudicated evaluation not measured. No gold, labels, adjudication rationale or heldout contents beyond the admitted source snapshot were loaded.",
        "Raw-anchor static text windows are bounded; omitted or absent evidence never certifies absence.",
        "Source/rights/custody admission fields are operator attestations; actual external access isolation must be verified separately.",
        "Provider tokenization/context limits and dependency-lock conformance require later activation; byte caps are not token caps.",
    ])
    if out.exists() or out.is_symlink():
        raise AuditError("output_exists", "evaluation preparation output must be fresh")
    out.mkdir(parents=True, exist_ok=False)
    for name, value in {"protocol-copy.json": lock, "packet.json": packet, "PREPARED.json": preparation}.items():
        with (out / name).open("xb") as handle:
            handle.write(canonical_json(value) + b"\n")
    return preparation
