"""Explicit provider ports. Live execution is disabled in this baseline."""

from __future__ import annotations

from pathlib import Path

from ..contracts import AuditError, Claim, POLICY_VERSION, canonical_json, sha256
from ..screen import screen_text


def require_no_live(mode: str) -> None:
    if mode == "live":
        raise AuditError("live_not_authorized", "Live extraction and single-pass comparison are not measured; no transport is enabled.")


def load_replay(
    path: Path,
    *,
    input_digest: str,
    prompt_digest: str,
    model: str,
    readme_text: str,
) -> list[Claim]:
    """Read a closed, input/prompt/model/policy-bound extraction proposal."""
    from ..contracts import ReplayEnvelope

    if screen_text(readme_text):
        raise AuditError("abstention_screened", "Model-bound input held before replay.", 3)
    from ..snapshot.safeio import SnapshotError, read_ordinary

    try:
        raw = read_ordinary(path.parent, path.name, cap=2 * 1024 * 1024)
    except (SnapshotError, OSError) as exc:
        raise AuditError("invalid_replay", "Replay must be a bounded ordinary file.") from exc
    envelope = ReplayEnvelope.model_validate_json(raw)
    if (envelope.input_digest, envelope.prompt_digest, envelope.model, envelope.policy_version) != (
        input_digest, prompt_digest, model, POLICY_VERSION,
    ):
        raise AuditError("replay_identity_mismatch", "Replay input/prompt/model/policy hashes differ.", 4)
    if sha256(canonical_json(envelope.claims)) != envelope.claims_digest:
        raise AuditError("replay_digest_mismatch", "Replay claim bytes differ.", 4)
    return envelope.claims
