"""Author explicit fake input configuration, never predictions or measurements."""

from __future__ import annotations

from pathlib import Path

from ..contracts import (
    AuditError, EvaluationPacket, POLICY_VERSION, PairedRunConfig, ProviderCaps,
    ProviderFixture, ProviderRequest, SimulatedUsage, canonical_json, sha256,
)
from ..snapshot.safeio import read_ordinary
from .port import _validate_request, request_digest


def write_fake_config(packet_path: Path, out: Path) -> PairedRunConfig:
    """Create a fresh identity-bound failure template for both paired model roles.

    No model output is generated. A user must explicitly author replacement
    fixture proposals to simulate successful inference. Null simulated usage is
    deliberately unresolved, and cannot become a real cost/token observation.
    """
    packet = EvaluationPacket.model_validate_json(read_ordinary(packet_path.parent, packet_path.name, cap=4 * 1024 * 1024))
    if out.resolve() == packet_path.resolve() or packet_path.parent.resolve() in out.resolve().parents:
        raise AuditError("config_inside_packet", "Keep config output outside the preserved packet directory.")
    caps = ProviderCaps(total_input_tokens=32000, total_output_tokens=8000,
                        total_seconds=60.0, total_cost_usd=0.0,
                        request_input_tokens=16000, request_output_tokens=4000,
                        request_seconds=30.0, request_cost_usd=0.0,
                        max_logical_requests=2, max_retries=0)
    prompts = {arm: sha256(f"fixture-only:{arm}:no-model-output".encode("utf-8"))
               for arm in ("extraction", "single_pass")}
    models = {arm: "fixture-only" for arm in prompts}
    fixtures = {}
    for arm in prompts:
        request = ProviderRequest(arm=arm, packet=packet, input_digest=sha256(canonical_json(packet)),
                                  prompt_digest=prompts[arm], model=models[arm], policy_version=POLICY_VERSION,
                                  caps=caps.model_copy(update={"max_logical_requests": 1}) if arm == "single_pass" else caps)
        _validate_request(request)
        fixtures[arm] = [ProviderFixture(request_digest=request_digest(request), proposals=[],
                                         simulated_usage=SimulatedUsage(input_tokens=None, output_tokens=None,
                                                                        cost_usd=None, elapsed_seconds=None),
                                         error="fixture_not_supplied", retryable=False)]
    result = PairedRunConfig(mode="fake", caps=caps, prompts=prompts, models=models,
                             fixtures=fixtures, replay_files={}, include_full_index=False)
    try:
        with out.open("xb") as stream:
            stream.write(canonical_json(result) + b"\n")
    except FileExistsError as exc:
        raise AuditError("output_exists", "Fake input config requires a fresh file.") from exc
    return result
