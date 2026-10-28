"""Explicit fake-only future live-port inputs; never a real grant or receipt."""

from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

from claim_auditor.contracts import EvaluationLock, LiveAuthorization, canonical_json, sha256
from claim_auditor.providers.http_json import JSONReply, StaticJSONTransport
from claim_auditor.providers.live import OpenAICompatibleAdapter
from claim_auditor.providers.port import request_digest
from claim_auditor.snapshot import read_source

from .provider_support import request_for
from .support import frozen_source, packet_for


def fixture_live_inputs(base):
    snapshot, root = frozen_source(base)
    prompt = "Synthetic offline regression input. Return bounded JSON."
    request = request_for(packet_for(snapshot, read_source(snapshot, root, "README.md")))
    request = request.model_copy(update={"prompt_digest": sha256(prompt.encode())})
    adapter = OpenAICompatibleAdapter()
    payload = adapter.build_request(request, prompt, None)
    grant = LiveAuthorization(
        enabled=True, authorization_id="SYNTHETIC-TEST-NOT-OWNER-GRANT",
        authorized_by="SYNTHETIC-TEST-NO-REAL-OWNER",
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        provider="openai_compatible", endpoint="https://provider.invalid/v1/chat/completions",
        request_digest=request_digest(request), payload_digest=sha256(payload),
        snapshot_manifest_digest=snapshot.manifest_digest,
        allowed_paths=[entry.path for entry in snapshot.entries], input_token_upper_bound=20,
        tokenizer_receipt="SYNTHETIC-TEST-NOT-TOKENIZER-EVIDENCE",
        worst_case_cost_receipt="SYNTHETIC-TEST-NOT-A-COST-RECEIPT",
        max_request_bytes=65536, max_response_bytes=4096, anthropic_version=None,
    )
    return request, prompt, adapter, grant, root


def fixture_json_reply(request, grant, **changes):
    value = dict(model=request.model, id="fixture-response",
                 usage={"prompt_tokens": 10, "completion_tokens": 5},
                 choices=[{"finish_reason": "stop", "message": {"content": json.dumps({"atoms": []})}}])
    fields = dict(endpoint=grant.endpoint, status_code=200, body=canonical_json(value),
                  elapsed_seconds=1.0, physical_attempts=1, settled_cost_usd=0.1,
                  cost_receipt="SYNTHETIC-FIXTURE-NOT-SETTLEMENT")
    fields.update(changes)
    return JSONReply(**fields)


def runner_boundary_inputs(base, request, prompt, adapter, grant):
    """Future runner unit inputs; explicitly unadmitted/injected preparation.

    Only the role-history check and canonical failure writer are under test.
    No fixture pretends that LOCK/rights/custody or real inference was admitted.
    """
    packet, caps = request.packet, request.caps
    roles = ("extraction", "single_pass")
    arms = ["product_full_index", "packet_candidate", "packet_grep", "live_extraction", "live_single_pass"]
    lock = EvaluationLock(
        protocol_id="SYNTHETIC-UNADMITTED", admitted=False, admitted_by=None, admitted_at=None,
        code_digest="0" * 64, taxonomy_version="declared-static/1", matcher_version="unused",
        packet_version=packet.packet_version, arm_names=arms,
        provider_models={arm: request.model for arm in ("live_extraction", "live_single_pass")},
        source_seal_digest=packet.snapshot_manifest_digest, gold_seal_digest="0" * 64,
        source_rights_receipt="NOT-A-RECEIPT", custody_receipt="NOT-A-RECEIPT", heldout_accessed=False,
        max_input_tokens=caps.total_input_tokens, max_output_tokens=caps.total_output_tokens,
        max_remote_seconds=int(caps.total_seconds), max_cost_usd=caps.total_cost_usd,
    )
    protocol = base / "SYNTHETIC-UNADMITTED.json"
    raw = canonical_json(lock)
    protocol.write_bytes(raw)
    pin = sha256(raw)
    durable = base / "durable"
    leaf = durable / pin / packet.packet_digest / "extraction"

    def prepare_fixture(protocol_path, snapshot_root, out):
        out.mkdir(parents=True)
        (out / "packet.json").write_bytes(canonical_json(packet))

    arguments = dict(protocol_digest=pin, caps=caps, system_prompts={role: prompt for role in roles},
                     models={role: request.model for role in roles},
                     authorizations={role: grant for role in roles},
                     transports={role: StaticJSONTransport(authorization_id=grant.authorization_id, replies=[]) for role in roles},
                     adapters={role: adapter for role in roles}, ledger_root=durable)
    return SimpleNamespace(protocol=protocol, leaf=leaf, arms=arms, prepare=prepare_fixture, arguments=arguments)
