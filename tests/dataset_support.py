"""Future real fake/replay closure fixtures, with synthetic agent label INPUTS.

Nothing runs at import. Paired/full-index artifacts come from the actual producer
and verifier at later activation; no passing report or score is handwritten.
"""

from pathlib import Path

from claim_auditor.contracts import DatasetCase, DatasetManifest, POLICY_VERSION, canonical_json, sha256
from claim_auditor.evaluation.packet import PACKET_VERSION, code_digest
from claim_auditor.evaluation.packet_facts import PACKET_FACT_VERSION
from claim_auditor.evaluation.runner import PAIRED_ARMS, RUNNER_VERSION, run_paired
from claim_auditor.evaluation.scoring import MATCHER_VERSION
from claim_auditor.evaluation.verify import verify_paired
from claim_auditor.index import PARSER_VERSION
from claim_auditor.providers.port import FakeTransport

from .provider_support import caps, fixture_for, proposal_for, proposed_atom, request_for
from .support import frozen_source, gold, packet_for


class DatasetFixture:
    def __init__(self, base: Path, *, fail_first_extraction=False):
        self.base = base
        self.sources, self.runs, self.gold_paths = [], [], []
        cases, label_inputs = [], []
        for number in range(2):
            case_base = base / f"case-{number}"
            case_base.mkdir()
            raw = b"The function `work` is declared.\n"
            snapshot, source = frozen_source(case_base, readme=raw,
                                              code=f"def work():\n    return {number}\n".encode())
            packet = packet_for(snapshot, raw)
            atom = proposed_atom(snapshot, raw)
            transports = {}
            for role in ("extraction", "single_pass"):
                request = request_for(packet, arm=role,
                                      limits=caps(max_logical_requests=1) if role == "single_pass" else caps())
                proposal = proposal_for(atom, relation="supports" if role == "single_pass" else None)
                fixture = fixture_for(request, proposals=[proposal])
                if fail_first_extraction and number == 0 and role == "extraction":
                    fixture = fixture.model_copy(update={"request_digest": "0" * 64})
                transports[role] = FakeTransport([fixture])
            run = case_base / "paired"
            produced = run_paired(packet, source, run, transports=transports, caps=caps(),
                                  prompts={role: "a" * 64 for role in transports},
                                  models={role: "fixture-model/1" for role in transports}, include_full_index=True)
            if produced["state"] != "closed_source_only":
                raise RuntimeError("Fixture activation failed to produce a real closed source run")
            verified = verify_paired(run, source)
            if set(verified["predictions"]) != {*PAIRED_ARMS, "product_full_index"}:
                raise RuntimeError("Fixture requires all real verified arms, including separate full-index utility")
            family = f"dev:family-{number}"
            row = gold(atom, "verified", identifier=f"gold:{number}").model_copy(update={"family_id": family})
            label_raw = canonical_json(row) + b"\n"  # Explicit agent control; not human gold or a measured result.
            label_path = base / f"synthetic-agent-labels-{number}.jsonl"
            cases.append(DatasetCase(
                case_id=f"case:{number}", family_id=family, ancestry_id=f"ancestry:{number}",
                snapshot_root=str(source), snapshot_id=snapshot.snapshot_id,
                snapshot_manifest_digest=snapshot.manifest_digest, source_content_digest=snapshot.content_digest,
                run_root=str(run), run_manifest_digest=verified["manifest_digest"],
                gold_path=str(label_path), gold_digest=sha256(label_raw), protocol_digest=None,
                source_rights_receipt=None, custody_receipt=None,
            ))
            self.sources.append(source)
            self.runs.append(run)
            self.gold_paths.append(label_path)
            label_inputs.append(label_raw)
        # No labels are available even to fixture closure construction before all
        # real future inference outputs have closed. No actual operation occurs now.
        for path, raw in zip(self.gold_paths, label_inputs):
            path.write_bytes(raw)
        self.manifest = DatasetManifest(
            dataset_id="synthetic-DEV-dataset", mode="dev_descriptive", admitted=False,
            admitted_by=None, admitted_at=None, protocol_id="dev:synthetic-protocol",
            taxonomy_version=POLICY_VERSION, matcher_version=MATCHER_VERSION,
            packet_version=PACKET_VERSION, runner_version=RUNNER_VERSION,
            packet_fact_version=PACKET_FACT_VERSION, parser_version=PARSER_VERSION,
            code_digest=code_digest(), required_arms=[*PAIRED_ARMS, "product_full_index"],
            provider_models={arm: "fixture-model/1" for arm in ("live_extraction", "live_single_pass")},
            prompt_digests={arm: "a" * 64 for arm in ("live_extraction", "live_single_pass")},
            caps=caps(), human_review_receipt=None, cases=cases,
        )
        self.path = base / "dataset.json"
        self.pin = self.write_manifest()

    def write_manifest(self, *, cases=None, **changes):
        fields = dict(changes)
        if cases is not None:
            fields["cases"] = cases
        manifest = self.manifest.model_copy(update=fields)
        raw = canonical_json(manifest) + b"\n"
        self.path.write_bytes(raw)
        return sha256(raw)

    def reseal_run(self, number, manifest, *, arm=None):
        # Adversarial mutation of actual future outputs, not a test-side verifier.
        root = self.runs[number]
        if arm is not None:
            relative = f"{arm}/ARM.json"
            body = canonical_json(manifest["arms"][arm]) + b"\n"
            (root / relative).write_bytes(body)
            manifest["artifacts"][relative] = sha256(body)
        raw = canonical_json(manifest) + b"\n"
        (root / "PAIRED.json").write_bytes(raw)
        cases = list(self.manifest.cases)
        cases[number] = cases[number].model_copy(update={"run_manifest_digest": sha256(raw)})
        return self.write_manifest(cases=cases)
