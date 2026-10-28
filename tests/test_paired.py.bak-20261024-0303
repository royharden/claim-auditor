"""Future equal-packet orchestration controls; no benchmark or live execution."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.contracts import AuditError, PredictionRow, canonical_json, sha256
from claim_auditor.evaluation.runner import PAIRED_ARMS, run_paired
from claim_auditor.providers.port import FakeTransport
from claim_auditor.snapshot import read_source

from .provider_support import caps, fixture_for, proposal_for, proposed_atom, request_for
from .support import frozen_source, packet_for


class PairedTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.snapshot, self.root = frozen_source(self.base)
        self.raw = read_source(self.snapshot, self.root, "README.md")
        self.packet = packet_for(self.snapshot, self.raw)
        self.out = self.base / "paired"
        self.prompts = {"extraction": "a" * 64, "single_pass": "a" * 64}
        self.models = {"extraction": "fixture-model/1", "single_pass": "fixture-model/1"}

    def transports(self, *, retry=False, invalid=False):
        result = {}
        atom = proposed_atom(self.snapshot, self.raw)
        for role in ("extraction", "single_pass"):
            request = request_for(self.packet, arm=role,
                                  limits=caps(max_logical_requests=1) if role == "single_pass" else caps())
            proposal = proposal_for(atom, relation="supports" if role == "single_pass" else None)
            fixture = fixture_for(request, proposals=[proposal])
            if invalid and role == "extraction":
                fixture = fixture.model_copy(update={"request_digest": "0" * 64})
            fixtures = [fixture_for(request, error="transient_fixture_failure", retryable=True), fixture] if retry else [fixture]
            result[role] = FakeTransport(fixtures)
        return result

    def run_source(self, **changes):
        fields = dict(transports=self.transports(), caps=caps(), prompts=self.prompts, models=self.models)
        fields.update(changes)
        return run_paired(self.packet, self.root, self.out, **fields)

    def rows(self, arm):
        return [PredictionRow.model_validate_json(line)
                for line in (self.out / arm / "predictions.jsonl").read_bytes().splitlines()]

    def test_closed_source_uses_same_packet_and_never_claims_measured_live_success(self):
        """what_bug_this_catches: paired arms receiving different evidence or fake output labeled live acceptance."""
        result = self.run_source()
        self.assertEqual(result["state"], "closed_source_only")
        self.assertFalse(result["comparative_complete"])
        self.assertFalse(result["human_adjudicated"])
        self.assertEqual(set(result["arms"]), set(PAIRED_ARMS))
        digest = sha256(canonical_json(self.packet))
        for arm in PAIRED_ARMS:
            self.assertEqual(result["arms"][arm]["input_digest"], digest)
            self.assertEqual(result["arms"][arm]["packet_digest"], self.packet.packet_digest)
            self.assertEqual(result["arms"][arm]["treatment"], "equal_packet")
        for arm in ("live_extraction", "live_single_pass"):
            info = result["arms"][arm]
            self.assertEqual(sha256(canonical_json(info["request"]["packet"])), digest)
            self.assertEqual(len(info["attempts"]), 1)
            self.assertFalse(info["response"]["comparative_complete"])
            self.assertNotIn("admitted_candidates", info["request"])
        self.assertEqual((self.out / "packet.json").read_bytes(), canonical_json(self.packet) + b"\n")
        for relative, expected in result["artifacts"].items():
            self.assertEqual(sha256((self.out / relative).read_bytes()), expected)

    def test_failed_physical_retry_remains_a_row_after_success(self):
        """what_bug_this_catches: a successful retry hiding a failed attempt from arm denominators."""
        result = self.run_source(transports=self.transports(retry=True))
        for arm in ("live_extraction", "live_single_pass"):
            self.assertEqual(len(result["arms"][arm]["attempts"]), 2)
            rows = self.rows(arm)
            self.assertTrue(any(row.status == "execution_failure" for row in rows))
            self.assertTrue(any(row.status == "prediction" for row in rows))
            self.assertGreaterEqual(result["arms"][arm]["failure_rows"], 1)

    def test_invalid_provider_output_is_not_an_empty_clean_arm(self):
        """what_bug_this_catches: invalid proposals disappearing as zero-prediction success."""
        result = self.run_source(transports=self.transports(invalid=True))
        rows = self.rows("live_extraction")
        self.assertEqual(result["arms"]["live_extraction"]["status"], "invalid_output")
        self.assertTrue(rows)
        self.assertTrue(all(row.status != "prediction" for row in rows))
        self.assertFalse(result["comparative_complete"])

    def test_existing_output_is_preserved_instead_of_overwritten(self):
        """what_bug_this_catches: paired reruns overwriting earlier closed or incomplete artifacts."""
        self.out.mkdir()
        sentinel = self.out / "sentinel.txt"
        sentinel.write_bytes(b"preserve")
        with self.assertRaises(AuditError) as caught:
            self.run_source()
        self.assertEqual(caught.exception.reason, "output_exists")
        self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_bad_packet_retains_failure_rows_for_every_arm(self):
        """what_bug_this_catches: invalid input eliminating required experiment arms and denominators."""
        self.packet = self.packet.model_copy(update={"packet_digest": "0" * 64})
        result = self.run_source()
        self.assertEqual(result["state"], "failed_input")
        self.assertEqual(set(result["arms"]), set(PAIRED_ARMS))
        for arm in PAIRED_ARMS:
            rows = self.rows(arm)
            self.assertTrue(rows)
            self.assertTrue(all(row.status != "prediction" for row in rows))
        self.assertEqual(json.loads((self.out / "PAIRED.json").read_bytes())["state"], "failed_input")
