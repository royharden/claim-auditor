"""Closed-proof mutation source against INT-published verifier/scorer interfaces."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.contracts import AuditError, canonical_json, sha256
from claim_auditor.evaluation.verify import score_paired, verify_paired
from claim_auditor.evaluation.runner import PAIRED_ARMS, run_paired
from claim_auditor.providers.port import FakeTransport
from claim_auditor.snapshot import read_source

from .provider_support import caps, fixture_for, proposal_for, proposed_atom, request_for
from .support import frozen_source, packet_for


class PairedIntegrityTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.snapshot, self.root = frozen_source(self.base)
        self.raw = read_source(self.snapshot, self.root, "README.md")
        self.packet = packet_for(self.snapshot, self.raw)
        self.out = self.base / "paired"

    def closed_run(self, *, retry=False):
        transports = {}
        atom = proposed_atom(self.snapshot, self.raw)
        for role in ("extraction", "single_pass"):
            request = request_for(self.packet, arm=role,
                                  limits=caps(max_logical_requests=1) if role == "single_pass" else caps())
            proposal = proposal_for(atom, relation="supports" if role == "single_pass" else None)
            success = fixture_for(request, proposals=[proposal])
            fixtures = [fixture_for(request, error="transient_fixture_failure", retryable=True), success] if retry else [success]
            transports[role] = FakeTransport(fixtures)
        result = run_paired(self.packet, self.root, self.out, transports=transports, caps=caps(),
                            prompts={role: "a" * 64 for role in transports},
                            models={role: "fixture-model/1" for role in transports})
        self.assertEqual(result["state"], "closed_source_only")
        # Positive prerequisite: refusal is meaningful only after a real run reopens.
        verified = verify_paired(self.out, self.root)
        self.assertEqual(verified["packet"], self.packet)
        self.assertEqual(verified["manifest_digest"], sha256((self.out / "PAIRED.json").read_bytes()))
        return json.loads((self.out / "PAIRED.json").read_bytes())

    def reseal(self, manifest, *, arm=None):
        # Adversary recomputes local hashes; verifier must still check semantic
        # identities/journals rather than trust an attacker-controlled digest.
        if arm is not None:
            relative = f"{arm}/ARM.json"
            body = canonical_json(manifest["arms"][arm]) + b"\n"
            (self.out / relative).write_bytes(body)
            manifest["artifacts"][relative] = sha256(body)
        (self.out / "PAIRED.json").write_bytes(canonical_json(manifest) + b"\n")

    def assert_integrity_error(self, operation, *reasons):
        with self.assertRaises(AuditError) as caught:
            operation()
        self.assertEqual(caught.exception.exit_code, 4)
        if reasons:
            self.assertIn(caught.exception.reason, reasons)

    def test_successful_reopen_exposes_all_paired_rows_and_attempts(self):
        """what_bug_this_catches: a closed verifier returning only selected arms or hiding attempt observations."""
        self.closed_run()
        verified = verify_paired(self.out, self.root)
        self.assertEqual(set(verified["predictions"]), set(PAIRED_ARMS))
        for arm in ("live_extraction", "live_single_pass"):
            self.assertEqual(len(verified["attempts"][arm]), 1)
            self.assertTrue(verified["predictions"][arm])
        self.assertFalse(verified["manifest"]["comparative_complete"])

    def test_missing_prediction_artifact_cannot_be_a_closed_empty_arm(self):
        """what_bug_this_catches: a missing predictions file being treated as zero extracted atoms."""
        self.closed_run()
        (self.out / "packet_candidate" / "predictions.jsonl").unlink()
        # The published boundary permits ordinary filesystem errors to propagate.
        with self.assertRaises((AuditError, OSError)) as caught:
            verify_paired(self.out, self.root)
        if isinstance(caught.exception, AuditError):
            self.assertEqual(caught.exception.exit_code, 4)

    def test_resealed_omitted_prediction_row_fails_proof_replay(self):
        """what_bug_this_catches: an attacker deleting a row and resealing counts/hashes to hide an omission."""
        # Protect the replay guard even when the altered arm has no successes.
        # This desired-behavior regression remains unexecuted during construction.
        manifest = self.closed_run()
        arm = "packet_candidate"
        artifact = self.out / arm / "predictions.jsonl"
        self.assertTrue(artifact.read_bytes().splitlines())
        artifact.write_bytes(b"")
        manifest["artifacts"][f"{arm}/predictions.jsonl"] = sha256(b"")
        manifest["arms"][arm]["rows"] = 0
        manifest["arms"][arm]["failure_rows"] = 0
        self.reseal(manifest, arm=arm)
        self.assert_integrity_error(lambda: verify_paired(self.out, self.root),
                                    "paired_row_integrity", "paired_proof_mismatch")

    def test_resealed_hidden_attempt_disagrees_with_durable_journal(self):
        """what_bug_this_catches: successful final metadata concealing a failed physical retry."""
        manifest = self.closed_run(retry=True)
        arm = "live_extraction"
        info = manifest["arms"][arm]
        self.assertEqual(len(info["attempts"]), 2)
        info["attempts"] = info["attempts"][-1:]
        info["response"]["attempts"] = info["response"]["attempts"][-1:]
        self.reseal(manifest, arm=arm)
        self.assert_integrity_error(lambda: verify_paired(self.out, self.root), "paired_attempt_integrity")

    def test_external_manifest_pin_is_separate_from_self_consistency(self):
        """what_bug_this_catches: a resealed artifact set silently replacing an externally pinned run."""
        self.closed_run()
        pin = sha256((self.out / "PAIRED.json").read_bytes())
        self.assertEqual(verify_paired(self.out, self.root, manifest_digest=pin)["manifest_digest"], pin)
        self.assert_integrity_error(lambda: verify_paired(self.out, self.root, manifest_digest="0" * 64),
                                    "paired_identity_mismatch", "paired_artifact_integrity")

    def test_score_rejects_corruption_before_opening_gold(self):
        """what_bug_this_catches: scorer reading labels before closed prediction integrity is established."""
        self.closed_run()
        packet = self.out / "packet.json"
        packet.write_bytes(packet.read_bytes() + b" ")
        score_out = self.base / "scores"
        # Missing gold is deliberate: reaching its reader would yield a different error.
        self.assert_integrity_error(
            lambda: score_paired(self.out, self.root, self.base / "GOLD-NOT-PRESENT.jsonl", score_out),
            "paired_artifact_integrity",
        )
        self.assertFalse(score_out.exists())
