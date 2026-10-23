"""DEV-only packet preparation cannot manufacture a locked/admitted experiment."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.contracts import AuditError, canonical_json, sha256
from claim_auditor.evaluation.packet import prepare_dev_packet, prepare_evaluation

from .support import frozen_source


class DevPacketTests(unittest.TestCase):
    def test_dev_preparation_has_no_lock_receipts_inference_or_admission(self):
        """what_bug_this_catches: keyless DEV preparation being presented as an admitted experiment or measured run."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            snapshot, root = frozen_source(base)
            out = base / "dev-packet"
            packet = prepare_dev_packet(root, out)
            metadata = json.loads((out / "DEV.json").read_bytes())
            self.assertEqual({path.name for path in out.iterdir()}, {"packet.json", "DEV.json"})
            self.assertEqual(metadata["designation"], "DEV_ONLY")
            self.assertEqual(metadata["status"], "prepared_only")
            self.assertTrue(metadata["source_only"])
            for field in ("admitted", "human_adjudicated", "comparative_complete", "heldout"):
                self.assertFalse(metadata[field])
            self.assertTrue(all(status == "not_run" for status in metadata["arm_status"].values()))
            self.assertEqual(metadata["input_digest"], sha256(canonical_json(packet)))
            self.assertEqual(metadata["source_manifest_digest"], snapshot.manifest_digest)
            self.assertFalse(packet.absence_certificates)

    def test_dev_metadata_cannot_be_reused_as_an_admitted_lock(self):
        """what_bug_this_catches: treating DEV.json as a substitute for required locked rights/custody admission."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            _, root = frozen_source(base)
            prepared = base / "dev"
            prepare_dev_packet(root, prepared)
            out = base / "forbidden-locked-preparation"
            with self.assertRaises(AuditError) as caught:
                prepare_evaluation(prepared / "DEV.json", root, out)
            self.assertEqual(caught.exception.reason, "invalid_evaluation_lock")
            self.assertFalse(out.exists())
