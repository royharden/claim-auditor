"""Future admitted-owner entry controls; no actual receipts, authority or operations."""

from datetime import datetime, timezone
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from claim_auditor.accounting import BudgetLedger, budget_admission_id, ledger_root_identity
from claim_auditor.cli import main
from claim_auditor.contracts import (
    AuditError, BudgetState, LiveBudgetAdmission, LiveExperimentConfig, LiveUsage,
    ReservationReconciliation, canonical_json, sha256,
)
from claim_auditor.providers.experiment import LiveOwnerContext, reconcile_configured_budget

from .live_support import fixture_live_inputs
from .pricing_support import synthetic_card


class OwnerReconciliationTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    def inputs(self):
        request, prompt, _, grant, _ = fixture_live_inputs(self.base)
        # Expiry controls future dispatch; it must not erase liability or prevent
        # explicit settlement of an old request. These remain synthetic inputs.
        grant = grant.model_copy(update={"expires_at": "2000-01-01T00:00:00+00:00"})
        roles = ("extraction", "single_pass")
        config = LiveExperimentConfig(
            caps=request.caps, system_prompts={role: prompt for role in roles},
            models={role: request.model for role in roles},
            authorizations={role: grant.model_copy(update={"authorization_id": f"SYNTHETIC-{role}"}) for role in roles},
            allowed_endpoints={role: [grant.endpoint] for role in roles},
            rate_cards={role: synthetic_card() for role in roles},
        )
        root = self.base / "durable"
        admission = LiveBudgetAdmission(
            admission_id="pending", owner_id="SYNTHETIC-OWNER",
            admitted_at="2020-01-01T00:00:00+00:00", protocol_digest="a" * 64,
            packet_digest=request.packet.packet_digest, ledger_root_identity=ledger_root_identity(root),
            caps_digest=sha256(canonical_json(config.caps)),
            authorization_ids={role: config.authorizations[role].authorization_id for role in roles},
            liability_scope="per_role_equal_caps", receipt_reference="SYNTHETIC-NOT-REAL-ADMISSION",
        )
        admission = admission.model_copy(update={"admission_id": budget_admission_id(admission)})
        usage = LiveUsage(
            origin="fixture", resolved_model=request.model, response_id="SYNTHETIC-RESPONSE",
            input_tokens=10, output_tokens=5, cost_usd=0.1, cost_receipt="SYNTHETIC-NOT-BILL",
            elapsed_seconds=1.0, raw_usage={"prompt_tokens": 10, "completion_tokens": 5},
            cost_basis="fixture", reported_bill_usd=0.1, pricing=None,
            settlement_context=None, settlement_observation=None, cost_error=None,
        )
        # Whitespace deliberately survives entrypoint forwarding. The canonical
        # ledger remains responsible for semantic receipt checks and settlement.
        usage_bytes = b" \n" + canonical_json(usage) + b"\n"
        price_bytes = b' { "fixture_only" : true } \n'
        record = ReservationReconciliation(
            reconciliation_id="SYNTHETIC-RECONCILIATION", reservation_id="SYNTHETIC-PENDING",
            budget_state_digest="b" * 64, usage=usage,
            usage_receipt="SYNTHETIC-USAGE", pricing_receipt="SYNTHETIC-PRICE",
            usage_receipt_digest=sha256(usage_bytes), pricing_receipt_digest=sha256(price_bytes),
            owner_id=admission.owner_id, recorded_at=datetime.now(timezone.utc).isoformat(),
            rationale="Synthetic adapter forwarding probe; never an actual owner action.",
        )
        context = LiveOwnerContext(credential_headers={}, activated=True, ledger_root=root, budget_admission=admission)
        initial = BudgetState(remaining_input_tokens=config.caps.total_input_tokens,
                              remaining_output_tokens=config.caps.total_output_tokens,
                              remaining_cost_usd=config.caps.total_cost_usd,
                              remaining_seconds=config.caps.total_seconds, pending=None, unknown_settlement=False)
        return SimpleNamespace(root=root, config=config, admission=admission, context=context,
                               record=record, usage_bytes=usage_bytes, price_bytes=price_bytes, initial=initial)

    def test_absent_or_inactive_owner_context_refuses_before_reads_and_ledger_or_transport(self):
        """what_bug_this_catches: plain callers reading receipts or selecting a leaf before trusted activation."""
        with patch("claim_auditor.snapshot.safeio.read_ordinary") as read, \
                patch("claim_auditor.accounting.BudgetLedger") as ledger, \
                patch("claim_auditor.providers.experiment.HTTPJSONTransport") as transport:
            for context in (None, LiveOwnerContext(credential_headers={})):
                with self.subTest(context=context), self.assertRaises(AuditError) as caught:
                    reconcile_configured_budget(owner_context=context, config=None, role="extraction",
                                                record=None, usage_receipt_data=None, pricing_receipt_data=None)
                self.assertEqual(caught.exception.reason, "live_not_authorized")
            read.assert_not_called()
            ledger.assert_not_called()
            transport.assert_not_called()

    def test_plain_reconcile_cli_refuses_before_opening_named_config_and_receipt_paths(self):
        """what_bug_this_catches: default CLI access to arbitrary files before trusted owner context exists."""
        stderr = io.StringIO()
        with patch("claim_auditor.snapshot.safeio.read_ordinary") as read, \
                patch("claim_auditor.providers.experiment.reconcile_configured_budget") as reconcile, \
                redirect_stderr(stderr):
            status = main(["budget-reconcile", "--record", str(self.base / "never-read-record.json"),
                           "--config", str(self.base / "never-read-config.json"), "--role", "extraction",
                           "--usage-receipt", str(self.base / "never-read-usage.json"),
                           "--pricing-receipt", str(self.base / "never-read-pricing.json")])
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(stderr.getvalue())["error"], "live_not_authorized")
        read.assert_not_called()
        reconcile.assert_not_called()

    def test_admitted_role_derives_sole_leaf_and_forwards_same_receipt_bytes_to_transition(self):
        """what_bug_this_catches: caller-selected leaves, altered receipt bytes or dropped expected-role binding."""
        inputs = self.inputs()
        with patch("claim_auditor.snapshot.safeio.read_ordinary", return_value=canonical_json(inputs.admission)), \
                patch("claim_auditor.providers.experiment.bind_budget_admission") as bind, \
                patch.object(BudgetLedger, "reconcile", autospec=True, return_value=inputs.initial) as reconcile, \
                patch("claim_auditor.providers.experiment.HTTPJSONTransport") as transport:
            result = reconcile_configured_budget(
                owner_context=inputs.context, config=inputs.config, role="single_pass", record=inputs.record,
                usage_receipt_data=inputs.usage_bytes, pricing_receipt_data=inputs.price_bytes,
            )
        self.assertIs(result, inputs.initial)
        self.assertEqual(reconcile.call_count, 1)
        ledger = reconcile.call_args.args[0]
        self.assertEqual(ledger.root, inputs.root / inputs.admission.protocol_digest / inputs.admission.packet_digest / "single_pass")
        self.assertEqual(reconcile.call_args.args[1], inputs.record)
        self.assertIs(reconcile.call_args.kwargs["usage_receipt_data"], inputs.usage_bytes)
        self.assertIs(reconcile.call_args.kwargs["pricing_receipt_data"], inputs.price_bytes)
        self.assertEqual(reconcile.call_args.kwargs["expected_admission"], inputs.admission)
        self.assertEqual(reconcile.call_args.kwargs["expected_role"], "single_pass")
        self.assertEqual(reconcile.call_args.kwargs["rate_card"], inputs.config.rate_cards["single_pass"])
        self.assertEqual(bind.call_args.kwargs["packet_digest"], inputs.admission.packet_digest)
        transport.assert_not_called()
        self.assertFalse(inputs.root.exists())  # Entry unit used no real ledger operations.

    def test_foreign_stored_admission_or_invalid_role_never_reaches_transition(self):
        """what_bug_this_catches: a trusted caller settling a record under another stored owner admission or role."""
        inputs = self.inputs()
        foreign = inputs.admission.model_copy(update={"owner_id": "OTHER-SYNTHETIC-OWNER"})
        foreign = foreign.model_copy(update={"admission_id": budget_admission_id(foreign)})
        with patch("claim_auditor.snapshot.safeio.read_ordinary", return_value=canonical_json(foreign)) as read, \
                patch("claim_auditor.providers.experiment.bind_budget_admission") as bind, \
                patch.object(BudgetLedger, "reconcile") as reconcile:
            with self.assertRaises(AuditError) as caught:
                reconcile_configured_budget(owner_context=inputs.context, config=inputs.config, role="extraction",
                                            record=inputs.record, usage_receipt_data=inputs.usage_bytes,
                                            pricing_receipt_data=inputs.price_bytes)
            self.assertEqual(caught.exception.reason, "reconciliation_owner_mismatch")
            read.reset_mock()
            with self.assertRaises(AuditError) as caught:
                reconcile_configured_budget(owner_context=inputs.context, config=inputs.config, role="product_full_index",
                                            record=inputs.record, usage_receipt_data=inputs.usage_bytes,
                                            pricing_receipt_data=inputs.price_bytes)
            self.assertEqual(caught.exception.reason, "invalid_reconciliation_role")
            read.assert_not_called()
            bind.assert_not_called()
            reconcile.assert_not_called()

    def test_ledger_rejects_wrong_protocol_leaf_and_cross_role_before_read_or_lock(self):
        """what_bug_this_catches: replacing a selected admitted role leaf with another otherwise valid budget path."""
        inputs = self.inputs()
        wrong = [inputs.root / ("c" * 64) / inputs.admission.packet_digest / "extraction",
                 inputs.root / inputs.admission.protocol_digest / inputs.admission.packet_digest / "single_pass"]
        with patch("claim_auditor.snapshot.safeio.read_ordinary") as read, \
                patch.object(BudgetLedger, "_locked") as lock:
            for leaf in wrong:
                with self.subTest(leaf=leaf), self.assertRaises(AuditError) as caught:
                    BudgetLedger(leaf, inputs.initial).reconcile(
                        inputs.record, expected_admission=inputs.admission, expected_role="extraction",
                        usage_receipt_data=inputs.usage_bytes, pricing_receipt_data=inputs.price_bytes,
                    )
                self.assertEqual(caught.exception.reason, "reconciliation_scope_mismatch")
            read.assert_not_called()
            lock.assert_not_called()
