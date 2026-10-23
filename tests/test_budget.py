"""Durable budget behavior, with local synthetic liability only when activated later."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from claim_auditor.accounting import BudgetLedger
from claim_auditor.contracts import AuditError, BudgetState


def limits():
    return BudgetState(remaining_input_tokens=100, remaining_output_tokens=50,
                       remaining_cost_usd=1.0, remaining_seconds=10.0,
                       pending=None, unknown_settlement=False)


class BudgetTests(unittest.TestCase):
    def test_unknown_usage_blocks_following_request_after_reopen(self):
        """what_bug_this_catches: restarting a ledger converting unknown usage into free budget."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            ledger = BudgetLedger(root, limits())
            reservation = ledger.reserve(40, 20, 0.4, 4.0)
            state = ledger.settle(reservation.reservation_id, input_tokens=None, output_tokens=1,
                                  cost_usd=None, elapsed_seconds=1.0)
            self.assertTrue(state.unknown_settlement)
            self.assertIsNotNone(state.pending)
            with self.assertRaises(AuditError) as caught:
                BudgetLedger(root, limits()).reserve(1, 1, 0.01, 1.0)
            self.assertEqual(caught.exception.reason, "unsettled_liability")

    def test_pending_liability_cannot_be_double_reserved(self):
        """what_bug_this_catches: retries reserving against budget already in flight."""
        with TemporaryDirectory() as directory:
            ledger = BudgetLedger(Path(directory), limits())
            ledger.reserve(40, 20, 0.4, 4.0)
            with self.assertRaises(AuditError) as caught:
                ledger.reserve(1, 1, 0.01, 1.0)
            self.assertEqual(caught.exception.reason, "unsettled_liability")

    def test_settlement_debits_and_enforces_shared_remainder(self):
        """what_bug_this_catches: a second request receiving the original total ceiling."""
        with TemporaryDirectory() as directory:
            ledger = BudgetLedger(Path(directory), limits())
            reservation = ledger.reserve(60, 30, 0.6, 6.0)
            state = ledger.settle(reservation.reservation_id, input_tokens=60, output_tokens=30,
                                  cost_usd=0.6, elapsed_seconds=6.0)
            self.assertEqual(state.remaining_input_tokens, 40)
            self.assertIsNone(state.pending)
            with self.assertRaises(AuditError) as caught:
                ledger.reserve(41, 1, 0.01, 1.0)
            self.assertEqual(caught.exception.reason, "budget_exhausted")

    def test_overrun_remains_unsettled_and_foreign_settlement_is_refused(self):
        """what_bug_this_catches: overruns clearing liability or another attempt settling it."""
        with TemporaryDirectory() as directory:
            ledger = BudgetLedger(Path(directory), limits())
            reservation = ledger.reserve(40, 20, 0.4, 4.0)
            with self.assertRaises(AuditError) as caught:
                ledger.settle("foreign", input_tokens=1, output_tokens=1, cost_usd=0.1, elapsed_seconds=1.0)
            self.assertEqual(caught.exception.reason, "reservation_mismatch")
            with self.assertRaises(AuditError) as caught:
                ledger.settle(reservation.reservation_id, input_tokens=41, output_tokens=1,
                              cost_usd=0.1, elapsed_seconds=1.0)
            self.assertEqual(caught.exception.reason, "reservation_overrun")
            with self.assertRaises(AuditError) as caught:
                ledger.reserve(1, 1, 0.01, 1.0)
            self.assertEqual(caught.exception.reason, "unsettled_liability")
