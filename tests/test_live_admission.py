"""Future fixture-only live-port probes; no actual owner grant, receipt or HTTP call."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from claim_auditor.contracts import AuditError, BudgetState, canonical_json
from claim_auditor.providers.http_json import StaticJSONTransport
from claim_auditor.providers.live import produce_live

from .provider_support import ledger_for
from .live_support import fixture_json_reply, fixture_live_inputs


class LiveAdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.request, self.prompt, self.adapter, self.authorization, _ = fixture_live_inputs(self.base)

    def reply(self, **changes):
        return fixture_json_reply(self.request, self.authorization, **changes)

    def produce(self, *, authorization=None, request=None, replies=None, ledger=None):
        authorization = self.authorization if authorization is None else authorization
        request = self.request if request is None else request
        return produce_live(
            request, system_prompt=self.prompt, adapter=self.adapter,
            authorization=authorization,
            transport=StaticJSONTransport(authorization_id=authorization.authorization_id,
                                          replies=[self.reply()] if replies is None else replies),
            ledger=ledger_for(self.base / "budget", request) if ledger is None else ledger,
        )

    def test_static_transport_success_is_fixture_not_live_measurement(self):
        """what_bug_this_catches: injected JSON usage being mislabeled as measured live output/cost."""
        response = self.produce()
        self.assertEqual((response.status, response.mode), ("proposed", "fake"))
        self.assertFalse(response.comparative_complete)
        self.assertEqual(response.usage[0].origin, "fixture")
        self.assertEqual(response.usage[0].cost_basis, "fixture")
        self.assertEqual(response.usage[0].reported_bill_usd, 0.1)
        self.assertEqual(response.usage[0].raw_usage, {"prompt_tokens": 10, "completion_tokens": 5})
        self.assertIsNone(response.usage[0].settlement_context)
        self.assertIsNone(response.usage[0].settlement_observation)
        self.assertEqual(response.usage[0].pricing.error, "rate_card_missing")
        self.assertEqual(response.usage[0].cost_usd, 0.1)  # synthetic fixture settlement
        self.assertIsNone(response.attempts[0].input_tokens)
        self.assertIsNone(response.attempts[0].elapsed_seconds)
        self.assertEqual(response.attempts[0].cost_usd, 0.0)  # current external spend

    def test_request_payload_expiry_endpoint_and_scope_mismatches_refuse_before_budget(self):
        """what_bug_this_catches: a grant for different source/request/provider metadata authorizing a call."""
        cases = [
            ({"request_digest": "0" * 64}, "live_admission_identity"),
            ({"payload_digest": "0" * 64}, "live_admission_identity"),
            ({"snapshot_manifest_digest": "0" * 64}, "live_admission_identity"),
            ({"expires_at": "2000-01-01T00:00:00+00:00"}, "live_not_authorized"),
            ({"endpoint": "https://provider.invalid/v1/messages"}, "provider_identity_mismatch"),
            ({"allowed_paths": ["README.md"]}, "live_data_scope_denied"),
        ]
        for changes, reason in cases:
            with self.subTest(changes=changes), self.assertRaises(AuditError) as caught:
                self.produce(authorization=self.authorization.model_copy(update=changes))
            self.assertEqual(caught.exception.reason, reason)
            self.assertFalse((self.base / "budget").exists())

    def test_owner_bound_model_cannot_be_changed_by_consumer(self):
        """what_bug_this_catches: reusing an authorization after swapping the requested model identity."""
        changed = self.request.model_copy(update={"model": "other-fixture-model"})
        with self.assertRaises(AuditError) as caught:
            self.produce(request=changed)
        self.assertEqual(caught.exception.reason, "live_admission_identity")
        self.assertFalse((self.base / "budget").exists())

    def test_missing_tokens_or_cost_blocks_successor_without_silent_zero(self):
        """what_bug_this_catches: unknown provider observations being settled as zero then allowing another call."""
        for number, missing in enumerate(("tokens", "cost")):
            value = json.loads(self.reply().body)
            if missing == "tokens":
                value["usage"].pop("prompt_tokens")
            reply = self.reply(body=canonical_json(value),
                               settled_cost_usd=None if missing == "cost" else 0.1,
                               cost_receipt=None if missing == "cost" else "SYNTHETIC-FIXTURE-NOT-SETTLEMENT")
            ledger_root = self.base / f"unknown-{number}"
            ledger = ledger_for(ledger_root, self.request)
            with self.subTest(missing=missing):
                response = self.produce(replies=[reply, self.reply()], ledger=ledger)
                self.assertEqual(response.status, "incomplete")
                self.assertEqual(response.error, "unsettled_liability")
                self.assertEqual(len(response.attempts), 1)
                observed = response.usage[0].input_tokens if missing == "tokens" else response.usage[0].cost_usd
                self.assertIsNone(observed)
                before = (ledger_root / "budget.json").read_bytes()
                with patch.object(StaticJSONTransport, "post_json") as post:
                    successor = self.produce(ledger=ledger)
                    post.assert_not_called()
                self.assertEqual((successor.status, successor.error), ("incomplete", "unsettled_liability"))
                self.assertEqual(successor.attempts, [])
                self.assertEqual((ledger_root / "budget.json").read_bytes(), before)
                state = BudgetState.model_validate_json(before)
                self.assertTrue(state.unknown_settlement)
                self.assertIsNotNone(state.pending)

    def test_late_reservation_refusal_retains_prior_physical_attempt_and_usage(self):
        """what_bug_this_catches: a retry budget/admission failure discarding an already observed physical attempt."""
        ledger = ledger_for(self.base / "late-budget", self.request)
        reserve = ledger.reserve
        count = 0

        def refuse_retry(*args, **kwargs):
            nonlocal count
            count += 1
            if count > 1:
                raise AuditError("budget_exhausted", "synthetic late reservation refusal", 3)
            return reserve(*args, **kwargs)

        with patch.object(ledger, "reserve", side_effect=refuse_retry):
            response = self.produce(ledger=ledger, replies=[self.reply(status_code=429), self.reply()])
        self.assertEqual((response.status, response.error), ("incomplete", "budget_exhausted"))
        self.assertEqual(len(response.attempts), 1)
        self.assertEqual(response.attempts[0].error, "provider_http_error")
        self.assertEqual(len(response.usage), 1)
        self.assertEqual(response.usage[0].origin, "fixture")
        self.assertEqual(response.usage[0].input_tokens, 10)
        self.assertFalse(response.comparative_complete)

    def test_failed_response_persistence_retains_observations_without_claiming_event(self):
        """what_bug_this_catches: a final event-store failure losing observations or falsely claiming a durable response."""
        root = self.base / "response-store"
        ledger = ledger_for(root, self.request)
        record = ledger.record_event

        def fail_response(value):
            if value["phase"] == "live_source_response":
                raise OSError("synthetic response event store failure")
            return record(value)

        with patch.object(ledger, "record_event", side_effect=fail_response):
            response = self.produce(ledger=ledger)
        self.assertEqual(response.status, "incomplete")
        self.assertIn("response_event_persistence_failed", response.error)
        self.assertEqual(len(response.attempts), 1)
        self.assertEqual(len(response.usage), 1)
        events = [json.loads(line) for line in (root / "attempts.jsonl").read_bytes().splitlines()]
        self.assertEqual(sum(event["phase"] == "closed" for event in events), 1)
        self.assertFalse(any(event["phase"] == "live_source_response" for event in events))

    def test_wrong_endpoint_hidden_attempt_or_oversize_reply_remains_failure(self):
        """what_bug_this_catches: foreign endpoints, hidden retries or oversized bodies becoming a normal proposal."""
        for number, reply in enumerate((self.reply(physical_attempts=2),
                                         self.reply(body=b"x" * 4097),
                                         self.reply(endpoint="https://other.invalid/v1/chat/completions"))):
            with self.subTest(number=number):
                response = self.produce(replies=[reply, self.reply()],
                                        ledger=ledger_for(self.base / f"invalid-{number}", self.request))
                self.assertEqual((response.status, response.error), ("incomplete", "invalid_transport_reply"))
                self.assertEqual(len(response.attempts), 1)
                self.assertEqual(response.proposals, [])

    def test_malformed_duplicate_key_json_preserves_unknown_liability(self):
        """what_bug_this_catches: ambiguous/malformed JSON falling back to success or triggering an unaccounted retry."""
        bodies = [b"not JSON", b'{"model":"fixture-model/1","model":"other"}']
        for number, body in enumerate(bodies):
            with self.subTest(number=number):
                response = self.produce(replies=[self.reply(body=body), self.reply()],
                                        ledger=ledger_for(self.base / f"json-{number}", self.request))
                self.assertEqual((response.status, response.error), ("incomplete", "invalid_provider_output"))
                self.assertEqual(len(response.attempts), 1)
                self.assertEqual(response.proposals, [])

    def test_resolved_model_mismatch_is_not_a_successful_measurement(self):
        """what_bug_this_catches: provider returning another model while the run records the requested identity."""
        value = json.loads(self.reply().body)
        value["model"] = "other-fixture-model"
        response = self.produce(replies=[self.reply(body=canonical_json(value))])
        self.assertEqual((response.status, response.error), ("invalid_output", "provider_model_mismatch"))
        self.assertEqual(len(response.attempts), 1)
        self.assertFalse(response.comparative_complete)

    def test_transport_policy_disallows_hidden_retries_before_reservation(self):
        """what_bug_this_catches: transport capability metadata bypassing the one-physical-attempt contract."""
        for field, value in (("hidden_retries", 1), ("follows_redirects", True), ("authorization_id", "foreign")):
            transport = StaticJSONTransport(authorization_id=self.authorization.authorization_id, replies=[self.reply()])
            setattr(transport, field, value)
            with self.subTest(field=field), self.assertRaises(AuditError) as caught:
                produce_live(self.request, system_prompt=self.prompt, adapter=self.adapter,
                             authorization=self.authorization, transport=transport,
                             ledger=ledger_for(self.base / "budget", self.request))
            self.assertEqual(caught.exception.reason, "invalid_transport_policy")
            self.assertFalse((self.base / "budget").exists())
