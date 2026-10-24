"""Future producer/transport boundary controls; no real authorization, credentials or calls."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock, patch

from claim_auditor.contracts import AuditError, BudgetState
from claim_auditor.providers.http_json import HTTPJSONTransport, StaticJSONTransport
from claim_auditor.providers.live import produce_live

from .live_support import fixture_json_reply, fixture_live_inputs
from .provider_support import ledger_for


class LiveProducerBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.request, self.prompt, self.adapter, self.grant, _ = fixture_live_inputs(self.base)

    def test_self_declared_live_transport_is_refused_before_any_reservation(self):
        """what_bug_this_catches: a stub labelled execution_kind="live" producing output recorded as live evidence."""
        grant = self.grant

        class SelfDeclaredLive:
            execution_kind = "live"
            hidden_retries = 0
            follows_redirects = False
            authorization_id = grant.authorization_id
            ledger_root = None
            budget_admission = None

            def post_json(self, **kwargs):
                raise AssertionError("An unpublished transport must never be called")

        class FixtureSubclass(StaticJSONTransport):
            execution_kind = "live"

        transports = [SelfDeclaredLive(),
                      FixtureSubclass(authorization_id=grant.authorization_id,
                                      replies=[fixture_json_reply(self.request, grant)])]
        for transport in transports:
            budget = self.base / f"budget-{type(transport).__name__}"
            with self.subTest(transport=type(transport).__name__):
                with self.assertRaises(AuditError) as caught:
                    produce_live(self.request, system_prompt=self.prompt, adapter=self.adapter,
                                 authorization=grant, transport=transport, ledger=ledger_for(budget, self.request))
                self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("invalid_transport_policy", 2))
                self.assertFalse(budget.exists())

    def test_unexpected_transport_exception_still_settles_unknown_and_closes(self):
        """what_bug_this_catches: an uncaught transport error skipping settlement, the closed event and the typed response."""
        root = self.base / "budget"
        transport = StaticJSONTransport(authorization_id=self.grant.authorization_id,
                                        replies=[fixture_json_reply(self.request, self.grant)])
        with patch.object(StaticJSONTransport, "post_json", side_effect=KeyError("synthetic-unexpected")):
            response = produce_live(self.request, system_prompt=self.prompt, adapter=self.adapter,
                                    authorization=self.grant, transport=transport,
                                    ledger=ledger_for(root, self.request))
        self.assertEqual((response.status, response.error, response.mode),
                         ("incomplete", "provider_transport_failure", "fake"))
        self.assertEqual(len(response.attempts), 1)
        self.assertEqual((response.attempts[0].status, response.attempts[0].error),
                         ("incomplete", "provider_transport_failure"))
        self.assertEqual(response.usage, [])
        state = BudgetState.model_validate_json((root / "budget.json").read_bytes())
        self.assertTrue(state.unknown_settlement)
        self.assertIsNotNone(state.pending)  # Liability stays recorded; nothing is released.
        events = [json.loads(line) for line in (root / "attempts.jsonl").read_bytes().splitlines()]
        closed = [event for event in events if event["phase"] == "closed"]
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0]["attempt"]["error"], "provider_transport_failure")
        self.assertIsNone(closed[0]["usage"])
        with self.assertRaises(AuditError) as caught:
            ledger_for(root, self.request).reserve(1, 1, 0.01, 1.0)
        self.assertEqual(caught.exception.reason, "unsettled_liability")

    def test_malformed_worker_metadata_is_a_typed_transport_reply_failure(self):
        """what_bug_this_catches: non-object or invalid-code worker metadata escaping as a raw Python error."""
        credential = "SYNTHETIC-NOT-A-CREDENTIAL"
        transport = HTTPJSONTransport(authorization=self.grant, owner_activation=True,
                                      allowed_endpoints=(self.grant.endpoint,),
                                      credential_headers={"authorization": credential})
        body = self.adapter.build_request(self.request, self.prompt, None)
        for envelope in (b"[]\n", b'{"error":5}\n', b'{"error":"Not A Code"}\n', b"not-json\n"):
            receive = MagicMock()
            receive.poll.return_value = True
            receive.recv_bytes.return_value = envelope
            context = MagicMock()
            context.Pipe.return_value = (receive, MagicMock())
            context.Process.return_value.pid = None  # No real worker is created or terminated.
            with self.subTest(envelope=envelope), patch("multiprocessing.get_context", return_value=context), \
                    patch("http.client.HTTPSConnection") as https:
                with self.assertRaises(AuditError) as caught:
                    transport.post_json(endpoint=self.grant.endpoint, body=body, headers={},
                                        timeout_seconds=1.0, max_response_bytes=self.grant.max_response_bytes)
                self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("invalid_transport_reply", 2))
                self.assertNotIn(credential, str(caught.exception))
                https.assert_not_called()
