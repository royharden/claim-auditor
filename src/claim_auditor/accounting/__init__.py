"""Bounded durable reservation source, with no network or credential access."""

from __future__ import annotations

import math
import os
import time
import uuid
from pathlib import Path

from ..contracts import AuditError, BudgetState, ProviderCaps, Reservation, canonical_json, sha256


class BudgetLedger:
    """Single active writer enforced by exclusive lock; unknown usage blocks calls."""

    def __init__(self, root: Path, limits: BudgetState) -> None:
        self.root = root
        self.initial = limits

    def _locked(self) -> int:
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            return os.open(self.root / "write.lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise AuditError("budget_writer_busy", "Reservation lock exists; reconcile owner, never delete by age.", 3) from exc

    def _read(self) -> BudgetState:
        path = self.root / "budget.json"
        return BudgetState.model_validate_json(path.read_bytes()) if path.exists() else self.initial

    def _save(self, state: BudgetState) -> None:
        temp = self.root / f".budget-{uuid.uuid4().hex}.tmp"
        with temp.open("xb") as stream:
            stream.write(canonical_json(state))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, self.root / "budget.json")

    def reserve(self, input_tokens: int, output_tokens: int, cost_usd: float, seconds: float) -> Reservation:
        if (type(input_tokens) is not int or type(output_tokens) is not int
                or any(not math.isfinite(value) or value < 0
                       for value in (input_tokens, output_tokens, cost_usd, seconds))):
            raise AuditError("invalid_budget_reservation", "Liability cannot be negative.")
        fd = self._locked()
        try:
            state = self._read()
            if state.pending is not None or state.unknown_settlement:
                raise AuditError("unsettled_liability", "Prior usage must be reconciled before another request.", 3)
            if (input_tokens > state.remaining_input_tokens or output_tokens > state.remaining_output_tokens
                    or cost_usd > state.remaining_cost_usd or seconds > state.remaining_seconds):
                raise AuditError("budget_exhausted", "Worst-case request exceeds remaining shared cap.", 3)
            reservation = Reservation(
                reservation_id=uuid.uuid4().hex, input_tokens=input_tokens, output_tokens=output_tokens,
                cost_usd=cost_usd, seconds=seconds, reserved_at=time.time(),
            )
            self._save(state.model_copy(update={"pending": reservation}))
            return reservation
        finally:
            os.close(fd)
            (self.root / "write.lock").unlink()

    def record_event(self, value: object) -> None:
        """Append durable source-attributed events; no provider observations invented."""
        fd = self._locked()
        try:
            with (self.root / "attempts.jsonl").open("ab") as stream:
                stream.write(canonical_json(value) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(fd)
            (self.root / "write.lock").unlink()

    def begin_request(self, request_digest: str, packet_digest: str, caps: ProviderCaps,
                      initial: BudgetState, *, treatment: str = "unspecified",
                      max_logical_requests: int | None = None) -> None:
        """Persist logical-request admission; crash/replay cannot reset retry liability.

        One ledger belongs to one treatment's packet, shared across its logical
        requests. Paired treatments use distinct ledgers with identical caps.
        """
        import json

        fd = self._locked()
        try:
            if self.initial != initial:
                raise AuditError("budget_cap_mismatch", "Ledger initial cap differs from request.")
            maximum = caps.max_logical_requests if max_logical_requests is None else min(max_logical_requests, caps.max_logical_requests)
            identity = sha256(canonical_json({"packet": packet_digest, "caps": caps,
                                              "treatment": treatment, "maximum": maximum}))
            path = self.root / "requests.json"
            if path.exists():
                if path.stat().st_size > 16 * 1024:
                    raise AuditError("invalid_request_ledger", "Logical request journal exceeds cap.")
                value = json.loads(path.read_bytes())
                if (not isinstance(value, dict) or set(value) != {"identity", "requests"}
                        or value["identity"] != identity or not isinstance(value["requests"], list)
                        or any(not isinstance(item, str) for item in value["requests"])):
                    raise AuditError("budget_identity_mismatch", "Existing ledger packet/caps differ.")
            else:
                # Initialize budget before journaling the first admitted request.
                # Existing pending or unknown state is always respected.
                value = {"identity": identity, "requests": []}
            state = self._read()
            if state.pending is not None or state.unknown_settlement:
                raise AuditError("unsettled_liability", "Reconcile the previous reservation first.", 3)
            if request_digest in value["requests"]:
                raise AuditError("duplicate_logical_request", "Use a fresh treatment ledger; no silent replay restart.", 3)
            if len(value["requests"]) >= maximum:
                raise AuditError("logical_request_limit", "Logical request cap reached.", 3)
            value["requests"].append(request_digest)
            temp = self.root / f".requests-{uuid.uuid4().hex}.tmp"
            with temp.open("xb") as stream:
                stream.write(canonical_json(value))
                stream.flush()
                os.fsync(stream.fileno())
            if not (self.root / "budget.json").exists():
                self._save(state)
            os.replace(temp, path)
        finally:
            os.close(fd)
            (self.root / "write.lock").unlink()

    def settle(self, reservation_id: str, *, input_tokens: int | None, output_tokens: int | None,
               cost_usd: float | None, elapsed_seconds: float | None) -> BudgetState:
        fd = self._locked()
        try:
            state = self._read()
            if state.pending is None or state.pending.reservation_id != reservation_id:
                raise AuditError("reservation_mismatch", "Only the active reservation can settle.", 4)
            values = (input_tokens, output_tokens, cost_usd, elapsed_seconds)
            if any(value is None for value in values):
                state = state.model_copy(update={"unknown_settlement": True})
                self._save(state)
                return state
            if any(value < 0 or not math.isfinite(value) for value in values if value is not None):
                raise AuditError("invalid_usage", "Usage cannot be negative.", 4)
            assert input_tokens is not None and output_tokens is not None
            assert cost_usd is not None and elapsed_seconds is not None
            if (input_tokens > state.pending.input_tokens or output_tokens > state.pending.output_tokens
                    or cost_usd > state.pending.cost_usd or elapsed_seconds > state.pending.seconds):
                self._save(state.model_copy(update={"unknown_settlement": True}))
                raise AuditError("reservation_overrun", "Observed usage exceeded reserved liability; further calls blocked.", 3)
            state = state.model_copy(update={
                "remaining_input_tokens": state.remaining_input_tokens - input_tokens,
                "remaining_output_tokens": state.remaining_output_tokens - output_tokens,
                "remaining_cost_usd": state.remaining_cost_usd - cost_usd,
                "remaining_seconds": state.remaining_seconds - elapsed_seconds,
                "pending": None,
                "unknown_settlement": False,
            })
            self._save(state)
            return state
        finally:
            os.close(fd)
            (self.root / "write.lock").unlink()
