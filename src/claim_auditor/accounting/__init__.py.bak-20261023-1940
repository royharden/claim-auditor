"""Bounded durable reservation source, with no network or credential access."""

from __future__ import annotations

import math
import json
import base64
import os
import stat
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..contracts import (
    Attempt, AuditError, BudgetState, DatedRateCard, LiveBudgetAdmission, ProviderBillReceipt, ProviderCaps,
    Reservation, ReservationReconciliation, SettlementContext, canonical_json, sha256, stable_id,
)


def ledger_root_identity(root: Path) -> str:
    """Lexical owner path identity, not an ACL/inode/containment certificate."""
    absolute = os.path.normcase(os.path.normpath(os.path.abspath(root)))
    if absolute.startswith(("\\\\", "//")):
        raise AuditError("invalid_budget_root", "Use an explicitly owner-selected ordinary local root.")
    return sha256(canonical_json({"absolute_ledger_root": absolute}))


def budget_admission_id(record: LiveBudgetAdmission) -> str:
    return stable_id("budget-admission", record.model_dump(mode="json", exclude={"admission_id"}))


def bind_budget_admission(root: Path, record: LiveBudgetAdmission, *, protocol_digest: str,
                           caps: ProviderCaps, authorization_ids: dict[str, str],
                           packet_digest: str | None = None) -> None:
    """Pin one nonsecret owner admission to a durable root; no budget math here.

    Changing output directories cannot reset these existing producer ledgers.
    Changing root identity requires a different content-bound owner admission.
    """
    from ..snapshot.safeio import read_ordinary

    record = LiveBudgetAdmission.model_validate_json(canonical_json(record))
    admitted = datetime.fromisoformat(record.admitted_at.replace("Z", "+00:00"))
    if (admitted > datetime.now(timezone.utc) or record.admission_id != budget_admission_id(record)
            or record.protocol_digest != protocol_digest or record.ledger_root_identity != ledger_root_identity(root)
            or (packet_digest is not None and record.packet_digest != packet_digest)
            or record.caps_digest != sha256(canonical_json(caps)) or record.authorization_ids != authorization_ids):
        raise AuditError("budget_admission_mismatch", "Owner admission must bind actual root/protocol/caps/authorizations.", 4)
    root = Path(os.path.abspath(root))
    root.mkdir(parents=True, exist_ok=True)
    for path in [*reversed(root.parents), root]:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise AuditError("invalid_budget_root", "Budget root must be ordinary owner-controlled directories.")
    try:
        fd = os.open(root / "admission.lock", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise AuditError("budget_writer_busy", "Admission lock exists; never delete by age.", 3) from exc
    try:
        path = root / "ADMISSION.json"
        if path.exists():
            existing = LiveBudgetAdmission.model_validate_json(read_ordinary(root, path.name, cap=64 * 1024))
            if canonical_json(existing) != canonical_json(record):
                raise AuditError("budget_admission_mismatch", "Existing root belongs to another owner budget admission.", 4)
        else:
            if any(item.name != "admission.lock" for item in root.iterdir()):
                raise AuditError("budget_admission_missing", "Do not silently adopt an existing unbound ledger root.", 4)
            with path.open("xb") as stream:
                stream.write(canonical_json(record) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
    finally:
        os.close(fd)
        (root / "admission.lock").unlink()


class BudgetLedger:
    """Single active writer enforced by exclusive lock; unknown usage blocks calls."""

    def __init__(self, root: Path, limits: BudgetState) -> None:
        self.root = root
        self.initial = BudgetState.model_validate_json(canonical_json(limits))

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
                or any(type(value) not in {int, float} or (type(value) is float and not math.isfinite(value)) or value < 0
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
            self._append_event_locked(value)
        finally:
            os.close(fd)
            (self.root / "write.lock").unlink()

    def _append_event_locked(self, value: object) -> None:
        with (self.root / "attempts.jsonl").open("ab") as stream:
            stream.write(canonical_json(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())

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
            state = self._settled_state_locked(state, reservation_id, input_tokens=input_tokens,
                                                output_tokens=output_tokens, cost_usd=cost_usd,
                                                elapsed_seconds=elapsed_seconds, owner_reconciliation=False)
            self._save(state)
            return state
        finally:
            os.close(fd)
            (self.root / "write.lock").unlink()

    def _settled_state_locked(self, state: BudgetState, reservation_id: str, *, input_tokens: int | None,
                              output_tokens: int | None, cost_usd: float | None,
                              elapsed_seconds: float | None, owner_reconciliation: bool) -> BudgetState:
        if state.pending is None or state.pending.reservation_id != reservation_id:
            raise AuditError("reservation_mismatch", "Only the active reservation can settle.", 4)
        if state.unknown_settlement and not owner_reconciliation:
            raise AuditError("owner_reconciliation_required", "Unknown liability needs an explicit receipted owner record.", 3)
        values = (input_tokens, output_tokens, cost_usd, elapsed_seconds)
        if any(value is None for value in values):
            return state.model_copy(update={"unknown_settlement": True})
        if (type(input_tokens) is not int or type(output_tokens) is not int
                or any(type(value) not in {int, float} or value < 0 or (type(value) is float and not math.isfinite(value)) for value in values)):
            raise AuditError("invalid_usage", "Explicit finite nonnegative token/money/time observations required.", 4)
        assert input_tokens is not None and output_tokens is not None
        assert cost_usd is not None and elapsed_seconds is not None
        if (input_tokens > min(state.pending.input_tokens, state.remaining_input_tokens)
                or output_tokens > min(state.pending.output_tokens, state.remaining_output_tokens)
                or cost_usd > min(state.pending.cost_usd, state.remaining_cost_usd)
                or elapsed_seconds > min(state.pending.seconds, state.remaining_seconds)):
            self._save(state.model_copy(update={"unknown_settlement": True}))
            raise AuditError("reservation_overrun", "Observation exceeds reserved/remaining liability; state stays blocked.", 3)
        return state.model_copy(update={"remaining_input_tokens": state.remaining_input_tokens - input_tokens,
                                        "remaining_output_tokens": state.remaining_output_tokens - output_tokens,
                                        "remaining_cost_usd": state.remaining_cost_usd - cost_usd,
                                        "remaining_seconds": state.remaining_seconds - elapsed_seconds,
                                        "pending": None, "unknown_settlement": False})

    def reconcile(self, record: ReservationReconciliation, *, rate_card: DatedRateCard | None = None,
                  usage_receipt_data: bytes | None = None, pricing_receipt_data: bytes | None = None) -> BudgetState:
        """Later actual owner action only; reuse the existing settlement transition.

        Exact state/reservation/attempt binding, actual supplied usage/pricing
        receipt references and within-cap known values are mandatory. No lock-age
        deletion, budget reset, implicit zero or invoice lookup is implemented.
        """
        from ..providers.settlement import validate_settlement_observation
        from ..providers.live import _json
        from ..snapshot.safeio import SnapshotError, read_ordinary

        try:
            fd = self._locked()
        except OSError as exc:
            raise AuditError("budget_storage_failure", "Cannot acquire the owner ledger; unresolved state is preserved.", 3) from exc
        try:
            record = ReservationReconciliation.model_validate_json(canonical_json(record))
            if (not isinstance(usage_receipt_data, bytes) or not isinstance(pricing_receipt_data, bytes)
                    or not 0 < len(usage_receipt_data) <= 8 * 1024 * 1024
                    or not 0 < len(pricing_receipt_data) <= 2 * 1024 * 1024
                    or sha256(usage_receipt_data) != record.usage_receipt_digest
                    or sha256(pricing_receipt_data) != record.pricing_receipt_digest):
                raise AuditError("reconciliation_receipts_required", "Actual supplied receipt bytes must match pinned nonempty usage/pricing digests.", 4)
            usage_receipt_value = _json(usage_receipt_data)
            pricing_receipt_value = _json(pricing_receipt_data)
            state = self._read()
            if state.pending is None or state.pending.reservation_id != record.reservation_id:
                raise AuditError("reservation_mismatch", "Owner record must name the actual unresolved reservation.", 4)
            if sha256(canonical_json(state)) != record.budget_state_digest:
                raise AuditError("reconciliation_state_changed", "Owner must review the current exact pending state.", 4)
            when = datetime.fromisoformat(record.recorded_at.replace("Z", "+00:00"))
            if when > datetime.now(timezone.utc) or when.timestamp() < state.pending.reserved_at:
                raise AuditError("invalid_reconciliation_date", "Actual owner action cannot predate reservation or be future dated.", 4)
            raw = read_ordinary(self.root, "attempts.jsonl", cap=64 * 1024 * 1024)
            reserved = []
            closed = []
            for line in raw.splitlines():
                item = _json(line)
                if (isinstance(item, dict) and item.get("phase") == "reserved"
                        and isinstance(item.get("reservation"), dict)
                        and item["reservation"].get("reservation_id") == record.reservation_id):
                    reserved.append(item)
                if isinstance(item, dict) and item.get("phase") == "closed" and isinstance(item.get("attempt"), dict):
                    closed.append(item)
            if len(reserved) != 1:
                raise AuditError("reconciliation_attempt_unavailable", "One durable pre-send reservation event is required; preserve/investigate missing history.", 4)
            event = reserved[0]
            if Reservation.model_validate_json(canonical_json(event["reservation"])) != state.pending:
                raise AuditError("reconciliation_reservation_changed", "Recorded request liability differs.", 4)
            attempt = Attempt.model_validate_json(canonical_json(event["attempt"]))
            usage = record.usage
            if usage.resolved_model != attempt.model:
                raise AuditError("reconciliation_model_mismatch", "Usage belongs to another resolved model.", 4)
            if attempt.mode == "live":
                if usage.origin != "provider_reported" or usage.settlement_context is None or usage.settlement_observation is None:
                    raise AuditError("reconciliation_provenance", "Actual live usage and bound owner observation required.", 4)
                context = usage.settlement_context
                supplied_context = SettlementContext.model_validate_json(canonical_json(usage_receipt_value))
                if canonical_json(supplied_context) != canonical_json(context):
                    raise AuditError("reconciliation_usage_receipt_mismatch", "Supplied actual usage context differs from the reviewed record.", 4)
                admission = LiveBudgetAdmission.model_validate_json(canonical_json(event.get("budget_admission")))
                if record.owner_id != admission.owner_id or admission.admission_id != budget_admission_id(admission):
                    raise AuditError("reconciliation_owner_mismatch", "Actual owner record must match durable budget admission.", 4)
                if (context.reservation_id != record.reservation_id or context.attempt_id != attempt.attempt_id
                        or context.request_digest != event.get("request_digest")
                        or context.payload_digest != event.get("payload_digest")
                        or context.authorization_id != event.get("authorization_id")
                        or attempt.provider != f"live:{context.provider}"):
                    raise AuditError("reconciliation_context_mismatch", "Actual reservation/authorization/request/payload/provider binding differs.", 4)
                for item in closed:
                    prior = item.get("usage")
                    if item["attempt"].get("attempt_id") == attempt.attempt_id and isinstance(prior, dict):
                        old_context = prior.get("settlement_context")
                        if isinstance(old_context, dict) and (old_context.get("response_digest") != context.response_digest
                                                               or old_context.get("response_id") != context.response_id):
                            raise AuditError("reconciliation_response_mismatch", "Do not substitute another physical response for pending liability.", 4)
                stored_card = DatedRateCard.model_validate_json(canonical_json(event.get("rate_card")))
                if rate_card is not None and canonical_json(rate_card) != canonical_json(stored_card):
                    raise AuditError("reconciliation_rate_card_mismatch", "Do not replace the pre-call owner card.", 4)
                if usage.cost_basis == "rate_card_derived":
                    supplied_card = DatedRateCard.model_validate_json(canonical_json(pricing_receipt_value))
                    if canonical_json(supplied_card) != canonical_json(stored_card):
                        raise AuditError("reconciliation_pricing_receipt_mismatch", "Actual supplied dated card differs from pre-call admission.", 4)
                elif usage.cost_basis == "provider_bill":
                    from decimal import Decimal

                    bill = ProviderBillReceipt.model_validate_json(canonical_json(pricing_receipt_value))
                    observation = usage.settlement_observation
                    if (bill.provider != context.provider or bill.resolved_model != context.resolved_model
                            or bill.response_id != context.response_id or observation is None
                            or Decimal(bill.amount_decimal) != Decimal(observation.amount_decimal)
                            or bill.receipt_reference != observation.receipt_reference
                            or datetime.fromisoformat(bill.issued_at.replace("Z", "+00:00")) > when):
                        raise AuditError("reconciliation_bill_receipt_mismatch", "Supplied actual bill does not match the request/model/response/amount/action.", 4)
                else:
                    raise AuditError("reconciliation_provenance", "Actual cost must be labeled derived or provider bill.", 4)
                observation = validate_settlement_observation(context, usage.settlement_observation,
                                                               rate_card=stored_card, allow_bill_reconciliation=True)
                if (usage.cost_usd != observation.cost_usd or usage.cost_basis != observation.basis
                        or usage.raw_usage != context.raw_usage or usage.pricing != context.pricing
                        or usage.input_tokens != context.pricing.input_tokens
                        or usage.output_tokens != context.pricing.output_tokens
                        or usage.cost_receipt != observation.receipt_reference or usage.cost_error is not None
                        or (usage.cost_basis == "provider_bill" and usage.reported_bill_usd != observation.cost_usd)):
                    raise AuditError("reconciliation_usage_changed", "Supplied normalized usage/cost differs from bound observation.", 4)
            elif usage.origin != "fixture" or usage.cost_basis != "fixture":
                raise AuditError("reconciliation_provenance", "Fixture liability cannot be relabeled actual provider use.", 4)
            else:
                if canonical_json(usage_receipt_value) != canonical_json(usage):
                    raise AuditError("reconciliation_fixture_receipt_mismatch", "Explicit simulation usage receipt differs.", 4)
            values = (usage.input_tokens, usage.output_tokens, usage.cost_usd, usage.elapsed_seconds)
            if any(value is None for value in values):
                raise AuditError("reconciliation_incomplete", "Actual supplied receipts must resolve all liability dimensions.", 3)
            candidate = self._settled_state_locked(state, record.reservation_id, input_tokens=usage.input_tokens,
                                                    output_tokens=usage.output_tokens, cost_usd=usage.cost_usd,
                                                    elapsed_seconds=usage.elapsed_seconds, owner_reconciliation=True)
            # Durable supplied receipts precede the one atomic state transition.
            # This event is deliberately 'validated', not a false commit receipt.
            self._append_event_locked({"phase": "owner_reconciliation_validated", "record": record,
                                        "usage_receipt_base64": base64.b64encode(usage_receipt_data).decode("ascii"),
                                        "pricing_receipt_base64": base64.b64encode(pricing_receipt_data).decode("ascii"),
                                        "candidate_state_digest": sha256(canonical_json(candidate))})
            self._save(candidate)
            return candidate
        except AuditError:
            raise
        except (OSError, ValueError, TypeError, KeyError, OverflowError, SnapshotError, RecursionError, MemoryError) as exc:
            raise AuditError("invalid_reconciliation", "Owner reconciliation failed closed; no budget reset or negative balance.", 4) from exc
        finally:
            os.close(fd)
            (self.root / "write.lock").unlink()
