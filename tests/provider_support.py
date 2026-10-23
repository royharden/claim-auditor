"""Fixed provider input constructors, with no rule extractor or label input."""

from claim_auditor.accounting import BudgetLedger
from claim_auditor.contracts import (
    BudgetState, Claim, Predicate, ProviderCaps, ProviderFixture, ProviderProposal,
    ProviderRequest, SimulatedUsage, canonical_json, sha256, stable_id,
)
from claim_auditor.providers.port import request_digest

from .support import span_for


def caps(**changes):
    fields = dict(total_input_tokens=100, total_output_tokens=50, total_seconds=10.0,
                  total_cost_usd=1.0, request_input_tokens=40, request_output_tokens=20,
                  request_seconds=4.0, request_cost_usd=0.4,
                  max_logical_requests=2, max_retries=1)
    fields.update(changes)
    return ProviderCaps(**fields)


def request_for(packet, *, arm="extraction", limits=None, prompt="a"):
    return ProviderRequest(arm=arm, packet=packet, input_digest=sha256(canonical_json(packet)),
                           prompt_digest=prompt * 64, model="fixture-model/1",
                           policy_version="declared-static/1", caps=limits or caps())


def ledger_for(root, request):
    limits = request.caps
    return BudgetLedger(root, BudgetState(
        remaining_input_tokens=limits.total_input_tokens,
        remaining_output_tokens=limits.total_output_tokens,
        remaining_cost_usd=limits.total_cost_usd, remaining_seconds=limits.total_seconds,
        pending=None, unknown_settlement=False,
    ))


def fixture_for(request, *, proposals=None, error=None, retryable=False, unknown=False):
    return ProviderFixture(request_digest=request_digest(request), proposals=proposals or [],
                           simulated_usage=SimulatedUsage(
                               input_tokens=None if unknown else 10,
                               output_tokens=None if unknown else 5,
                               cost_usd=None if unknown else 0.1,
                               elapsed_seconds=None if unknown else 1.0,
                           ), error=error, retryable=retryable)


def proposed_atom(snapshot, raw, *, unknown=False):
    # Two explicitly hand-authored meanings, not generated from the production grammar.
    span = span_for(snapshot, raw, end=len(raw.rstrip(b"\r\n")))
    parent = stable_id("sentence", snapshot.snapshot_id, "README.md", span.start_byte, span.end_byte)
    identifier = stable_id("claim", parent, 0)
    fields = dict(kind="other" if unknown else "symbol_declared",
                  subject=span.quote if unknown else "work", module=None, path=None,
                  key=None, expected=None, negated=False, condition=None, qualifiers=[], pattern=None)
    query = Predicate(predicate_id=stable_id("predicate", identifier, fields), **fields)
    return Claim(claim_id=identifier, parent_id=parent, atom_ordinal=0, kind=query.kind,
                 normalized=span.quote, span=span, predicates=[query],
                 extraction_method="model_proposal", extraction_version="hand-authored-dev/1",
                 uncertainty=["unsupported_semantics"] if unknown else [])


def proposal_for(atom, *, relation=None, evidence=None):
    return ProviderProposal(candidate_id=atom.claim_id, claim=atom, relation=relation,
                            evidence_spans=evidence or [])
