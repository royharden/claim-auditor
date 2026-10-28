# Typed provider source boundary

Construction only: no provider or application execution has occurred. `live` is
refused with `live_not_authorized`. No SDK, HTTP transport, credential lookup or
fallback exists. Real live extraction and single-pass comparison remain unfinished.

The paired runner uses the single port
`providers.produce(request, *, transport, ledger) -> ProviderResponse`.
`ProviderRequest` requires `arm` (`extraction` or `single_pass`), `packet`,
`input_digest=sha256(canonical_json(packet))`, `prompt_digest`, `model`,
`policy_version` and `caps`. The packet's internal digest is independently checked.
No extracted candidates, labels, adjudication rationale or human gold are request
fields. Both treatments consume identical packet bytes; arm/prompt identities
remain separately bound. Unknown/extra/omitted wire fields fail closed.

`ProviderCaps` requires `total_input_tokens`, `total_output_tokens`, `total_seconds`,
`total_cost_usd`, `request_input_tokens`, `request_output_tokens`, `request_seconds`,
`request_cost_usd`, `max_logical_requests`, `max_retries`. Total ceilings cannot
exceed 32k input, 8k output, 60 seconds; each physical attempt reserves its declared
worst case, at most 30 seconds. Extraction admits at most two logical requests;
single-pass admits one. Each admits at most one retry. These are declared fixture
liabilities, not verified tokenization or actual provider costs. Future live
admission must validate tokenizer/rates and disable hidden SDK retries.

Construct a separate `BudgetLedger(root, BudgetState(...))` per treatment, with
remaining values matching the total caps and `pending=None`,
`unknown_settlement=False`. The initial state does not reset an existing ledger.
The ledger pins packet, caps, model, mode and treatment, durably admits logical
requests, and reserves before each transport attempt. Duplicate logical request
digests cannot silently restart. Unknown settlement or overrun retains liability
and blocks subsequent calls. Reconciliation must use the pending reservation ID;
never delete a lock or budget file to recover. A crashed reserved attempt remains
pending. Atomic replacement and fsynced attempt events are construction controls;
race/crash/filesystem behavior is unverified.

`FakeTransport(fixtures: list[ProviderFixture])` and
`ReplayTransport(paths: list[Path])` require an explicitly supplied fixture for
each attempt. No last-item reuse or fallback occurs. Replay files are bounded
ordinary files. Every fixture requires `request_digest=request_digest(request)`,
`proposals`, `simulated_usage`, `error` and `retryable`. A failed fixture carries
no proposals; a successful fixture cannot request a retry. `simulated_usage` has
required nullable input/output token, cost and elapsed fields; it drives fixture
budget bookkeeping only. Unknown fixture usage blocks a following attempt.

`ProviderProposal` requires `candidate_id`, `claim`, `relation`, `evidence_spans`.
The historical field name `candidate_id` means the proposed Claim's source-derived
ID, not an input candidate. New exact README spans are permitted. IDs follow the
existing source convention: sentence ID from snapshot/path/start/end, then claim
ID from parent/ordinal and predicate ID from claim/fields. Quote/UTF-8 offsets,
digest and LF display coordinates must agree. Duplicate source atoms/IDs and
clipped surrounding qualifiers fail closed. The bounded static grammar validates
the proposed predicate from the quoted text, preserving negation, condition and
qualifiers; unsupported semantic mappings must use the grammar's explicit unknown
kind/uncertainty. This is conservative mapping, not measured semantic extraction.
No pre-extracted inventory is supplied to either provider.

Extraction proposals carry null relation and no code evidence. Single-pass has an
explicit proposed relation, with evidence confined to admitted excerpt bytes.
Full-file coordinate and citation reopening remains the sole citation resolver's
job. Relations never decide four-way findings. No provider/packet absence proof
exists. The consumer preserves all screened, invalid, incomplete or failed rows.

Responses contain request digest, status, proposals, attempts, simulated usage,
error, `mode=fake|replay`, and `comparative_complete=False`. Attempt mode is replay
with provider `fake` or `replay`; token and latency observations are null. Attempt
cost zero denotes only current external spend for inert replay, never a historic
or estimated live cost. Simulated fixture observations are separately labeled and
must not feed actual live cost/latency claims. A proposed response is not product,
benchmark or runtime acceptance.

The older `audit --mode replay` envelope remains a separate inventory-preserving
legacy path. It neither implements nor replaces this raw-packet paired comparison.
