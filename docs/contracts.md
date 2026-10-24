# Static evidence contracts

`src/claim_auditor/contracts.py` is the sole serialized-schema authority. Closed,
strict Pydantic v2 models reject extra fields and type coercion. Observation
fields require explicit values, nulls or empty lists. Version constants default
to `claim-auditor/1` and `declared-static/1`; absence is never a default observation.

`Snapshot` identifies a full Git object revision or separately identified fixture
inventory. Its entries are sorted, casefold-unique portable relative paths and raw
SHA256/size/mode/status records. A fixture cannot impersonate a Git revision.
`Span` contains half-open UTF-8 byte offsets and display lines. Quote bytes, length
and digest must agree; the citation service separately reopens exact frozen bytes.

Inventory retains every block, including unsupported or unparsed prose. Each
`Claim` owns exact-span `Predicate` records with negation, conditions and qualifiers.
The index returns base positive proposition states; policy applies negation once.
Conditional/qualified propositions without exact support remain unknown.

Positive and contrary evidence require spans. Negative evidence requires a
replayable `CoverageReport` for the exact structured query. Complete negative
coverage cannot include skipped/unparsed scope. A near miss is never an exact match.

Reduction after citation validation: all supported predicates → verified; real
supported plus unresolved predicates → partial; all decisively absent/opposite →
missing within named scope; ambiguity or unsupported semantics → unknown. Existing
subject plus entirely wrong value does not manufacture a partial verdict.
`Finding.accused_predicate_ids` records only exact absent/inconsistent predicates
in missing/partial findings; unknown/verified findings carry none. Scoring never
assumes every unresolved partial predicate is an accusation.

`RUN.json` records lifecycle, tool/dependency versions, mode, attempts, errors,
snapshot identity and exact report artifact hashes. `report.json` is the typed
`AuditReport`; report writers return every emitted artifact hash. A fresh run gets
a frozen `snapshot/manifest.json` and `snapshot/files/` copy. Final RUN publication
uses an atomic replace. Incomplete/crashed runs cannot be verified as complete.

Exit codes: 0 complete report, 2 input/setup, 3 incomplete audit/comparison, 4
integrity failure, 5 explicitly requested `--fail-on missing` policy. Nonzero input,
integrity and incomplete status precedes optional accusation policy.
A requested README with no snapshot entry is an input error
(`readme_not_in_snapshot`, exit 2). A README excluded at snapshot time (for
example an unsupported encoding or lone-CR line endings) yields an incomplete
`Inventory` with a `readme_excluded` pipeline error whose detail is the gap reason
(exit 3). Only an included README reaches `read_source`, whose byte-identity
failures remain `source_integrity` (exit 4).

Exit 4 covers every already pinned, sealed or admitted artifact whose bytes or
bindings changed; exit 2 stays for pre-start argument/config/admission refusals.
`contracts.RUN_STATE_EXIT` (via `exit_for_state`) is the one run-state table:
`complete` 0, `failed_input` 2, `incomplete` 3, `failed_integrity` 4; the CLI uses
it. `contracts.RUN_STATE_REFUSAL` (via `refusal_for_state`) maps each non-complete
state to its own refusal code, so `verify_report` on such a run raises
`run_failed_input` (2), `run_failed_integrity` (4) or `run_incomplete` (3, every
other non-complete state); the former shared `run_not_complete` no longer exists.
Nested verification of a tool-written sealed copy translates `run_not_found`: a
missing `RUN.json` in an export's copied closure is `export_copy_identity` (4), and
a missing `RUN.json` under a paired run's `full-index-run` is
`paired_artifact_integrity` (4). Local Git acquisition hash-verifies every commit,
tree and blob object it reads against its ID (SHA-1 or SHA-256 by ID length); a
mismatch is `git_object_hash_mismatch` (4). A supplied snapshot root without a
top `manifest.json` is `snapshot_not_found` (2) and a supplied run root without
`RUN.json` is `run_not_found` (2); missing inner artifacts remain integrity (4).
`export_report` refuses traversing/UNC arguments as `invalid_export_path` (2), while
links/reparse points or non-ordinary entries inside the run tree stay
`unsafe_export_path` (4). An uncaught CLI exception is `unexpected_failure` (3).

Each reason code has exactly one exit class. Evaluation-side applications of the
exit-4 rule (changed pinned/sealed artifacts) are: DEV custody
`dev_source_inventory_changed`, `dev_seal_changed`, `dev_manifest_changed`,
`dev_stage_artifact_changed`, `dev_source_manifest_changed`,
`dev_label_source_changed` and `dev_label_evidence_changed`; dataset
`dataset_manifest_changed`, `dataset_source_changed`, `dataset_protocol_changed`
and `dataset_gold_changed`; manual annotation `manual_parent_changed`,
`manual_atom_changed`, `manual_annotation_digest`, `manual_source_changed`,
`manual_inventory_changed`, `manual_ruling_history_changed` and
`manual_candidate_source_changed`; rulings `ruling_digest_mismatch`,
`ruling_claim_changed`, `ruling_source_changed`, `ruling_binding_changed`,
`ruling_ledger_changed`, `annotation_report_changed` and
`annotation_source_changed`; plus `source_seal_mismatch`,
`replay_identity_mismatch`, `paired_gold_seal_mismatch` and
`evaluation_lock_digest_mismatch`. Other custody, dataset, manual and ruling
refusals (missing, conflicting, out-of-scope or over-limit inputs) stay input (2).
`unsettled_liability`, `parser_invalid_output` and `paired_dispatch_unbound` are
incomplete (3). Setup refusals that formerly shared an integrity code were renamed
and stay input (2): `transport_admission_binding` and `budget_admission_required`
(`budget_admission_mismatch` is now always 4), and
`undeclared_experiment_control` (`paired_invalid_artifact` is now always 4).
`invalid_ledger_scope`, `invalid_reconciliation_role` and
`reconciliation_scope_required` are input (2). Pre-start admission/config refusals
and input-schema checks remain 2.

A source file over the per-file cap (512 KiB) is not read. Its `SnapshotEntry` is
`excluded` with a `file_byte_limit` `ScopeGap`, so the snapshot is incomplete and
absence is never established. The entry `sha256` is the marker
`snapshot.unread_entry_digest("file_byte_limit", size, object_id)`, not a content
digest. A fixture marker binds only size; a Git marker binds the blob object ID.
The aggregate text cap, the compressed object-copy cap and commit-object reads still
abort snapshot creation. These mappings are constructed source; they have not been
executed.

Live transport is disabled. Replay requires input/prompt/model/policy identities
and independently recognized atoms, is visibly replay, and supplies no live quality
or cost evidence. Future comparison admission must preserve the required live
extraction and single-pass arms; optional Jev cannot substitute for either.

W2 adds a distinct raw-packet `ProviderRequest`/`ProviderResponse` port, closed
`ProviderCaps`, `ProviderFixture`, `ProviderProposal`, `SimulatedUsage` and local
`PairedRunConfig`. No rule candidate list or labels enter provider requests.
New exact-span atoms are validated against raw prose and the bounded predicate
grammar; unknown semantics remain explicit. See [provider modes](provider-modes.md)
for required fields, source identities, fixture usage and durable budget rules.
No existing four-way finding or legacy replay wire signature changed.

`AnnotationRuling` requires ruling/source/claim/evidence identities, `atom:GoldAtom`,
timezone-aware `recorded_at`, explicit nullable `supersedes_ruling_id` and
`human_action_id`. Its schema checks exact claim digest and annotator provenance:
agent records cannot carry human actions; human records require an explicit action
ID. A nonempty string is not proof of review. The ruling service additionally
checks content-addressed IDs, reopened-byte bindings and explicit operator human
confirmation, retaining history and disagreements. Rulings are judgments, not
verified source evidence, consensus, human gold or heldout custody certification.

R02 adds closed `LiveAuthorization`, `LiveAtomProposal`, `LiveEvidencePointer`,
`LiveProposalPayload`, `LiveUsage` and `LiveProviderResponse` for dormant provider
source. These preserve owner admission and observation missingness independently
of the unchanged fake/replay wire. Raw model atom coordinates are normalized into
source-derived IDs and predicates by code. No live response or measured acceptance
is created by constructing these types. See provider modes for activation limits.

`ManualAnnotation` is the closed source-first inventory record. It requires
annotation/source/family identities, `inventory:Inventory`, explicit
`parent_spans:list[Span]`, actual annotator type/ID, aware recording time, nullable
`action_id` and nullable `supersedes_annotation_id`. `Inventory.complete` is its
sole coverage state; there is no parallel coverage flag or candidate-derived list.
Agent rows cannot carry human actions; human rows need an actual action ID.
The annotation service reopens full source, parent spans/qualifiers and raw block
coverage, derives content identity and confirms real human action at write/export.

The `annotation-record` CLI accepts a draft containing these same fields except
the two service-computed annotation/supersession IDs. It validates through the
existing central model and checks selected source identity; it does not introduce
a duplicate draft wire, infer complete coverage or generate labels. `--previous`
selects an explicit retained predecessor. `annotation-package --snapshot` is
source-first; `--run` is separately labeled assisted review of an existing report.

`ManualExportConfig` contains explicit claim-to-evidence path and latest ruling
selection maps plus required nullable operator/action/date/rationale fields. Those
action fields are all null for agent proposals or all explicit for a human export;
actual human confirmation remains a separate service/CLI guard. Paths are portable
and relative to the operator's selection file. It is operation input, never a
second label record, coverage state, custody receipt or proof of adjudication.

Source reference for strict models and serialization: [Pydantic configuration](https://pydantic.dev/docs/validation/latest/api/pydantic/config/)
and [serialization](https://pydantic.dev/docs/validation/latest/concepts/serialization/),
consulted 2026-10-23. No dependency installation or runtime conformance occurred.
