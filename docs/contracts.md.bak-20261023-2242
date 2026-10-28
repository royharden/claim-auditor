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
