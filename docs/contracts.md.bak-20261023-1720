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

Source reference for strict models and serialization: [Pydantic configuration](https://pydantic.dev/docs/validation/latest/api/pydantic/config/)
and [serialization](https://pydantic.dev/docs/validation/latest/concepts/serialization/),
consulted 2026-10-23. No dependency installation or runtime conformance occurred.
