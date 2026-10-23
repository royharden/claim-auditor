# Intended operator quickstart

**Source construction only. None of these commands has run.** Runtime, parser/
transport containment and dependency compatibility remain unverified. Live/human
comparison is not measured; no Action has run. These are future commands after the
owner authorizes normal-mode setup and local execution. Dirty Mode does not permit
running them, installing dependencies, starting services or creating CI scaffolding.

## Local audit and integrity

Use Python 3.12+ and a trusted installed tool outside the audited target. Dependencies
are declared but not installed/locked during construction. A future owner resolves
and reviews them, generates `uv.lock`, and then runs `uv sync`. No keys are needed
for rules/fake/replay source paths. The CLI does not load `.env`; `.env.example`
contains reserved names only, without values. Dormant HTTP credentials are explicit
future caller arguments, never target-controlled configuration.

From the product repository, after authorized setup:

```console
uv run claim-auditor demo --offline --out results-local/demo-001
uv run claim-auditor verify-report results-local/demo-001/run
```

The demo authors source inputs, then generates a real local snapshot/report at
runtime. It does not ship a prerecorded passing report. Choose new output names
for every retry and preserve failed/incomplete directories for investigation.
Static declarations are narrower than runtime behavior or whole-product quality.

To audit an existing owned source fixture:

```console
uv run claim-auditor snapshot --fixture fixtures/corpus-dev/ledger-cli/source --out results-local/snapshot-001
uv run claim-auditor audit --snapshot results-local/snapshot-001 --readme README.md --mode rules --out results-local/audit-001
uv run claim-auditor verify-report results-local/audit-001
```

Only the family's `source/` enters acquisition. Its provenance/review prompts are
outside inference source. For local Git acquisition use `snapshot --repo PATH
--commit FULL_OBJECT_ID --out NEW_PATH`; supply a complete nonshallow owned store.
No target code or README commands are executed. Reports may contain private code
and stay local absent separate publication authority.

## Closed paired fake/replay assembly

Both provider roles must receive exactly the same raw source packet and canonical
input digest. The admitted research `eval --protocol LOCK --input SNAPSHOT --out
NEW_PATH` remains separate: its real rights/custody/admission fields must never be
fabricated merely to run a DEV example. DEV-only packet preparation is a separate
source operation and cannot admit a heldout experiment.

Prepare a disclosed DEV-only packet through the same source packet builder, without
manufacturing an admitted research LOCK:

```console
uv run claim-auditor dev-packet --snapshot results-local/snapshot-001 --out results-local/prepared
uv run claim-auditor paired-input --packet results-local/prepared/packet.json --out results-local/paired-input.json
uv run claim-auditor paired-run --packet results-local/prepared/packet.json --snapshot results-local/snapshot-001 --config results-local/paired-input.json --out results-local/paired-001
uv run claim-auditor paired-verify --run results-local/paired-001 --snapshot results-local/snapshot-001
```

`paired-input` writes closed fake input configuration, with both roles explicitly
`fixture_not_supplied`, nullable simulated usage and no proposed predictions. This
is a safe failure template, not a model simulator or sample success. `paired-run`
retains the failures and returns 3. To exercise successful fake/replay proposals,
the operator must supply explicit matching fixtures with exact source spans and
request identities; see [provider modes](provider-modes.md). No list of rule
candidates/labels/rationale is sent to the provider. Replays do not become live.

`paired-verify` without an external digest checks self-consistency only. Retain
the exact returned raw `PAIRED.json` digest independently; later verification or
scoring can supply `--manifest-digest EXACT_RETAINED_SHA256`. This digest binds an
artifact, not custody, human review or quality. It never falls back to current HEAD.

```console
uv run claim-auditor paired-score --run results-local/paired-001 --snapshot results-local/snapshot-001 --gold operator-gold.jsonl --out results-local/score-001 --manifest-digest EXACT_RETAINED_SHA256
```

The service verifies inference closure before opening separate labels and supports
one snapshot/family per run. No sample human labels or invented scores are supplied.
Fake/replay descriptive scoring returns 3 and cannot complete the required live/
human comparison. Optional full-index utility is a separate treatment, never
undisclosed evidence for packet arms.

## DEV source staging

Twelve disclosed DEV families contain 120 authored statements, not 120 extracted
atoms, human gold, heldout examples or measured results. Supply actual existing
authorship/rights provenance and an operator access receipt; the CLI never writes
those attestations on someone's behalf. Use an opaque alias (`f-` plus sixteen
lowercase hexadecimal digits), not a name encoding a verdict or family outcome.

```console
uv run claim-auditor dev-stage --source fixtures/corpus-dev/ledger-cli/source --out results-local/stage-001 --alias f-0123456789abcdef --provenance fixtures/corpus-dev/ledger-cli/provenance.json --access-receipt operator-dev-access.json
uv run claim-auditor dev-export --stage results-local/stage-001 --seal-digest EXACT_RETAINED_SEAL_SHA256 --out results-local/source-export-001
```

Retain the returned `seal_digest` independently. Export verifies it before copying
only the aliased snapshot; provenance, access receipts and label material remain
outside inference output. Outputs must be fresh. These operations are DEV-only and
refuse heldout/admission claims; opaque aliases and hashes cannot enforce blindness,
ACLs, source rights or custody.

## Annotation and ruling history

Source-first manual inventory must start from the full original README, account
for every assertion and raw block, and may introduce atoms missed by automatic
extraction. Its explicit parent spans bind omitted qualifiers/conditions; automatic
candidate lists cannot define manual coverage. Prepare the complete source-first
package without running the candidate extractor:

```console
uv run claim-auditor annotation-package --snapshot results-local/snapshot-001 --family-id dev-example --out results-local/manual-review-001
```

This writes a blank source inventory package, never completed annotations. Review
every raw block and original README span, record parent context and attribution,
and preserve incomplete coverage rather than inventing extractor-independent gold.

To record a manually authored inventory, prepare `operator-inventory.json` with
exactly the fields of `contracts.ManualAnnotation` except `annotation_id` and
`supersedes_annotation_id` (both are computed by the recording service). Required
input includes the selected source-manifest digest, family, full `Inventory`,
explicit `parent_spans`, annotator type/ID, aware timestamp and explicit nullable
action ID. Every raw block must retain its review status/reason. The central wire
validates this input; the service reopens source/parents and checks coverage. It
does not use a candidate-extracted atom list.

```console
uv run claim-auditor annotation-record --snapshot results-local/snapshot-001 --input operator-inventory.json --out results-local/manual-annotation-001.json
```

Use `--previous EXISTING_RECORD` to preserve and explicitly supersede the prior
annotation. Agent records require null action ID. Human records require an actual
human action, nonblank action ID and an explicit `--confirm-human-action` by the
real operator. Do not populate human records or receipts on a person's behalf.
Recording an inventory is not a verdict, consensus or complete gold release.

Record explicitly authored judgments against these manual atoms with reopened
evidence, retaining provenance and any disagreements:

```console
uv run claim-auditor annotation-ruling --snapshot results-local/snapshot-001 --annotation results-local/manual-annotation-001.json --ledger results-local/manual-rulings.jsonl --atom operator-judgment.json --evidence operator-evidence.json --recorded-at ACTUAL_TIMEZONE_AWARE_ACTION_TIMESTAMP
uv run claim-auditor annotation-export --snapshot results-local/snapshot-001 --annotation results-local/manual-annotation-001.json --ledger results-local/manual-rulings.jsonl --selection operator-selection.json --out results-local/manual-proposals-001
```

`operator-judgment.json` is a strict `GoldAtom` judgment authored by the actual
annotator, not supplied by this repository. The type name does not make agent
judgments human gold. The service requires an exact manual claim/family and checks
the selected evidence bundle. Revisions name `--supersedes-ruling-id`; a real human
judgment additionally names `--human-action-id` and `--confirm-human-action`.

`operator-selection.json` follows closed `ManualExportConfig`:

| Required field | Operator input |
|---|---|
| `evidence_files` | Exact claim ID to existing evidence-bundle path, using portable relative `/` paths from the selection file's directory; include every claim in retained ruling history |
| `ruling_ids` | Exact manual claim ID to explicitly selected latest ruling ID |
| `operator_id`, `action_id`, `recorded_at`, `adjudication_rationale` | Each explicit null for agent proposals; all real, nonblank action fields for a human gold release |

Default export writes preliminary `agent-proposals.jsonl`, preserving pending
coverage/history and never upgrading an agent inventory to human status. Human
gold is a separate future operator operation: use an actual complete human manual
inventory and human rulings, provide actual export action fields/rationale, and
explicitly pass both `--human-gold` and `--confirm-human-action`. The service requires
one latest human selection per manual claim and preserves competing judgments/
disagreements. It emits `gold.jsonl` only after these checks; no such artifact or
human action was created during construction. Both exports preserve full history
and evidence with a final `EXPORT.json`; neither certifies heldout admission,
custody, independent human review or measured comparative quality.

For a descriptive check of candidate omissions, the service API
`evaluation.annotation.audit_manual_omissions(snapshot_root, annotation_path,
candidate_inventory_path, out)` compares against the independently authored manual
denominator and retains pending coverage. It does not define manual atoms from
the candidate list, perform review, or create a complete benchmark result.

The existing report-based package is **assisted review**. It is useful for inspecting
machine-proposed atoms and evidence, and cannot substitute for source-first manual
inventory or independent heldout authoring:

```console
uv run claim-auditor annotation-package --run results-local/audit-001 --family-id dev-example --out results-local/assisted-review-001
uv run claim-auditor rulings-import --ledger results-local/rulings.jsonl --input operator-rulings.jsonl
uv run claim-auditor rulings-export --ledger results-local/rulings.jsonl --out results-local/rulings-export-001.jsonl
```

Packages contain source and blank review instructions, not prepopulated human
judgments. Ruling imports preserve history/disagreements and reject changed bindings.
A real human action additionally requires explicit IDs/dates and
`--confirm-human-action`; a switch or string cannot prove that review happened.
Agent judgments remain agent judgments. Ruling export is full history, not consensus
or scorer-ready human gold. No corpus custody or human benchmark is created here.

## Exit meanings and safe continuation

| Exit | Meaning |
|---|---|
| 0 | Requested local source/artifact operation completed; no product acceptance implied |
| 2 | Invalid arguments/input/setup; inspect the structured error |
| 3 | Incomplete audit, unresolved liability, or intentionally incomplete fake/replay comparison |
| 4 | Integrity/citation/pinned-identity failure; preserve the artifacts |
| 5 | Complete audit hit explicitly requested `--fail-on missing` |

Input/integrity/incomplete audit errors take precedence over `--fail-on missing`.
`paired-run` and `paired-score` deliberately return 3 even when source-only assembly
finishes. Inspect retained error/failure rows rather than interpreting a zero score
or empty output as success. Do not delete budget locks/pending reservations to
recover, reuse output paths, or enable live calls to make an example look complete.
Actual runtime tests, human/live evaluation, workflow source/execution and independent
product acceptance remain separate future work.
