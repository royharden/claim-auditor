# Claim Auditor

Claim Auditor inventories bounded README assertions and compares supported Python
static propositions with an immutable local source snapshot. Findings retain exact
README byte spans, evidence or replayable search coverage, and one of
`verified`, `partial`, `missing`, or `unknown`.

**Construction baseline — runtime unverified.** Dependencies have not been
installed or locked (`uv.lock` is not yet present), the CLI/demo has not run, and no tests or GitHub Actions have
run. Human-adjudicated evaluation is not measured; comparative acceptance is
incomplete. Live provider calls are disabled.

CA10 GitHub workflow source and execution are deferred until Dirty Mode closes;
no CI or deployment scaffolding is included in this construction baseline.

## Later local activation

Python 3.12+ and uv are intended. After authorized runtime activation, resolve and
review dependencies and generate `uv.lock`, then use the following commands. These
are intended instructions, not evidence that they have succeeded:

```console
uv sync
uv run claim-auditor demo --offline --out results-local/demo-001
uv run claim-auditor verify-report results-local/demo-001/run
```

The demo creates owned source containing a declared function, an invented API and
an operational claim. Verdicts are generated through snapshot, inventory, index,
policy, citation and report services; no prerecorded verdict output is shipped.
Actual evidence and coverage are stored alongside `report.json`, Markdown and
escaped static HTML. A later tamper exercise must show integrity refusal.

For an existing complete local Git object store, supply a full object ID:

```console
uv run claim-auditor snapshot --repo /path/to/local-repo --commit FULL_OBJECT_ID --out results-local/snapshot-001
uv run claim-auditor audit --snapshot results-local/snapshot-001 --readme README.md --mode rules --out results-local/audit-001
uv run claim-auditor verify-report results-local/audit-001
```

No target code or README commands are run. Worktree indirection, archives, shallow
or alternate/promisor object stores are outside the supported acquisition boundary;
an ordinary owned fixture source is also accepted with `snapshot --fixture PATH`.
Every output path must be new. CLI errors use nonzero status; a complete report
does not mean the repository is correct.

## Architecture

- `contracts`: strict wire records and source-derived identity helpers.
- `snapshot`, `index`, `patterns`: frozen bytes and bounded static propositions.
- `inventory`: CommonMark block accounting and exact original-byte claims.
- `citations`: sole span/coverage reopening and report-integrity service.
- `audit`: deterministic negation-aware verdict reduction and run lifecycle.
- `report`: local JSON/JSONL, Markdown and inert HTML; owned demo inputs.
- `evaluation`: source-only packet preparation, one-to-one matching and scorer.
- `providers`, `screen`, `accounting`: explicit replay/disabled-live boundary,
  conservative model-input hold and bounded durable reservation port.

## Evidence and measurement

Rules mode uses no model. Replay is explicitly identified and does not become a
live result. No external provider spend occurred during construction; future live
cost and usage are unknown, not a zero-cost claim.

| Required evidence | Current status |
|---|---|
| Snapshot → audit → report and tamper execution | Not run |
| Hostile-input/resource/no-execution checks | Not run |
| Independent corpus and actual human labels | Not measured / not staffed |
| Packet grep/path and deterministic comparison | Not measured |
| Live extraction and single-pass LLM comparison | Not measured; live disabled |
| Exact-revision GitHub Action report artifact | Action not yet run |
| Independent nonauthoring product acceptance | Pending |

Scoring uses separately supplied labels after inference closes. Agent labels are
never human gold. An admitted evaluation protocol must freeze source/label custody,
rights, matcher, taxonomy, packets, code, providers and shared caps before heldout
access. No committed headline quality number is present.

## Limits

Static declaration is not importability, runtime availability or behavior. The
supported taxonomy covers exact paths, syntactic declarations, literal metadata,
dependency/script declarations, literal environment references and named bounded
code patterns. Operational, behavioral and marketing propositions remain unknown.
Incomplete scope cannot justify an absence accusation. See
[contracts](docs/contracts.md), [threat model](docs/threat-model.md), and
[limitations](docs/LIMITATIONS.md).

This source was authored by coding agents under explicit static-only Dirty Mode.
Focused source inspection and syntax parsing are the only permitted checks for
this phase. Nothing has been pushed, published, deployed or connected to real
accounts. MIT licensed; no third-party project code was vendored.
