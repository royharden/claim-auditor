# Claim Auditor

Claim Auditor inventories bounded README assertions against an immutable local
Python source snapshot. Findings retain original byte spans, cited evidence or
replayable search coverage, and `verified`, `partial`, `missing` or `unknown`.
Static declarations do not establish runtime behavior, security or performance.

**Source construction — runtime unverified.** Dependencies are not installed or
locked, no CLI/demo/tests/benchmark has run, and no provider has been called.
Human-adjudicated comparison is unmeasured; **Action not yet run**. No public
release, upload or deployment has occurred. CI/deployment scaffolding is deferred.

## Start with the owned demo

After separately authorized runtime setup, use Python 3.12+ and a trusted installed
tool outside the audited target. Resolve/review dependencies and generate
`uv.lock` before activation; see the [operator quickstart](docs/quickstart.md).
These are future commands, not execution evidence:

```console
uv run claim-auditor demo --offline --out results-local/demo-001
uv run claim-auditor verify-report results-local/demo-001/run
```

Choose a fresh private output directory. The demo authors source, then constructs
its snapshot and report through the actual audit pipeline; it ships no prerecorded
findings, gold or scores. Its six authored sentences distinguish a declaration and
literal default from an invented API, contrary default and universal runtime claim.
Six sentences are not a measured extraction count or six expected verdicts.
Follow the [two-minute demo tour](docs/demo-tour.md) to inspect actual future
artifacts and explain only the evidence they contain.

## Follow the source journeys

| Purpose | Detailed guide |
|---|---|
| Freeze owned source, audit and reopen citations/context | [Operator quickstart](docs/quickstart.md), [report provenance](docs/report-provenance.md) |
| Hand off selected report evidence and frozen source locally | [Pinned offline artifacts](docs/offline-artifacts.md) |
| Review every source assertion independently of extractor omissions | [Source-first annotation](docs/annotation-guide.md) |
| Prepare disclosed DEV packets and explicit fake/replay inputs | [Quickstart](docs/quickstart.md), [provider modes](docs/provider-modes.md) |
| Understand inference closure, separate labels and case-entry limits | [Paired arms](docs/paired-arms.md), [dataset evaluation](docs/dataset-evaluation.md) |
| Review dated pricing, durable admission and explicit reconciliation | [Cost accounting](docs/cost-accounting.md) |
| Maintain the implementation and understand its boundaries | [Architecture](docs/architecture.md), [limitations](docs/LIMITATIONS.md), [construction notes](docs/release-notes.md) |

`export-report` requires an independently retained raw `RUN.json` SHA256 and fresh
output. It copies only the verified report/source closure under `run/`; copied
source may be private. Local consistency is not origin, custody or publication
permission. Optional audit/demo owner declarations remain declarations, not observed
Git, workflow or provider activity; absent provenance stays unknown.

Manual source-first inventory covers the original README independently of candidate
extraction; assisted report review is separately labeled. Agent proposals cannot
become human gold through an attribution string. DEV fixtures and fake input
configuration are not heldout evidence or measured outcomes. Fake templates contain
explicit missing-fixture failures, not passing predictions.

Plain CLI `live-experiment` and `budget-reconcile` refuse before input reads without
a trusted injected activated owner context. Config, argv, environment and target
text cannot supply that authority or credentials. Dormant adapter/HTTPS source has
not run. Reconciliation selects only the admitted root/protocol/packet/role leaf;
it settles receipt-bound liability through the existing ledger and cannot resume
an interrupted experiment. Used case history remains refused even after settlement;
do not switch roots or identities to bypass it. No current rates or populated real
receipts are supplied.

## What remains unperformed

Snapshot-to-report/tamper execution, hostile-input containment, dependency and
provider compatibility, actual human labels and independent heldout custody,
benchmark/live comparisons, cost/latency measurements and the exact-revision GitHub
Action remain unverified or unmeasured. Independent product acceptance is pending.
No quality, superiority or security guarantee follows from static source inspection.
See [limitations](docs/LIMITATIONS.md) and the [validation plan](docs/validation-plan.md).

MIT licensed; no third-party project code was vendored. Disclosed DEV source
provenance remains with its fixtures; authored inputs are not external benchmark
or human-label receipts. Normal source uses LF checkout policy; `fixtures/**` is
byte-preserving because provenance binds original bytes. No fixture renormalization
was performed; checkout/digest conformance remains unverified.
