# Closed multi-family dataset evaluation

Status: source construction only. No function in this module has been invoked, no gold was opened and no scores or study outputs were generated during Dirty Mode. Runtime, human/live/heldout comparison and product acceptance remain unverified. The twelve disclosed DEV families/120 authored statements are unannotated source, not a measured benchmark.

`evaluation.dataset` is a consumer of the canonical `verify_paired`, `score_rows`, `summarize_attempts` and existing whole-family bootstrap. It adds dataset identity/closure coordination and summary rendering, not another verifier, matcher, scoring formula, ledger, provider or bootstrap implementation. D4 owns the central `DatasetCase`/`DatasetManifest` schemas and CLI. D5 owns the source runner/verifier/scorer and metric definitions; dataset code preserves their results.

## Closure before labels

`preflight_dataset` verifies the external dataset-manifest byte pin, exact installed code/taxonomy/matcher/packet/runner/parser identities, required methods and study model/prompt/cap declarations. It rejects duplicate case IDs, family IDs, ancestry clusters, snapshots, content identities or closed-run manifests. This first version uses one representative per declared ancestor; variants are separate studies, never silently dropped cases or extra independent families. True ancestry is an operator/curator responsibility, not inferable from names or hashes.

Then it calls D5's canonical `verify_paired` for **every** declared case with the case's external closed-run digest, reopens the source Snapshot through the existing source authority, and checks cross-case source/content/protocol bindings. Four equal-packet roles plus separate full-index utility must be present. Failed, screened, invalid and incomplete arms remain required recorded outcomes rather than disappearing. Locked studies require explicit prior admission, actual human review receipt and exact copied per-case protocol with matching rights/custody/source/later-gold pins. Receipt strings and flags cannot prove the actual controls were effective.

Only after the entire preflight succeeds can `evaluate_dataset` open any gold file. Preflight does not stat/follow/open the label paths; it checks only their lexical separation from inference/source/control trees and from each other. Canonical ordinary-file readers reject symlink/reparse paths when actual reads occur. Paths are operator-supplied local paths, with no URL/traversal/UNC expansion. Actual external custody and no-leakage staffing remain required; naming separation alone cannot establish blindness or detect semantic labels concealed in arbitrary source.

Every opened GoldAtom file must match its separately pinned exact byte digest, declared source/README/family and exact reopened spans. Invalid, blank, empty, duplicated/conflicting or foreign rows refuse, not drop. Gold remains bounded to the existing atom policy per case, 10 MiB per file, 32 MiB total; at most 48 cases. Changed input manifest during scoring refuses. Scoring outputs must be fresh and outside every source/inference directory.

## Metrics and denominators

All cases' atoms and predictions are supplied together to the existing scorer per method. Case-local IDs are namespaced for traceability; original IDs remain in item metadata. Family IDs are remapped only within scoring to the declared ancestry cluster, and the original family/case mapping remains explicit. Whole-family intervals therefore use whole ancestry clusters with the existing bootstrap defaults, not renamed variants or individual atoms. Small/undefined intervals stay exploratory/inconclusive. Each dataset already rejects repeated ancestors; no case is resampled as an independent alias of its sibling.

The existing scorer produces the four-way confusion matrices, all-atom omissions/extras/ambiguities/failure rows, extraction by kind, accusation/reassurance errors and unknown appropriateness/overuse. Dataset tables are generated from these records and the original method rows; headline averages across cases are not substituted for all-atom scoring. Per-family/per-kind slices use the same scorer without intervals. Generic case-level failures are retained in per-kind diagnostic slices, making slices nonadditive; never sum those slices into totals.

Observed attempts pass through `summarize_attempts`, preserving unknown token/cost/latency fields and known subtotals. No-attempt summaries are absent/undefined, not invented zeros. Typed nullable live usage and separately simulated fixture usage remain visible per case/method; simulation is never added to observed usage. Required arm names containing `live` do not prove a real provider ran. Genuine live-protocol/attempt origins must be present before those prerequisites can be considered observed, while screened/failed cases stay in the denominators.

All four equal-packet methods are compared in their own panel. `product_full_index` is a distinct utility panel with privileged evidence; its results cannot stand in for a fair packet-limited improvement claim.

## Targets and incomplete acceptance

The promoted predeclared DEV target gate stays with `scoring.score_rows`: its actual `counts.dev_targets_met`, metric values and undefined denominators are reported rather than reimplemented. The promoted plan additionally requires 12 independent families/120 gold atoms, 30 defects/nondefects, 15 items per reported kind, actual human review, required live extraction/single-pass comparison and the real admission/custody protocol. Candidate accusation precision must not fall below grep; the summary reports that comparison from existing metric values, or undefined when either denominator is absent. Quality/cost interpretation against the simpler single-pass baseline remains independent work.

The implementation always reports comparative acceptance incomplete and does not certify human adjudication, custody or product acceptance. Human-attribution field completeness is reported separately from independently verified human work. DEV mocks, unadmitted templates, zero/insufficient denominators, unsupported provenance, absent actual live origins and unknown cost/latency remain explicit inconclusive conditions. D5/INT's settled extraction-target policy preserves all-atom metrics and gates extraction targets on the supported-kind slice through the same scorer/matcher. This consumer reports that authority's returned metrics/gate and does not implement another formula. Actual future independent evaluation must freeze the settled gate before locking, never tune it after heldout visibility.

## Dormant public API and reproduction

- `preflight_dataset(manifest_path: Path, *, manifest_digest: str) -> dict[str, Any]` returns canonical verified case payloads with `gold_opened=False`; it is not an admission token. Passing its returned object cannot bypass a later preflight.
- `evaluate_dataset(manifest_path: Path, out: Path, *, manifest_digest: str) -> dict[str, EvaluationResult]` performs its own complete preflight, opens pinned labels only afterward, invokes the existing scorer and writes a fresh descriptive output.
- `render_dataset_markdown(summary: dict[str, Any]) -> str` renders existing item/metric/interval records as escaped static Markdown; it computes no alternate metrics and does not type in example results.

After execution is authorized and actual independent source/label staffing exists: fill the [unadmitted templates](../config/corpus-evaluation/README.md) in private operator storage; freeze exact tool/dependency/prompt/model/cap/protocol/ancestry/source/run pins before label visibility; execute and close all required source-only inference cases through D5; retain the external dataset manifest digest; call preflight; then explicitly call evaluation to a new output directory. These are proposed future operations, not commands that ran. CLI wiring belongs to D4 and must follow these exact signatures.

D4's source now wires these future invocations; they have not been executed:

```text
claim-auditor dataset-score --manifest <operator-manifest.json> --manifest-digest <exact-byte-sha256> --preflight
claim-auditor dataset-score --manifest <operator-manifest.json> --manifest-digest <same-exact-byte-sha256> --out <fresh-output-directory>
```

The preflight-only CLI prints a compact closure status without serializing its internal verified payloads or creating scores. The scoring CLI preserves the explicit nonacceptance exit/status behavior; an output is not independent product/custody acceptance.

Successful descriptive output contains `SUMMARY.json`, every `items.json` row, the original byte-exact `manifest-copy.json`, escaped `summary.md` tables and last-written `DATASET.json` artifact hashes. Summaries include per-method confusion/counts/metrics/intervals, per-family/per-kind slices, named item/error rows, original support relations/predicate partitions, usage origins/missingness, all case pins and inconclusive target conditions. No manually written benchmark output is supplied. The marker says closed descriptive/unaccepted, never a human/live/product acceptance certificate.

Input preflight refusals leave original manifests/runs untouched and raise explicit errors before gold. Failures after a fresh output is created leave a `FAILED.json` phase/reason when writable, preserve all partial artifacts and re-raise; no cleanup or favorable-case retry occurs. A partial directory without final `DATASET.json` is not a completed output. Preserve failed studies and disagreements; never replace a failed study with a filtered manifest under the same frozen identity.
A case whose paired run closed as a genuine `failed_input` verifies as a failure-only closure and stays visible in the denominators instead of aborting the study; a changed pinned artifact does not. Changed pinned dataset artifacts (`dataset_manifest_changed`, `dataset_source_changed`, `dataset_protocol_changed`, `dataset_gold_changed`) are integrity failures (exit 4); case identity/protocol/scope schema refusals stay input (exit 2). Constructed source only; not executed.

Future normal-mode validation must exercise late-case closure failure with a sentinel ensuring no earlier gold was opened, altered run/source/protocol/model/cap pins, duplicate ancestry/content/atoms, missing required arms, screened/provider failures and omissions, multiple-family bootstrap grouping, unknown-versus-simulated usage, stale manifest during scoring, fresh-output refusal and inert Markdown fields. No such runtime/testing/scoring operation occurred here.
