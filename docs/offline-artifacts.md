# Local offline report/evidence handoff

Status: source construction only. No export, archive, report verification, worker, code-digest helper, metadata receipt or reopening/tamper test has been executed during Dirty Mode. This module prepares a later local operation; no bundle or passing export example is supplied here.

`claim_auditor.report.export.export_report(run_root: Path, out: Path, *, manifest_digest: str) -> dict[str, Any]` copies one complete, externally pinned audit run into a fresh directory. It reuses the sole `citations.verify_report` service and existing strict run context. The returned dictionary is export bookkeeping, not another run schema, verifier, origin/custody certificate or publication permission. D4 owns CLI integration and D6 owns future test source.

## Input and selection

The caller must retain an independently trusted, full lowercase SHA256 of the exact input `RUN.json` bytes. Reading a replacement file's own hash back into the same operation does not establish origin. The exporter checks that external pin before canonical verification, keeps original completeness/integrity refusals and requires a fresh, ordinary, nonoverlapping local destination. Traversal, UNC paths, symlinks/reparse points, stale output and copied targets inside the trusted tool package refuse.

Selection comes from the pinned canonical RunManifest artifact inventory and Snapshot entries, never a general directory copy. It preserves:

- Original byte-exact RUN.json and all eleven current report/inventory/claim/finding/evidence/coverage/prediction/Markdown/HTML/context artifacts from the canonical inventory.
- Original `snapshot/manifest.json`, including source identities, scope gaps and excluded/unavailable entry metadata.
- Every included frozen `snapshot/files/<path>` byte needed by the existing snapshot/citation/query/policy replay authority. It does not choose a favorable subset of cited excerpts or silently drop private required source.

An inventory-derived directory name/type audit rejects missing or extra objects without selecting files by a walk. Unknown manifest artifacts are nonexportable until the selection policy is reviewed, and are not opened or silently ignored. Agent coordination records, backups, owner authorization/budget/ledger data and unrelated files are outside the allowed closure. Known credential/private-agent paths in required source refuse the **whole export**, rather than producing an incomplete bundle advertised as complete. Excluded source stays metadata-only; it is not promoted to included coverage.

Known sensitive filename checks are conservative selection policy, not a content secret detector. Ordinary source implementations such as a ledger module remain source code; known key/credential files and JSON/YAML/etc authorization/ledger records refuse. Declared `.env.example`/sample/template source names can be included, but the name does not prove the contents safe. The operator must review actual rights, private data and source contents before any later transfer. The source can remain private even when no known sensitive name is present. Local export grants no publication or external-data-transfer permission.

The existing canonical verifier remains the report-validity authority. This module adds a narrower copy policy over its inventory; it does not recalculate findings, evidence or context provenance. Incomplete/invalid reports do not become valid through export, unknown context never gets backfilled, and mismatched historical tool source is not relabeled current. Use the corresponding trusted tool installation or a separately authorized fresh audit when genuine regeneration is needed.

## Output and closure

```text
fresh-out/
  run/
    RUN.json
    context.json
    context.jsonl
    report.json, report.md, report.html
    inventory.json
    claims.jsonl, findings.jsonl, evidence.jsonl, coverage.jsonl, predictions.jsonl
    snapshot/
      manifest.json
      files/<all included frozen source paths>
  EXPORT.json
```

Relative report/evidence relationships and original hashes are preserved. Copied source stays data; export neither executes/imports it nor opens a browser. The offline reopening entrypoint remains `verify_report(fresh_out / "run")`; no competing export verifier is introduced. The HTML/CSP and Markdown content remain the original byte-exact inert outputs verified by that service. The bundle contains evidence, not an installed Python/tool environment; canonical reopening still needs the corresponding trusted tool and dependencies, without a network fallback.

Before copying, the source must pass its canonical verifier and manifest-byte recheck. Copying uses selected ordinary-file readers and exclusive new-file writes; every copied byte is checked against its pinned source hash/size. Original selected bytes are checked again after copying, the copy is reopened through the canonical verifier, and copied inventory/bytes are checked again before final bookkeeping. Because the copy is tool-written and sealed, a missing copied `RUN.json` during that reopening is reported as `export_copy_identity` (integrity, exit 4), not the operator-input `run_not_found` (2). The exporter never rewrites RUN.json, report context, findings or a declared Git/workflow identity to make a stale bundle pass.

`EXPORT.json` is written last and returned as a dictionary. It records input manifest pin, `run_relative_path="run"`, run/context/snapshot identities, every output-relative path/size/SHA256, total bytes and a content-derived export ID. It explicitly states local-copy/unpublished, unverified origin/custody/runtime, no observed workflow execution and no publication authorization. Its hashes prove consistency with the selected local bytes, not who generated the original run, that a GitHub Action occurred or that rights/access controls were effective.

Bounds: the existing source entry/file limits, at most source-entry cap plus 32 files, at most 128 MiB selected copy data, existing 64 MiB report/4 MiB manifest/128 KiB context read caps. Exceeding a bound refuses the full operation; required source is never truncated or omitted. Output parent must already exist as an ordinary operator-owned directory. No ACL provisioning, archive compression, upload, remote resource, provider, Git command or key lookup is supplied.

## Failure and later use

A preflight failure creates no export directory. After copying begins, failures re-raise the original error and preserve the fresh partial directory; a best-effort `FAILED.json` records phase-independent incomplete state and copied path names, never success. It overrides any incomplete/export marker: do not hand off an output with FAILED.json, truncated metadata or an unsuccessful call. Files are never overwritten, deleted or repaired in place. Retry to a different fresh output after resolving the source problem. No crash/host-filesystem durability guarantee has been demonstrated; directory races and interruption/fsync behavior need actual later validation.

After actual execution is authorized: choose the complete local audit and independently retained input manifest pin; review the selected source/private-data scope; call `export_report` to a fresh private folder; retain its returned bookkeeping and verify the copied `run/` with the same canonical tool. Preserve the original run and external pin. This describes future operations, not commands that ran in this source phase. D4's CLI consumer must require input run, external `--manifest-digest` and fresh `--out`; source changes here do not themselves authorize invoking it.

Later normal-mode checks must exercise incorrect external pin, canonical incomplete/context/citation refusal, extra root/source objects, sensitive/agent/owner records, missing required private source, symlink/reparse/traversal/overlap refusal, source mutation during copying, copied-byte mutation, empty JSONL preservation, stale destination, interrupted/partial output and exact offline reopening. Export/reopening tests, actual Action artifact/upload receipts, human/live comparisons and independent product acceptance remain unperformed.
