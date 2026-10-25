# Local offline validation

PB-M2-R03, 2026-10-25, Windows PowerShell. This record covers a local engineering
journey, not product acceptance or a benchmark. Base: `a01685e12646f56d56eb1385998176abfd09137b`.
The report display repair is locally exercised with independently authored controls.

The isolated D11 environment uses CPython 3.12.13, Pydantic 2.14.1,
markdown-it-py 4.2.0 and an editable install of this checkout. Runtime dependencies
were exported from D8's provisional lock and installed with required hashes.
Final packaging/build conformance belongs to the separate environment candidate.

Executed local journey:

- `claim-auditor demo --offline --out NEW_DEMO`: exit 0, complete, no pipeline errors.
- `claim-auditor verify-report NEW_DEMO/run`: exit 0.
- `claim-auditor export-report --run NEW_DEMO/run --manifest-digest RETAINED_SHA256 --out NEW_EXPORT`: exit 0.
- `claim-auditor verify-report NEW_EXPORT/run`: exit 0.

Six generated findings comprise two verified declarations/default facts, two missing
invented/contrary facts, and two unknown operational/behavioral assertions. These
owned engineering inputs are not independent gold or a measured accuracy sample.
The independently retained raw `RUN.json` SHA256 is
`1512f3bdf9d51a77c68590b5ba416d48d8f258268144f48e00ee10832030732c`.
The observed tool-byte digest is
`35df5d9699e5fe0caee814471a0424b51aa66fbdc100dd83c0bf0af0e84c48bc`.

Reviewer-authored workflow display controls: three tests passed locally against
the repair. The legacy runner parser searches for `##[` anywhere in a line;
display therefore breaks the delimiter itself. A leading backslash alone would
leave it recognizable. Modern line-leading `::` commands, controls, fences and
HTML escaping retain their existing protections. Raw JSON, quoted evidence,
snapshot bytes and digest methods are unchanged. Parser reference:
[Actions runner ActionCommand.cs](https://github.com/actions/runner/blob/main/src/Runner.Common/ActionCommand.cs).

The initial focused suite ran 23 tests with zero assertion failures, 11 errors
and zero skips. Errors arose in the inherited Windows snapshot ancestor checks
(`ancestor_changed_during_read`) while using shared temporary directories. The
snapshot owner and RV1 received the original log. A diagnostic repeat using a
lane-local temporary directory passed all 23 tests with zero failures, errors or
skips. No snapshot guard was patched or bypassed. A copied exported source was
then modified; `verify-report` refused it with integrity exit 4. The ordinary
shared-temp failure remains an open dependency;
a local passing journey does not waive it. The High-effort implementation check passed three display tests. Independent
review of the exact display candidate and ordinary-path snapshot reconciliation
remain required.

Tool code identity hashes exact installed Python bytes using
`trusted-package-py-sha256/1`. A checkout with different bytes can legitimately
have a different identity. All 45 trusted Python files in this D11 checkout used
LF when inspected. After changing tool bytes or rebuilding a checkout, generate
fresh runs and retain their actual manifest pins; do not normalize old hashes or
relabel old artifacts as new executions. Frozen target/source bytes remain exact.

Human-adjudicated evaluation, sealed heldout custody, live extraction/single-pass
comparisons, actual GitHub Action execution and independent full-product acceptance
remain incomplete. No paid calls, credentials, Docker resources, listening servers,
push or publication were used for this journey. Original failing and successful
artifacts are retained in the agent handoff, outside committed product files.
