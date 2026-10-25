# Trusted offline workflow source

CA10 supplies local workflow source only. **Action not_run**: no push, workflow
dispatch, upload, run URL or platform artifact has been produced by this package.
Local simulation and lint cannot satisfy M2-05. Human/live comparisons and full
product acceptance remain separate requirements.

## Execution and trust boundaries

`.github/workflows/claim-audit.yml` defines `self-audit` and `fixture-audit` on
Ubuntu 24.04. Push triggers are restricted to `main`; manual dispatch must also
select `main` and the actor must equal the repository owner. PR and fork triggers
are absent. Both workflow and jobs grant only `contents: read`. No environment,
deployment, model key, write token, user-supplied command, cache, or target-side
installation is configured.

The workflow glue is checked out at `github.workflow_sha`, a revision distinct
from the requested target SHA. A second checkout installs the trusted tool at the
literal full commit `c33655fb57dd6fbde310377173efb0e589ef534a`. Its own `uv.lock`
and two-stage `scripts/bootstrap.sh` install CPython 3.12.13, the locked build
backend, and exact runtime packages. The helper checks observed tool HEAD and
the installed package's origin before running the CLI. Neither Python imports nor
dependency installation use the target directory. Checkout credentials are not
persisted, and LFS/submodules are disabled in both trusted checkouts.

The target is always this GitHub repository. A dispatch may choose only a full
lowercase SHA1; otherwise the target is `github.sha`. The helper's `fetch` command
initializes a fresh `.git` object store under a separate target directory using an
empty template. It fetches the exact commit without depth/filter/submodule options
and without a checkout. No target hooks, scripts, Git attributes, filters, package
metadata or dependency installation are executed. Git global/system configuration,
inherited Git injection and credential helpers are disabled. Only this future
fetch step receives the runner's built-in read-only token, through process-local
configuration; it is never written to a credential/config file or passed to the
audit step. Fetch failures, a 120-second limit, or a store exceeding 500 MiB stop
the job. Store monitoring is periodic, not a hard filesystem quota.

The canonical isolated `snapshot --repo --commit` reader validates target content,
object IDs, completeness and its own bounds. Local audit does not run even
`rev-parse` against target-controlled configuration. Target checkout HEAD is not
the semantic authority: the requested immutable object and resulting snapshot
commit must agree. The workflow's own fresh fetch also checks its fetched HEAD.
Tool, target and output directories must be physically disjoint; shallow stores,
bad identities, links and reused output refuse before completion.

Before every helper Git launch, the executable is resolved from an absolute PATH
entry and compared with the physical target directory. Executables inside the
target, including its `.git` store, are excluded even through PATH junctions or
Windows 8.3 aliases. The fetch helper applies the same check against its entire
new output directory for setup, transfer and identity reads. Installed Git outside
the target remains eligible; no eligible executable is a setup refusal. This
executable check occurs before the canonical target snapshot admission and does
not read target Git configuration.

## Local helper interface

Run the helper using the trusted tool environment's Python with `-I`:

```text
workflow_audit.py audit --mode self|fixture --tool-root TRUSTED_TOOL
  --tool-revision FULL_TOOL_SHA --workflow-revision FULL_WORKFLOW_SHA
  --trigger-revision FULL_TRIGGER_SHA --trigger-kind push|workflow_dispatch
  --repository OWNER/REPO --run-id POSITIVE_INTEGER
  --target-repo LOCAL_TARGET --target-sha FULL_TARGET_SHA --out NEW_DIRECTORY
```

`fetch --repository OWNER/REPO --target-sha FULL_SHA --out NEW_DIRECTORY` is a
separate future network-acquisition command. It is not used by local validation.
No generic remote URL, SSH path, credential file or arbitrary fixture path is
accepted. In fixture mode the fixed disclosed source is
`fixtures/corpus-dev/ledger-cli/source` from the trusted tool revision. Its snapshot
is `fixture_inventory`, with a null Git commit; it never impersonates the trigger
or requested target. The requested target is separately admitted through the
canonical Git snapshot command, including in fixture mode.

Both modes invoke existing snapshot, rules audit, verify-report, pinned
export-report and exported-copy verify-report authorities. No replacement report
validator is introduced. Exit 0 means those steps completed; input/setup, incomplete
and integrity failures retain exits 2/3/4. A refusal stops the job and prevents the
upload step. Missing prerequisites and excluded/sensitive source cannot silently
become clean reports.

## Artifact and identity contract

Output contains local diagnostics, acquisition snapshots, declarations and a run.
Only `OUT/artifact/` is selected for upload: `report-export/` is the canonical
selected complete report/source closure, and `workflow-receipt.json` binds its file
hashes, raw RUN digest, tool/workflow/trigger/requested-target identities and actual
snapshot kind/commit/manifest. Neither the whole checkout, `.git`, `.venv`, target
store nor diagnostics is uploaded. Hidden files are included within this exact
verified export so an allowed frozen evidence file cannot be silently omitted.
The canonical export's sensitive-path refusal remains active.

Retention is explicitly seven days; missing upload input is an error. The upload
action's platform ZIP digest is recorded separately in the job summary. It is not
confused with the raw RUN or per-file digests. Workflow metadata supplied to the
helper remains declared context: a local fake run number or URL is not Action
execution proof. The helper labels execution `not_observed_by_helper`; the actual
platform run and artifact are future evidence. Reports may contain private source;
source-only approval here grants no publication or Action execution authority.

## Dependency provenance and activation limits

Full commits resolved from official public GitHub refs on 2026-10-25; the annotated
setup-uv tag was peeled to its commit. The action definitions and relevant input,
Git-acquisition, checksum and selected-upload source were inspected. This is bounded
vendor-source inspection, not an exhaustive action security audit.

| Action | Full immutable commit | Inspected action.yml SHA256 |
| --- | --- | --- |
| actions/checkout v4 | `11d5960a326750d5838078e36cf38b85af677262` | `6188f6991491ed38977347cdaad0b0cd921a6d6232892363c91f433c22954f4f` |
| astral-sh/setup-uv v6 | `d0cc045d04ccac9d8b7881df0226f9e82c39688e` | `b7e64add830d513ed49b8cadba8c75138eb45e0ff3dbf95bd687cc250b761444` |
| actions/upload-artifact v4 | `ea165f8d65b6e75b540449e92b4886f43607fa02` | `29b21270ff44638a165ea12abb4481796770c629e513217af7b4df1aa3821177` |

uv 0.11.29's Linux x86-64 GNU archive checksum is pinned to
`04f8b82f5d47f0512dcd32c67a4a6f16a0ea27c81537c338fd0ad6b23cebe829`.
The OS runner image and Python distributor remain platform dependencies; no
immutable runner-image or supply-chain proof is claimed.

Before a separately authorized real run, reconcile the literal tool revision to
the final accepted source/lock, verify that revision is available in the eventual
repository, reconcile the workflow revision, and obtain independent affected
checks. The pinned local tool commit is not claimed to exist on GitHub.
The self-audit must satisfy normal resource and sensitive-export limits; a refused
self-audit is a failure to address, never a reason to drop evidence or bypass
export protections.

Primary references:
[GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use),
[checkout source](https://github.com/actions/checkout/tree/11d5960a326750d5838078e36cf38b85af677262),
[setup-uv source](https://github.com/astral-sh/setup-uv/tree/d0cc045d04ccac9d8b7881df0226f9e82c39688e),
[upload-artifact source](https://github.com/actions/upload-artifact/tree/ea165f8d65b6e75b540449e92b4886f43607fa02).
