# Public development evaluation

These reviewer-authored controls use synthetic public inputs. They do not open a
holdout, call a provider, create human gold, or claim comparative acceptance.

From the repository root with the installed Python 3.12 package:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_evaluation_public_controls -v
.\.venv\Scripts\python.exe -m evals.dev_controls --out <fresh-output-directory>
.\.venv\Scripts\python.exe -m evals.offline_e2e --out <another-fresh-directory>
```

The scorer controls independently specify the arithmetic for false accusations,
false reassurance, abstention and omissions. All-unknown and all-missing controls
must fail the development quality gate. Generated JSONL labels explicitly identify
their agent author and synthetic provenance. Synthetic citation fields are scorer
inputs, not claims that a real resolver validated those pointers.

The e2e runner invokes the installed CLI in isolated Python subprocesses. It runs
the owned offline demo, verifies the closed report, mutates only that invocation's
frozen README, then requires integrity exit 4. It preserves outputs and stdout/stderr.
Its output is intentionally damaged after the final check; do not present it as an
intact report. No project files are changed or removed.

Live extraction, live single-pass, human adjudication, heldout evaluation and an
actual GitHub Action remain not measured. Passing these controls is engineering
evidence only, subject to independent review and INT acceptance.

The Dockerfile pins Python 3.12.13 by image digest and uses the exact runtime/build
versions in `docker-requirements.txt`. `.dockerignore` admits only source, packaging
metadata and these public controls. No credential files, Git metadata or transcripts
are included. Start a container only after the assigned M2 agent-ports claim/check
passes. Use the printed labels, the assigned `m2-r03-rv2-*` name, no published ports,
`--network none`, a read-only root and an M2-owned output bind mount at `/results`.
Preserve the stopped container and artifacts. A Dockerfile alone is not execution
evidence; the R03 ledger conflict currently blocks that run.
