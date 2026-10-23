# Offline demonstration

Construction status: source written; the commands below have **not been run** in Dirty Mode. They are the intended activation sequence after dependency setup and normal validation are authorized.

From the outer shell, the installed CLI will support:

```powershell
claim-auditor demo --offline --out <new-run-directory>
claim-auditor verify-report <new-run-directory>
```

The demo creates a new owned source directory with a declared function, an invented function and a throughput claim. It snapshots those bytes and calls the same inventory, index, deterministic policy, citation and report path as a normal audit. It contains no prewritten verdict output. Agent-authored source is development input, never human gold.

Open the generated `report.html` or `report.md` locally. The intended walkthrough is to inspect the precise declared-function proposition, its frozen source excerpt, the invented name's bounded absence coverage, and the operational statement's unknown reason. These are scoped static statements; a function declaration does not establish importability or runtime behavior.

After normal mode resumes, make a separate disposable copy of the generated run, alter one source byte under its `snapshot/files/`, then invoke `verify-report` on that copy. Integrity verification should refuse it. This tamper check remains unexecuted.

Every report says **runtime unverified**, **human-adjudicated evaluation not measured**, **comparative acceptance incomplete**, and **Action not yet run**. An offline demo never satisfies the required actual human/live benchmark or actual GitHub Action artifact.

Reports contain local source and excerpts. Keep them private unless separately authorized for publication. HTML is generated with escaped text, no script, no remote resources and no README-originated active links.
