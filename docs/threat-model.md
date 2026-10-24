# No-execution boundary and unverified controls

Untrusted README/source bytes are data. No target import, build, test, script,
README command, URL, hook or model instruction is executed. Acquisition permits
only reviewed installed Git operations and parser workers; no shell interpolation,
network acquisition or generic file/URL opener exists. Snapshot, evidence and run
outputs are local and can contain private source. Publication is outside this tool.

Path handling rejects traversal, absolute paths, casefold collisions, Windows
reserved names and links/reparse points. Source reopening binds raw bytes to the
manifest. Snapshot isolation prevents a changed checkout from changing citations.
Coverage replay binds exact query and examined bytes; incomplete parsing cannot
prove absence. Reports escape source/README content and include no active README
HTML or remote resource. Invalid evidence is suppressed and fails run integrity.

Local Git ingestion isolates target objects from target configuration, hooks,
attributes, refs and inherited Git environment. Shallow/alternate/promisor stores
and worktree indirection are unsupported. Blob size/entry/stream/deadline caps and
parser time/memory enforcement must be real at execution; missing enforcement
must fail setup rather than silently allow unbounded hostile parsing. An individual
source file or blob over the per-file cap is recorded as unread excluded scope
(snapshot incomplete, no absence claim); the aggregate text and compressed-copy caps
still abort the snapshot. Every Git commit, tree and blob object read is
hash-verified against its object ID, and the file list comes from walking verified
trees from the verified commit, so a tampered object store fails with
`git_object_hash_mismatch` (4). Git itself is resolved only from absolute PATH
entries, never the working directory, and on Windows only as `git.exe`.

Output display: CLI terminal JSON is ASCII-only, and report Markdown/HTML escape
source text and neutralize line-leading `::` (including after Unicode whitespace)
for display. JSON/JSONL artifacts remain byte-exact data, not terminal-safe text.
Do not print reports or artifacts into CI/workflow logs; publish them as uploaded
files. Parser memory/time enforcement is unavailable on macOS, so the worker
reports `enforced: false` and indexing refuses with `parser_enforcement_unavailable`
(2); macOS is unsupported for hostile input.

Live calls are absent from this construction baseline. Screening is a conservative
input hold, not prompt-injection isolation or semantic proof. The durable accounting
port reserves worst-case shared liability before a future call, permits one active
reservation and blocks further calls when settlement is unknown. No SDK/hidden
retry path is enabled or claimed tested.

Construction uses static checks only. Malicious-config/filter/hook/import-shadowing
sentinels, path-replacement races, resource enforcement, Windows behavior and
tamper/coverage reopening still need runtime validation after Dirty Mode closes.
No security certification or broad runtime correctness claim is made.
