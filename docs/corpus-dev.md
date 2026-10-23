# Authored DEV corpus

`fixtures/corpus-dev/` contains twelve original, agent-authored teaching families and 120 separately authored prose assertions. The first six families contain 52 assertions; the R02 expansion adds 68. Each `source/` directory is a separate loose repository fixture; pass only that directory to a future fixture snapshot operation. Family provenance and review prompts live outside `source/` and must not enter model packets. No product, parser, inference or scoring command was run to produce these examples.

| Family | Source structure | Review focus |
|---|---|---|
| ledger-cli | Flat CLI module plus project scripts/dependencies | Static declarations, exact version conflict, absent function, runtime portability |
| sensor-class | Class members plus dynamic module export | Qualified symbols, literal conflict, dynamic uncertainty, accuracy proxy |
| async-cache | Coroutine with default, explicit raise and environment use | Bounded code facts, negation, conditional prose, behavior abstention |
| plugin-dispatch | Two modules, handler registry and dynamic plugin lookup | Declaration versus dynamic attribute, wrong literal, reliability proxy |
| package-config | Nested package with re-export and optional dependency table | Module identity, absent declaration, packaging metadata and security proxy |
| conditional-backend | Two conditional function definitions | Dynamic scope, exact timeout, negated path, operational unknowability |
| invoice-records | Dataclass inheritance with decimal fields | Class/member declarations versus generated/inherited behavior, wrong constant, tax/uptime claims |
| retry-decorator | Higher-order decorator returning a wrapped closure | Literal decorator argument versus effective retry behavior, negation and runtime reliability |
| dispatch-types | Singledispatch with separately registered implementations | Explicit raise, type registration versus universal support, absent bytes handler |
| stream-context | Generator iteration within a context manager | Literal default versus memory/cancellation semantics and resource cleanup |
| typing-platform | TYPE_CHECKING class plus platform-guarded import | Conditional declaration/import scope, environment reference and compatibility |
| layered-settings | Nested TOML profiles with runtime-selected overlay | Declared literal versus effective profile value, optional dependencies and queue behavior |

The sources were composed separately for these structures rather than emitted from one implementation template. They share a documented claim grammar to exercise existing extraction interfaces. They are twelve proposed ancestry families, all exposed DEV material authored by the same agent; this is neither independent human authorship nor a hidden corpus. Parent/mutation ancestry and source-byte inventory are recorded in each `provenance.json`. No copied third-party code, external downloads, accounts or provider calls are used.

Each prose assertion is separate, including deliberately unsupported and conditional assertions. `review-prompts.json` lists original claims and review questions without final labels, claims of successful extraction, or measured findings. Those proposed atoms must later be reconciled against exact UTF-8 spans; the authored list is not an executed extraction artifact. Missing declarations in complete static modules and dynamic lookup cases deliberately differ: a dynamic gap must never become an absence accusation.

`coverage-map.json` records all 120 authored quotes, original README byte anchors, preliminary kind hints, ambiguity-review notes and the explicit pending-human-annotation status. It is author-maintained review metadata outside inference source. `conditional` is a review category, not a new ClaimKind or verdict. Source statements can remain unsupported, unsplittable or ambiguous after actual extraction. These counts therefore do not establish valid extracted atoms or any label/outcome denominator. Every statement still needs real annotation, including apparently straightforward declarations.

The twelve-family/120-authored-statement source target has been prepared, but the promoted DEV claim target remains unverified until complete extraction and actual annotation. No 12-heldout-family/120-claim corpus, required defect/nondefect/kind denominators, staffed human adjudication, locked live comparisons or product acceptance is supplied. No benchmark score, custody receipt, human signature or gold label is supplied. An external curator must author and protect future heldout material; hashes of these already exposed files cannot create blindness.

Later activation: freeze source bytes through the existing fixture snapshot interface or DEV-only staging source; create inventories and reopen every quoted span; inspect all unsupported/skipped rows; then invite actual human review through the annotation procedure. Run these cases and measure effort only after runtime authorization is restored. The module fixtures are audit inputs and must never be imported or executed by the auditor.
