"""Versioned syntax-only patterns. No pattern asserts runtime behavior."""

PATTERN_VERSION = "bounded-patterns/1"
PATTERNS = {
    "async-def/v1": "Named declaration uses async def; no scheduling/behavior assertion.",
    "literal-default/v1": "Literal default expression on an unambiguous declaration; no call semantics.",
    "literal-constant/v1": "Single top-level literal assignment; no effective runtime value assertion.",
    "explicit-raise/v1": "Named function contains explicit raise syntax, excluding nested declarations; reachability unknown.",
    "decorator-argument/v1": "Literal keyword on a named decorator expression; no retry/reliability assertion.",
}
