"""Deterministic model-input hold; screening is not an isolation guarantee."""

import re

_INSTRUCTION = re.compile(
    r"ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|"
    r"(?:run|execute)\s+(?:this\s+)?(?:command|shell|script)|"
    r"(?:send|reveal|print|exfiltrate)\s+(?:the\s+)?(?:secret|token|api.?key|credentials)|"
    r"(?:fetch|browse|visit)\s+https?://",
    re.IGNORECASE,
)


def screen_text(text: str) -> list[str]:
    """Return stable hold reasons; never execute or follow matched text."""
    return ["abstention_screened"] if _INSTRUCTION.search(text) else []
