"""Deterministic model-input hold; screening is not an isolation guarantee."""

import re
from pydantic import BaseModel

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


def screen_original_strings(value: object) -> list[str]:
    """Apply the same policy to every original wire string, before JSON escapes.

    Includes scope paths, gap metadata and excerpts; no new pattern or model
    policy. The caller supplies a bounded packet model/dict, never rendered JSON.
    """
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if isinstance(value, str):
        return screen_text(value)
    if isinstance(value, dict):
        for key, item in value.items():
            if screen_original_strings(key) or screen_original_strings(item):
                return ["abstention_screened"]
    elif isinstance(value, (list, tuple)):
        for item in value:
            if screen_original_strings(item):
                return ["abstention_screened"]
    return []
