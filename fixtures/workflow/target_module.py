"""Static target input: the workflow must never import or execute this file."""

from pathlib import Path

Path(__file__).with_name("TARGET_CODE_EXECUTED").write_text("unexpected execution")


def present():
    return 3
