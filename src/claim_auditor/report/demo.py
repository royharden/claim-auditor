"""Tiny owned fixture construction; no handwritten verdicts or target execution."""

from __future__ import annotations

from pathlib import Path

from claim_auditor.contracts import AuditError


def create_demo_source(out: Path) -> Path:
    if out.exists() or out.is_symlink():
        raise AuditError("output_exists", "demo source must be a fresh directory")
    out.mkdir(parents=True, exist_ok=False)
    files = {
        "README.md": (
            "# Owned demo\n\n"
            "The function `present` is declared in module `sample`.\n\n"
            "The function `invented` is declared in module `sample`.\n\n"
            "The service handles 10000 requests per second.\n\n"
            "The function `present` has literal default `value=3` in module `sample`.\n\n"
            "The function `present` returns `3` for every input.\n\n"
            "The function `present` has literal default `value=30` in module `sample`.\n"
        ).encode("utf-8"),
        "sample.py": b'def present(value: int = 3) -> int:\n    return value\n',
        "pyproject.toml": b'[project]\nname = "owned-claim-demo"\nversion = "0.1.0"\nrequires-python = ">=3.12"\n',
    }
    for name, raw in files.items():
        with (out / name).open("xb") as handle:
            handle.write(raw)
    return out
