"""Owned parser input. The auditor reads these bytes without importing this file."""

import os

GREETING = "hello"


def greet(name="world"):
    return f"{GREETING}, {name}"


async def declared_async():
    raise RuntimeError("syntax-only evidence; reachability is not asserted")


def read_name():
    return os.getenv("CLAIM_AUDITOR_DEMO_NAME")
