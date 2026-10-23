"""Original DEV fixture: coroutine, local branch and environment reference."""

import os

REGION = os.getenv("CACHE_REGION", "local")
_values = {}


async def fetch(key, ttl=15):
    if ttl < 0:
        raise ValueError("negative ttl")
    return _values.get((REGION, key))
