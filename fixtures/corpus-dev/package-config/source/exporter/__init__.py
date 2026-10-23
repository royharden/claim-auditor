"""Original DEV fixture: package-level re-export is not a local declaration."""

from .codec import encode

__all__ = ["encode"]
