"""Original DEV fixture: typing-only class and platform-guarded import."""

import os
import sys
from typing import TYPE_CHECKING

PROTOCOL = "stdio"
TRACE = os.getenv("ADAPTER_TRACE")

if TYPE_CHECKING:
    class DebugSession:
        session_id: str

if sys.platform == "win32":
    from msvcrt import get_osfhandle as native_handle
else:
    native_handle = None


def platform_name():
    return sys.platform
