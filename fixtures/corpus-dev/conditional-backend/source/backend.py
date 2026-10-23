"""Original DEV fixture: conditional definitions and a static local constant."""

import os

CONNECT_TIMEOUT = 3

if os.getenv("BACKEND_MODE") == "remote":
    def connect():
        return "remote-placeholder"
else:
    def connect():
        return "local-placeholder"
