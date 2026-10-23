"""Original DEV fixture: context manager with generator delegation."""

from contextlib import contextmanager


def iter_rows(stream, limit=4):
    for number, line in enumerate(stream):
        if number >= limit:
            return
        yield line.rstrip("\n")


@contextmanager
def open_rows(path):
    stream = open(path, encoding="utf-8")
    try:
        yield iter_rows(stream)
    finally:
        stream.close()
