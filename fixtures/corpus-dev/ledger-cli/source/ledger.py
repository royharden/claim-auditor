"""Original DEV fixture: flat command module; never execute as audit input."""

from pathlib import Path

DEFAULT_FILE = "entries.txt"


def append_note(note, destination=DEFAULT_FILE):
    with Path(destination).open("a", encoding="utf-8") as stream:
        stream.write(note + "\n")


def main():
    return "ledger-note"
