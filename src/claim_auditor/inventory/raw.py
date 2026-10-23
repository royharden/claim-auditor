"""Original-byte coordinates. Never recover quotes from rendered Markdown."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RawDocument:
    raw: bytes
    text: str
    char_bytes: tuple[int, ...]
    line_bytes: tuple[int, ...]

    @classmethod
    def decode(cls, raw: bytes) -> RawDocument:
        text = raw.decode("utf-8", errors="strict")
        positions = [0]
        for char in text:
            positions.append(positions[-1] + len(char.encode("utf-8")))
        # CommonMark normalizes CRLF and bare CR before creating line maps.
        # Scan the original bytes so map lines still reopen the original slice.
        lines = [0]
        cursor = 0
        while cursor < len(raw):
            if raw[cursor : cursor + 2] == b"\r\n":
                cursor += 2
                lines.append(cursor)
            elif raw[cursor : cursor + 1] in (b"\r", b"\n"):
                cursor += 1
                lines.append(cursor)
            else:
                cursor += 1
        if lines[-1] != len(raw):
            lines.append(len(raw))
        return cls(raw, text, tuple(positions), tuple(lines))

    def block_bytes(self, first_line: int, after_line: int) -> tuple[int, int]:
        if first_line < 0 or after_line <= first_line:
            raise ValueError("invalid Markdown line map")
        if first_line >= len(self.line_bytes) - 1:
            raise ValueError("Markdown line map exceeds raw source")
        return self.line_bytes[first_line], self.line_bytes[min(after_line, len(self.line_bytes) - 1)]

    def line_bounds(self, start: int, end: int) -> tuple[int, int]:
        from bisect import bisect_right

        if not 0 <= start <= end <= len(self.raw):
            raise ValueError("byte range outside source")
        return bisect_right(self.line_bytes, start), bisect_right(self.line_bytes, max(start, end - 1))

    def unique_alignment(self, quote: str, start: int, end: int) -> tuple[int, int]:
        """Only for exact inline quotes; ambiguous repetitions are refused."""
        needle = quote.encode("utf-8")
        if not needle:
            raise ValueError("empty quote")
        scope = self.raw[start:end]
        found = scope.find(needle)
        if found < 0 or scope.find(needle, found + 1) >= 0:
            raise ValueError("quote alignment is absent or ambiguous")
        return start + found, start + found + len(needle)


def safe_display(value: str) -> str:
    """Keep quotes byte-exact in records; render terminal controls inert."""
    import unicodedata

    return "".join(
        char if char in "\n\t" or unicodedata.category(char) not in {"Cc", "Cf"}
        else f"\\u{ord(char):04x}"
        for char in value
    )
