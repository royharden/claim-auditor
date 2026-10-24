"""Original-byte coordinates and inert serialization controls."""

from html.parser import HTMLParser
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from claim_auditor.citations import validate_span
from claim_auditor.contracts import AuditReport, sha256
from claim_auditor.inventory.raw import RawDocument
from claim_auditor.report import render_html, render_markdown
from claim_auditor.provenance import capture_run_context

from .support import claim, finding, frozen_source, inventory_for, span_for


class Tags(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.attributes = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)

    def handle_data(self, data):
        self.text.append(data)


class CoordinateReportTests(unittest.TestCase):
    def controlled_raw_input(self, base, raw):
        # Unit-only metadata/read port. This is not an acquired bare-CR bundle
        # and does not exercise load_snapshot or manifest-integrity acceptance.
        snapshot, root = frozen_source(base)
        entries = [entry.model_copy(update={"sha256": sha256(raw), "size": len(raw)})
                   if entry.path == "README.md" else entry for entry in snapshot.entries]
        return snapshot.model_copy(update={"entries": entries}), root

    def test_crlf_non_bmp_combining_and_second_occurrence_reopen(self):
        """what_bug_this_catches: code-point offsets or first-match quotes replacing raw bytes."""
        raw = "😀 e\u0301\r\nrepeat\r\nrepeat\r\n".encode("utf-8")
        with TemporaryDirectory() as directory:
            snapshot, root = frozen_source(Path(directory), readme=raw)
            document = RawDocument.decode(raw)
            self.assertEqual(document.char_bytes[1], 4)
            self.assertEqual(document.char_bytes[-1], len(raw))
            start = raw.rindex(b"repeat")
            span = span_for(snapshot, raw, start=start, end=start + 6)
            self.assertEqual((span.start_line, span.end_line), (3, 3))
            validate_span(snapshot, root, span)
            self.assertEqual(document.block_bytes(0, 1), (0, raw.index(b"\n") + 1))

    def test_ambiguous_inline_alignment_is_refused(self):
        """what_bug_this_catches: silently citing the first of repeated inline phrases."""
        raw = b"repeat and repeat\r\n"
        document = RawDocument.decode(raw)
        with self.assertRaises(ValueError):
            document.unique_alignment("repeat", 0, len(raw))
        self.assertEqual(document.unique_alignment("repeat", 11, len(raw)), (11, 17))

    def test_bare_cr_line_maps_agree_with_citation_reopening(self):
        """what_bug_this_catches: CommonMark bare-CR lines disagreeing with LF-only citation counts."""
        # Independent span unit contract: real acquisition still refuses lone CR.
        raw = b"first\rsecond\r"
        with TemporaryDirectory() as directory:
            snapshot, root = self.controlled_raw_input(Path(directory), raw)
            start = raw.index(b"second")
            span = span_for(snapshot, raw, start=start, end=start + 6)
            self.assertEqual((span.start_line, span.end_line), (2, 2))
            with patch("claim_auditor.citations.read_source", return_value=raw):
                validate_span(snapshot, root, span)

    def test_half_open_unicode_line_ends_agree_for_all_newline_forms(self):
        """what_bug_this_catches: end-exclusive spans being assigned to the following line."""
        first = "😀 e\u0301".encode("utf-8")
        for separator in (b"\n", b"\r\n", b"\r"):
            with self.subTest(separator=separator), TemporaryDirectory() as directory:
                raw = first + separator + b"second" + separator
                snapshot, root = self.controlled_raw_input(Path(directory), raw)
                after_first = len(first) + len(separator)
                before_second_newline = after_first + len(b"second")
                for start, end, expected in (
                    (0, len(first), (1, 1)),
                    (0, after_first, (1, 1)),
                    (after_first, before_second_newline, (2, 2)),
                    (after_first, len(raw), (2, 2)),
                ):
                    span = span_for(snapshot, raw, start=start, end=end)
                    self.assertEqual((span.start_line, span.end_line), expected)
                    with patch("claim_auditor.citations.read_source", return_value=raw):
                        validate_span(snapshot, root, span)

    def test_empty_file_span_remains_a_valid_existence_pointer(self):
        """what_bug_this_catches: shared line mapping invalidating a zero-byte file citation."""
        with TemporaryDirectory() as directory:
            snapshot, root = frozen_source(Path(directory), readme=b"")
            span = span_for(snapshot, b"")
            self.assertEqual((span.start_byte, span.end_byte, span.start_line, span.end_line), (0, 0, 1, 1))
            validate_span(snapshot, root, span)

    def test_hostile_markup_has_no_active_tags_urls_or_terminal_controls(self):
        """what_bug_this_catches: README HTML, links or escape codes becoming report actions."""
        payload = (Path(__file__).resolve().parents[1] / "fixtures" / "adversarial" / "report-payload.md").read_bytes()
        payload += b"\x1b[31mterminal control\x1b[0m\n"
        with TemporaryDirectory() as directory:
            snapshot, _ = frozen_source(Path(directory), readme=payload)
            atom = claim(span_for(snapshot, payload))
            context, errors = capture_run_context(
                run_id="synthetic-inert-report-unit", started_at=datetime.now(timezone.utc).isoformat(),
                snapshot=snapshot, mode="rules", provider=None, model=None,
                prompt_digest=None, packet_digest=None,
            )  # Actual trusted observations only at future activation, never now.
            self.assertEqual(errors, [])
            report = AuditReport(snapshot=snapshot, inventory=inventory_for(snapshot, atom),
                                 findings=[finding(atom, "unknown")], evidence=[], coverage=[],
                                 errors=[], mode="rules", evaluation_status="not measured", run_context=context)
            rendered = render_html(report)
            parser = Tags()
            parser.feed(rendered)
            self.assertFalse({"script", "iframe", "img", "a", "form", "object", "svg", "base"} & set(parser.tags))
            self.assertFalse(any(name.lower().startswith("on") or name in {"href", "src", "action"}
                                 for name, _ in parser.attributes))
            self.assertIn("<script>", "".join(parser.text))
            self.assertNotIn("\x1b", rendered)
            markdown = render_markdown(report)
            # The payload contains a six-backtick fence; its enclosing quote uses seven.
            self.assertIn("```````text\n", markdown)
            self.assertNotIn("\x1b", markdown)
