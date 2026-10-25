"""Untrusted source text must remain inert in terminal/workflow display."""

import re
import unittest

from claim_auditor.report import _display, _fenced


class WorkflowDisplayTests(unittest.TestCase):
    def test_modern_and_legacy_actions_commands_with_leading_whitespace_are_inert(self):
        """what_bug_this_catches: legacy ##[error]/warning/command escaping the ::-only guard."""
        for command in ("::error::payload", "##[error]payload", "##[warning]payload",
                        "##[command]payload", "##[group]payload", "##[endgroup]"):
            for prefix in ("", " ", "\t", "\u2003"):
                with self.subTest(command=command, prefix=prefix):
                    raw = prefix + command
                    rendered = _display(raw)
                    self.assertNotEqual(rendered, raw)
                    self.assertIsNone(re.match(r"^\s*(?:::|##\[)", rendered))

    def test_legacy_command_delimiter_is_inert_even_inside_ordinary_text(self):
        """what_bug_this_catches: the Actions legacy parser finds ##[ with IndexOf, not StartsWith.

        Reference: actions/runner src/Runner.Common/ActionCommand.cs TryParse.
        A backslash before the delimiter does not prevent legacy command parsing.
        """
        for payload in ("prefix ##[error]payload", r"\##[warning]payload",
                        "first\nordinary ##[command]payload"):
            with self.subTest(payload=payload):
                self.assertNotIn("##[", _display(payload))

    def test_multiline_commands_and_fence_payload_cannot_escape_display(self):
        """what_bug_this_catches: only guarding the first line or a README closing its Markdown fence."""
        payload = "ordinary\n  ##[error]bad\n::warning::bad\n``````\n<script>bad</script>"
        rendered = _fenced(payload)
        opening, *body, closing = rendered.splitlines()
        self.assertEqual(opening, closing + "text")
        self.assertGreater(len(closing), 6)
        self.assertFalse(any(re.match(r"^\s*(?:::|##\[)", line) for line in body))
