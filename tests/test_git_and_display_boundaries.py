"""Future controls for Git object addressing, git resolution, terminal JSON, display and parser setup.

Pure-function and patched-boundary probes only: no Git process, network or real worker runs.
"""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock, patch

from claim_auditor.cli import _terminal_json, main
from claim_auditor.contracts import AuditError
from claim_auditor.index import _parser_packet, _worker
from claim_auditor.report import _display, _fenced
from claim_auditor.snapshot.git import _batch_bounded, _tree_entries, _trusted_git, _verify_object_id
from claim_auditor.snapshot.safeio import SnapshotError

# Well-known Git SHA-1 object IDs (independent of this implementation).
EMPTY_BLOB_SHA1 = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
EMPTY_TREE_SHA1 = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


class GitObjectAddressingTests(unittest.TestCase):
    def test_object_ids_are_recomputed_and_mismatch_is_integrity_exit_4(self):
        """what_bug_this_catches: trusting object-store bytes whose content does not hash to the requested ID."""
        _verify_object_id("sha1", "blob", b"", EMPTY_BLOB_SHA1)
        _verify_object_id("sha1", "tree", b"", EMPTY_TREE_SHA1)
        payload = b"owned demo\n"
        sha256_id = hashlib.sha256(b"blob %d\0" % len(payload) + payload).hexdigest()
        _verify_object_id("sha256", "blob", payload, sha256_id)
        for algorithm, kind, data, oid in (("sha1", "blob", b"tampered", EMPTY_BLOB_SHA1),
                                           ("sha1", "tree", b"", EMPTY_BLOB_SHA1),
                                           ("sha256", "blob", payload + b"x", sha256_id)):
            with self.subTest(algorithm=algorithm, kind=kind):
                with self.assertRaises(AuditError) as caught:
                    _verify_object_id(algorithm, kind, data, oid)
                self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("git_object_hash_mismatch", 4))
        # acquire_git wraps only OSError/ValueError/SubprocessError as input (2); integrity must not be relabelled.
        self.assertFalse(issubclass(AuditError, (OSError, ValueError, subprocess.SubprocessError)))

    def test_batch_read_rejects_payload_that_does_not_match_its_object_id(self):
        """what_bug_this_catches: cat-file output accepted under the requested ID without content addressing."""
        tampered = b"not the empty blob"
        header = f"{EMPTY_BLOB_SHA1} blob {len(tampered)}".encode("ascii")
        replies = [header + b"\n", header + b"\n" + tampered + b"\n"]
        with patch("claim_auditor.snapshot.git._run", side_effect=replies) as run:
            with self.assertRaises(AuditError) as caught:
                _batch_bounded(["git"], Path("."), {}, EMPTY_BLOB_SHA1, 1024, "blob")
        self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("git_object_hash_mismatch", 4))
        self.assertEqual(run.call_count, 2)

    def test_tree_modes_are_canonicalized_like_git_and_unknown_modes_refused(self):
        """what_bug_this_catches: valid legacy tree modes refused, or unknown modes silently admitted."""
        oid = bytes(range(20))

        def entry(mode, name):
            return mode + b" " + name + b"\0" + oid

        payload = b"".join([entry(b"040000", b"dir"), entry(b"100664", b"group.txt"), entry(b"100755", b"run.sh"),
                            entry(b"100644", b"plain.py"), entry(b"120000", b"link"), entry(b"160000", b"sub")])
        modes = [(mode, name) for mode, name, _ in _tree_entries(payload, 20)]
        self.assertEqual(modes, [("40000", b"dir"), ("100644", b"group.txt"), ("100755", b"run.sh"),
                                 ("100644", b"plain.py"), ("120000", b"link"), ("160000", b"sub")])
        self.assertTrue(all(record[2] == oid.hex() for record in _tree_entries(payload, 20)))
        for bad in (b"1000644", b"777777", b"10064", b"abcdef"):
            with self.subTest(mode=bad), self.assertRaises(SnapshotError):
                _tree_entries(entry(bad, b"file"), 20)


class TrustedGitResolutionTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.name = "git.exe" if os.name == "nt" else "git"

    def binary_dir(self, label, names):
        directory = self.base / label
        directory.mkdir()
        for name in names:
            path = directory / name
            path.write_bytes(b"synthetic placeholder; never executed\n")
            path.chmod(0o755)
        return directory

    def test_git_is_never_resolved_from_cwd_relative_entries_or_batch_wrappers(self):
        """what_bug_this_catches: a planted git.exe/git.bat in the working directory running instead of installed Git."""
        cwd = self.binary_dir("cwd", [self.name])
        wrappers = self.binary_dir("wrappers", ["git.bat", "git.cmd"])
        trusted = self.binary_dir("trusted", [self.name])
        if os.name != "nt" and not os.access(trusted / self.name, os.X_OK):
            self.skipTest("temporary directory is mounted noexec; X_OK resolution cannot be probed here")
        relative = os.path.join("relative-bin")
        with patch.object(Path, "cwd", return_value=cwd):
            path = os.pathsep.join([str(cwd), relative, str(wrappers), str(trusted)])
            with patch.dict(os.environ, {"PATH": path}):
                self.assertEqual(_trusted_git(), (trusted / self.name).resolve())
            for only in ([str(cwd)], [relative], [str(wrappers)], [str(cwd), str(wrappers)]):
                with self.subTest(path=only), patch.dict(os.environ, {"PATH": os.pathsep.join(only)}):
                    with self.assertRaises(SnapshotError) as caught:
                        _trusted_git()
                    self.assertIn("trusted_git_binary_unavailable", str(caught.exception))


class TerminalAndDisplayTests(unittest.TestCase):
    def test_terminal_json_is_ascii_only_and_round_trips(self):
        """what_bug_this_catches: C1/bidi/zero-width characters reaching the operator's terminal raw."""
        value = {"quote": "csi\u009b bidi\u202e zw\u200b del\u007f e\u00e9", "n": 1}
        raw = _terminal_json(value)
        self.assertTrue(all(byte < 128 for byte in raw))
        self.assertEqual(json.loads(raw), value)
        for escape in (b"\\u009b", b"\\u202e", b"\\u200b"):
            self.assertIn(escape, raw)

    def test_cli_error_output_is_terminal_safe(self):
        """what_bug_this_catches: a hostile path or detail printed to stderr with raw control/bidi characters."""
        if sys.getfilesystemencoding().lower().replace("-", "") != "utf8" and os.name != "nt":
            self.skipTest("non-UTF-8 filesystem encoding cannot represent the hostile path")
        with TemporaryDirectory() as directory:
            missing = Path(directory) / "run-\u202e-\u009b"
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(["verify-report", str(missing)])
        self.assertEqual(status, 2)
        self.assertTrue(stderr.getvalue().isascii())
        self.assertEqual(json.loads(stderr.getvalue())["error"], "run_not_found")

    def test_line_leading_workflow_commands_are_neutralized_in_display_only(self):
        """what_bug_this_catches: README lines like ::add-mask:: executing when a report is printed in an Actions log."""
        text = "::add-mask::x\n  ::warning::y\n\u00a0::error::z\n\t::stop-commands::t\nok :: mid-line"
        self.assertEqual(_display(text),
                         "\\::add-mask::x\n  \\::warning::y\n\u00a0\\::error::z\n\t\\::stop-commands::t\nok :: mid-line")
        fenced = _fenced("\u00a0::notice::n")
        self.assertIn("\u00a0\\::notice::n", fenced)
        self.assertNotIn("\n\u00a0::notice", fenced)


class ParserEnforcementTests(unittest.TestCase):
    def test_macos_reports_enforcement_unavailable_and_parent_fails_setup(self):
        """what_bug_this_catches: macOS RLIMIT_AS accepted as enforced memory limits for hostile input."""
        with patch.object(_worker.sys, "platform", "darwin"), patch.object(_worker.os, "name", "posix"):
            with self.assertRaises(OSError) as caught:
                _worker._enforce_limits()
        self.assertIn("macos_memory_limit_not_enforced", str(caught.exception))
        stdout = io.StringIO()
        with patch.object(_worker, "_enforce_limits", side_effect=OSError("macos_memory_limit_not_enforced")), \
                patch.object(_worker.sys, "stdin") as stdin, redirect_stdout(stdout):
            _worker.main()
        stdin.buffer.read.assert_not_called()  # No target bytes are read without enforcement.
        self.assertEqual(json.loads(stdout.getvalue()),
                         {"enforced": False, "error": "macos_memory_limit_not_enforced", "files": []})
        process = MagicMock()
        process.stdout.read.side_effect = [stdout.getvalue().encode("utf-8"), b""]
        process.stderr.read.side_effect = [b""]
        process.wait.return_value = 0
        process.returncode = 0
        with patch("claim_auditor.index.subprocess.Popen", return_value=process):
            with self.assertRaises(AuditError) as caught:
                _parser_packet(b"[]")
        self.assertEqual((caught.exception.reason, caught.exception.exit_code), ("parser_enforcement_unavailable", 2))
