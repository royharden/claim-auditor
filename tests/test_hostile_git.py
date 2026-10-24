"""Future owned-repository isolation probes; no Git command runs during construction."""

from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from claim_auditor.audit.policy import decide_finding
from claim_auditor.contracts import AuditError
from claim_auditor.index import StaticIndex, resolve
from claim_auditor.snapshot import create_git_snapshot, read_source

from .git_fixture import GitFixture, config_value
from .support import claim, predicate, span_for


class HostileGitTests(unittest.TestCase):
    def test_revision_aliases_abbreviations_and_options_refuse_before_process_start(self):
        """what_bug_this_catches: target revision text becoming an executable Git argument or mutable HEAD lookup."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            for revision in ("HEAD", "a" * 12, "A" * 40, "--help", "a" * 40 + "\n"):
                with self.subTest(revision=revision), patch("claim_auditor.snapshot.git.subprocess.Popen") as process:
                    with self.assertRaises(AuditError) as caught:
                        create_git_snapshot(base, revision, base / "out")
                    self.assertEqual(caught.exception.reason, "git_commit")
                    process.assert_not_called()

    def test_exact_commit_is_recorded_and_unknown_full_id_never_falls_back_to_head(self):
        """what_bug_this_catches: silently substituting the checkout's HEAD for a requested immutable object."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            fixture = GitFixture(base)
            snapshot = create_git_snapshot(fixture.root, fixture.head, base / "frozen")
            self.assertEqual(snapshot.commit, fixture.head)
            self.assertEqual(snapshot.hash_algorithm, "sha1")
            self.assertEqual(snapshot.source_kind, "git_commit")
            self.assertEqual(read_source(snapshot, base / "frozen", "tiny.py"), b"def work():\n    pass\n")
            with self.assertRaises(AuditError) as caught:
                create_git_snapshot(fixture.root, "0" * 40, base / "wrong-object")
            self.assertEqual(caught.exception.reason, "git_snapshot_input")
            self.assertFalse((base / "wrong-object" / "manifest.json").exists())

    def test_hostile_config_hooks_filters_helpers_and_shadow_modules_stay_inert(self):
        """what_bug_this_catches: acquisition loading target Git configuration, filters, hooks or Python imports."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            marker = base / "SENTINEL-EXECUTED.txt"
            sentinel = ("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('unexpected target execution')\n").encode()
            files = {"README.md": b"The function `work` is declared.\n",
                     "tiny.py": b"def work():\n    pass\n", ".gitattributes": b"tiny.py filter=sentinel\n",
                     "sitecustomize.py": sentinel, "json.py": sentinel, "subprocess.py": sentinel}
            fixture = GitFixture(base, files)
            script = fixture.root / ".git" / "harmless-sentinel.py"
            script.write_bytes(sentinel)
            command = f'"{Path(sys.executable).as_posix()}" "{script.as_posix()}"'
            hooks = fixture.root / ".git" / "hostile-hooks"
            hooks.mkdir()
            hook = hooks / "post-checkout"
            hook.write_text("#!/bin/sh\nexec " + command + "\n", encoding="utf-8")
            hook.chmod(0o755)
            config = fixture.root / ".git" / "config"
            with config.open("a", encoding="utf-8") as stream:
                stream.write("\n[core]\n hooksPath = " + config_value(hooks.as_posix()) +
                             "\n fsmonitor = " + config_value(command) +
                             '\n[filter "sentinel"]\n clean = ' + config_value(command) +
                             "\n smudge = " + config_value(command) + "\n required = true\n" +
                             "[credential]\n helper = " + config_value("!" + command) +
                             "\n[alias]\n cat-file = " + config_value("!" + command) + "\n")
            # No fixture-builder Git call after hostile configuration is installed.
            out = base / "frozen"
            snapshot = create_git_snapshot(fixture.root, fixture.head, out)
            self.assertEqual(snapshot.commit, fixture.head)
            self.assertFalse(marker.exists())
            self.assertEqual(read_source(snapshot, out, "tiny.py"), files["tiny.py"])
            self.assertEqual(read_source(snapshot, out, "json.py"), sentinel)
            self.assertFalse((out / "files" / ".git").exists())

    def test_incomplete_or_indirected_object_stores_are_refused(self):
        """what_bug_this_catches: shallow, alternate, promisor or worktree state silently changing snapshot scope."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            cases = ["shallow", "alternates", "promisor-config", "promisor-pack", "commondir", "config.worktree", "git-file"]
            for name in cases:
                fixture = GitFixture(base / name)
                store = fixture.root / ".git"
                repo = fixture.root
                if name == "shallow":
                    (store / "shallow").write_text(fixture.head + "\n", encoding="ascii")
                elif name == "alternates":
                    (store / "objects" / "info" / "alternates").write_text(str(store / "objects") + "\n", encoding="utf-8")
                elif name == "promisor-config":
                    with (store / "config").open("a", encoding="utf-8") as stream:
                        stream.write('\n[remote "origin"]\n promisor = true\n')
                elif name == "promisor-pack":
                    (store / "objects" / "pack" / ("pack-" + "a" * 40 + ".promisor")).write_bytes(b"")
                elif name == "git-file":
                    repo = base / "indirected-repo"
                    repo.mkdir()
                    (repo / ".git").write_text("gitdir: " + str(store) + "\n", encoding="utf-8")
                else:
                    (store / name).write_text("../other-store\n", encoding="utf-8")
                out = base / f"refused-{name}"
                with self.subTest(name=name), self.assertRaises(AuditError) as caught:
                    create_git_snapshot(repo, fixture.head, out)
                self.assertEqual(caught.exception.reason, "git_snapshot_input")
                self.assertFalse((out / "manifest.json").exists())

    def test_lfs_and_gitlink_gaps_never_authorize_absence_accusations(self):
        """what_bug_this_catches: unavailable LFS/submodule content being treated as exhaustively absent source."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            readme = b"The file `large.bin` exists.\nThe file `vendor/lib/invented.py` exists.\n"
            fixture = GitFixture(base, {"README.md": readme, "tiny.py": b"pass\n",
                                        "large.bin": b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"0" * 64 + b"\nsize 999\n"})
            fixture.git("update-index", "--add", "--cacheinfo", f"160000,{fixture.head},vendor/lib")
            commit = fixture.commit()
            out = base / "frozen"
            snapshot = create_git_snapshot(fixture.root, commit, out)
            self.assertFalse(snapshot.complete)
            self.assertIn("lfs_pointer_unavailable", {gap.reason for gap in snapshot.exclusions})
            self.assertIn("submodule_content_unavailable", {gap.reason for gap in snapshot.exclusions})
            index = StaticIndex(snapshot=snapshot, root=out)  # Scope-policy seam, not parser coverage.
            for path in ("large.bin", "vendor/lib/invented.py"):
                query = predicate(kind="path_exists", subject=path, path=path, module=None)
                quote = f"The file `{path}` exists.".encode()
                start = readme.index(quote)
                atom = claim(span_for(snapshot, readme, start=start, end=start + len(quote)), query)
                result = resolve(index, query)
                finding = decide_finding(atom, [result], citation_valid=True)
                self.assertEqual(finding.verdict, "unknown")
                self.assertEqual(finding.accused_predicate_ids, [])
                self.assertFalse(any(item.kind == "negative" for item in result.evidence))
