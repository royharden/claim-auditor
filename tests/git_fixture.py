"""Trusted disposable Git fixture construction, executed only in later validation.

No repository is created at import. Commands have no remote, use an empty hook
template and disabled inherited Git configuration. Hostile configuration is added
only AFTER the safe fixture commit; the fixture builder is not called afterwards.
"""

import os
from pathlib import Path
import shutil
import subprocess


class GitFixture:
    def __init__(self, base: Path, files=None):
        executable = shutil.which("git")
        if executable is None:
            raise RuntimeError("Activation prerequisite: trusted installed Git; missing tooling is not a pass/skip")
        self.executable = str(Path(executable).absolute())
        self.root = base / "repo"
        self.template = base / "empty-template"
        self.root.mkdir(parents=True)
        self.template.mkdir()
        self.env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_COUNT="0",
                        GIT_TERMINAL_PROMPT="0", GIT_NO_REPLACE_OBJECTS="1", GIT_ALLOW_PROTOCOL="")
        self.git("init", f"--template={self.template}", "--object-format=sha1")
        for name, raw in (files or {"README.md": b"The function `work` is declared.\n",
                                   "tiny.py": b"def work():\n    pass\n"}).items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.git("add", "--", ".")
        self.head = self.commit()

    def git(self, *args):
        command = [self.executable, "-c", f"core.hooksPath={self.template}",
                   "-c", "core.fsmonitor=false", "-c", "commit.gpgSign=false",
                   "-c", "gc.auto=0", "-c", "maintenance.auto=false",
                   "-c", "credential.helper=", "-c", "protocol.allow=never",
                   "-C", str(self.root), *args]
        return subprocess.run(command, cwd=self.template, env=self.env, shell=False,
                              input=b"", capture_output=True, check=True, timeout=20).stdout

    def commit(self):
        self.git("-c", "user.name=Synthetic Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "--no-gpg-sign", "-m", "owned disposable fixture")
        return self.git("rev-parse", "HEAD").decode("ascii").strip()


def config_value(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
