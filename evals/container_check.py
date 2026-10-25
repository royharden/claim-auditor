"""Network-free packaged DEV controls plus installed CLI e2e entrypoint."""

import argparse
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    for module, directory in (("evals.dev_controls", "controls"), ("evals.offline_e2e", "e2e")):
        result = subprocess.run([sys.executable, "-m", module, "--out", str(args.out / directory)],
                                timeout=600, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
