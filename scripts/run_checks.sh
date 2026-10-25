#!/usr/bin/env sh
set -eu
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
python_bin=${1:-"$project_root/.venv/bin/python"}
pattern=${2:-'test*.py'}
if [ ! -x "$python_bin" ]; then
    printf '%s\n' 'Project Python missing. Run scripts/bootstrap.sh first.' >&2
    exit 2
fi
"$python_bin" -I -c 'import sys; assert sys.version_info[:2] == (3,12), "Python 3.12 required"'
cd "$project_root"
exec "$python_bin" -I -m unittest discover -s "$project_root/tests" -t "$project_root" -p "$pattern" -v
