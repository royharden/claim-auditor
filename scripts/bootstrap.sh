#!/bin/sh
# Run from any directory: sh <checkout>/scripts/bootstrap.sh [--build]
# Requires uv on PATH. Python and packages stay inside this checkout.
set -eu
if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != '--build' ]; }; then
    echo 'Usage: bootstrap.sh [--build]' >&2
    exit 2
fi
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export UV_PROJECT_ENVIRONMENT="$project_root/.venv"
export UV_PYTHON_INSTALL_DIR="$project_root/.agent-work/python"
# Install the locked backend first, then build the editable package using it.
uv --no-config sync --project "$project_root" --locked --python 3.12.13 --managed-python --group dev --no-install-project
uv --no-config sync --project "$project_root" --locked --python 3.12.13 --managed-python --group dev --no-build-isolation
python="$project_root/.venv/bin/python"
"$python" -c 'import sys; assert sys.version_info[:3] == (3, 12, 13), sys.version; print(sys.executable)'
if [ "$#" -eq 1 ]; then
    "$python" -m build --wheel --no-isolation --outdir "$project_root/dist" "$project_root"
fi
