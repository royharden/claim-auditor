# Run from any directory: pwsh -File <checkout>/scripts/bootstrap.ps1
# Requires uv on PATH. Python and packages stay inside this checkout.
[CmdletBinding()]
param([switch]$Build)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$uvCommand = @(Get-Command uv -CommandType Application -ErrorAction Stop)[0]
$previousEnvironment = $env:UV_PROJECT_ENVIRONMENT
$previousPythonDirectory = $env:UV_PYTHON_INSTALL_DIR
try {
    $env:UV_PROJECT_ENVIRONMENT = Join-Path $projectRoot '.venv'
    $env:UV_PYTHON_INSTALL_DIR = Join-Path $projectRoot '.agent-work/python'
    # Install the locked backend first, then build the editable package using it.
    & $uvCommand.Source --no-config sync --project $projectRoot --locked --python 3.12.13 --managed-python --group dev --no-install-project
    if ($LASTEXITCODE -ne 0) { throw "Locked build-tool installation failed (exit $LASTEXITCODE)." }
    & $uvCommand.Source --no-config sync --project $projectRoot --locked --python 3.12.13 --managed-python --group dev --no-build-isolation
    if ($LASTEXITCODE -ne 0) { throw "Locked dependency installation failed (exit $LASTEXITCODE)." }
    $python = Join-Path $projectRoot '.venv/Scripts/python.exe'
    & $python -c 'import sys; assert sys.version_info[:3] == (3, 12, 13), sys.version; print(sys.executable)'
    if ($LASTEXITCODE -ne 0) { throw 'Python version verification failed.' }
    if ($Build) {
        & $python -m build --wheel --no-isolation --outdir (Join-Path $projectRoot 'dist') $projectRoot
        if ($LASTEXITCODE -ne 0) { throw "Wheel build failed (exit $LASTEXITCODE)." }
    }
} finally {
    $env:UV_PROJECT_ENVIRONMENT = $previousEnvironment
    $env:UV_PYTHON_INSTALL_DIR = $previousPythonDirectory
}
