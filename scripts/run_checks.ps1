# Run from any cwd against this checkout's installed, locked Python environment.
[CmdletBinding()]
param(
    [string]$Python = '',
    [string]$Pattern = 'test*.py'
)
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $Python) { $Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw 'Project Python is missing. Run scripts/bootstrap.ps1 first.'
}
& $Python -I -c 'import sys; assert sys.version_info[:2] == (3,12), "Python 3.12 required"'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Import tests as a package so their relative support imports work.
Push-Location $ProjectRoot
try {
    & $Python -m unittest discover -s (Join-Path $ProjectRoot 'tests') -t $ProjectRoot -p $Pattern -v
    $CheckExit = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $CheckExit
