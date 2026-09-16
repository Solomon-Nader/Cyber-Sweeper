# Cyber Sweeper one-shot setup for Windows PowerShell.
# Usage (from the project folder):   .\scripts\setup.ps1
# Creates a virtual environment, installs the package and its dependencies,
# runs the environment check and the test suite.

$ErrorActionPreference = "Stop"
Write-Host "== Cyber Sweeper setup ==" -ForegroundColor Cyan

# 1. Python
try { $pyver = (python --version) 2>&1 } catch { $pyver = "" }
if (-not $pyver -or $pyver -notmatch "Python 3\.(9|1[0-9])") {
    Write-Host "Python 3.9+ was not found on PATH. Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH')." -ForegroundColor Red
    exit 1
}
Write-Host "Python  : $pyver"

# 2. Virtual environment
if (-not (Test-Path ".venv")) {
    python -m venv .venv
    Write-Host "Created .venv"
}
. .\.venv\Scripts\Activate.ps1

# 3. Package + dev tools
python -m pip install --upgrade pip --quiet
pip install -e ".[dev]" --quiet
Write-Host "Installed cybersweeper and dependencies"

# 4. nmap (optional)
if (Get-Command nmap -ErrorAction SilentlyContinue) {
    Write-Host "nmap    : found ($((nmap --version | Select-Object -First 1)))"
} else {
    Write-Host "nmap    : NOT found - optional. Install from https://nmap.org/download.html for the nmap engine." -ForegroundColor Yellow
}

# 5. Environment check + tests
Write-Host ""
cybersweeper check
Write-Host ""
Write-Host "Running the test suite..." -ForegroundColor Cyan
pytest -q
Write-Host ""
Write-Host "Done. Try:  cybersweeper scan 127.0.0.1 -p common     or     cybersweeper gui" -ForegroundColor Green
