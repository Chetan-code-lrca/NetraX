$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "Python Launcher with Python 3.12+ is required."
}
if (-not (Get-Command node -ErrorAction SilentlyContinue) -or
    -not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "Node.js 20+ and npm are required for the dashboard."
}

py -3.12 --version
if (-not (Test-Path ".venv")) {
    py -3.12 -m venv .venv
}

$Python = Join-Path $Root ".venv\Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt
& $Python -m pip install cicflowmeter

New-Item -ItemType Directory -Force -Path "model-artifacts" | Out-Null
npm --prefix frontend ci

Write-Host ""
Write-Host "NetraX setup complete."
Write-Host "Start the API:       .\.venv\Scripts\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000"
Write-Host "Start the dashboard: cd frontend; npm run dev"
Write-Host "Before model-based analysis, place trusted files in model-artifacts\."
Write-Host "See model-artifacts\README.md and docs\INTERVIEW_GUIDE.md."
