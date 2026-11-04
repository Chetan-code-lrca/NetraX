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

$PythonVersion = py -3 -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"
if ([version]$PythonVersion -lt [version]"3.12.0") {
    throw "Python 3.12 or newer is required. Detected $PythonVersion."
}
node -e "const major = Number(process.versions.node.split('.')[0]); if (major < 20) { console.error('Node.js 20 or newer is required.'); process.exit(1); }"
if (-not (Test-Path ".venv")) {
    py -3 -m venv .venv
}

$Python = Join-Path $Root ".venv\Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements.txt

New-Item -ItemType Directory -Force -Path "model-artifacts" | Out-Null
npm --prefix frontend ci

Write-Host ""
Write-Host "NetraX setup complete."
Write-Host "Start the API:       .\.venv\Scripts\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000"
Write-Host "Start the dashboard: cd frontend; npm run dev"
Write-Host "Before model-based analysis, place trusted files in model-artifacts\."
Write-Host "See model-artifacts\README.md and docs\INTERVIEW_GUIDE.md."
