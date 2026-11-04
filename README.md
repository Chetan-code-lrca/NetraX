# NetraX

**Passive, evidence-aware analysis of one-way network traffic.**

NetraX is a file-based network traffic analysis tool built around the SIH26145
problem: detecting suspicious behavior when a monitoring point can observe only
one direction of a communication flow.

The first practical workflow is intentionally simple: upload an authorized
PCAP/PCAPNG capture or a supported flow CSV, run analysis, review evidence and
download a JSON report. NetraX does not actively probe the network or perform
mitigation.

## What it can analyze

The current inference pipeline includes:

- Port scanning indicators
- DDoS traffic indicators
- C2 / botnet beaconing behavior
- DGA and DNS tunneling indicators
- Encrypted-malware traffic indicators
- Data-exfiltration indicators

The detectors do not all use the same technique. Some use trained model
artifacts; C2 and exfiltration paths also include feature/rule-based analysis.
The PortScan/DDoS flow-model inputs are governed by the versioned
`netrax.flow.forward.v1` contract. See
[the strict one-way feature contract](docs/ONE_WAY_FEATURE_CONTRACT.md) for
approved fields, excluded legacy features and retraining requirements. Old
PortScan/DDoS models that expect bidirectional fields are rejected at runtime;
they must be retrained rather than silently adapted. PortScan/DDoS training also requires capture-group-disjoint
evaluation metadata; it will not fall back to random row-level splits.
An alert is an investigation lead, not proof that a host is compromised.

## Run it with Docker Compose

This is the recommended way to run the full dashboard and API on one machine.

### Prerequisites

- Docker Desktop (Windows/macOS) or Docker Engine with the Compose plugin (Linux)
- The five trusted trained model artifacts listed in
  [model-artifacts/README.md](model-artifacts/README.md) for full model-based
  analysis

### Start

Clone the repository:

```bash
git clone https://github.com/Chetan-code-lrca/NetraX.git
cd NetraX
```

Place your trained model artifacts in `model-artifacts/` as described in
[model-artifacts/README.md](model-artifacts/README.md), then build and start:

```bash
docker compose up --build
```

Open **http://localhost:8080**.

Stop the application with:

```bash
docker compose down
```

The dashboard container serves the built React application and proxies
`/api/*` requests to the FastAPI service. The API is not exposed directly to
the host by the Compose configuration.

### Check runtime readiness

- `http://localhost:8080/api/health` — confirms that the API process is alive.
- `http://localhost:8080/api/readiness` — shows whether the model artifacts
  and PCAP conversion dependency are available.
- `http://localhost:8080/docs` — interactive API documentation.

A source checkout can start without model files, but model-based analysis will
not be available until the required trusted artifacts are supplied. The UI
shows this as an incomplete runtime setup rather than claiming all detectors
are ready.

## Run locally without Docker

For a guided setup on Linux/macOS, run `bash scripts/setup.sh`. On Windows,
run `./scripts/setup.ps1` from PowerShell. The scripts install project
packages; you still need to provide the trusted model artifacts described
below.

### 1. Install the backend

Use Python 3.12 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install cicflowmeter
```

For Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install cicflowmeter
```

### 2. Configure model artifacts

Copy the model files you trained and evaluated into `model-artifacts/`. Then
point NetraX to that directory:

Linux/macOS:

```bash
export NETRAX_MODEL_DIR="$PWD/model-artifacts"
```

Windows PowerShell:

```powershell
$env:NETRAX_MODEL_DIR = "$PWD\model-artifacts"
```

See [model-artifacts/README.md](model-artifacts/README.md) for the exact
filenames. Never download or load model binaries from an untrusted source.

### 3. Start the API

From the repository root:

```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

### 4. Start the dashboard

In a second terminal:

```bash
cd frontend
npm ci
npm run dev
```

Open **http://localhost:5173**. The Vite development server proxies API
requests to `http://127.0.0.1:8000`.

For a separately hosted frontend, set `VITE_NETRAX_API_URL` to the full API
base URL at build time. Configure the matching frontend origin in
`NETRAX_ALLOWED_ORIGINS` on the API.

## Analyze a file

1. Open the dashboard.
2. Choose a `.pcap`, `.pcapng`, or NetraX-compatible flow `.csv`.
3. Select **Analyze traffic**.
4. Review the findings, confidence score, and observed/available/missing
   evidence.
5. Select **Download report** to save a JSON copy of the analysis.

For PCAP/PCAPNG files, the API uses CICFlowMeter to convert packets into flow
records. For CSV files, supply the flow features expected by one of the current
detector input contracts; arbitrary CSV files are not automatically
interpretable as network flows.

### Try the bundled sample without model artifacts

The dashboard links to a small synthetic C2 behavioral CSV at
`frontend/public/examples/c2-behavioral-sample.csv`. Upload it to exercise
the rule-based C2 detector on a fresh clone. This sample does not require
trained model artifacts or CICFlowMeter. It is synthetic demonstration data,
not a real packet capture or evidence of an actual attack. PortScan, DDoS, DNS,
and encrypted-malware model paths still require their trusted trained
artifacts.

## Input and resource limits

| Limit | Current value |
| --- | ---: |
| Uploaded file size | 100 MB |
| Extracted CSV flow rows | 100,000 |
| CICFlowMeter conversion timeout | 120 seconds |
| Alerts returned to the dashboard | 500 |

The API reports explicit errors when a file is unsupported, too large, has too
many rows, cannot be converted, or requires a missing model artifact.

## Tests and quality checks

Backend tests:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
```

Frontend production build:

```bash
cd frontend
npm ci
npm run build
```

GitHub Actions runs the backend test suite and frontend build for pushes and
pull requests.

## Architecture

```text
Browser
  │
  ▼
React + Vite dashboard
  │  upload / report
  ▼
FastAPI service
  │
  ├── Validate file type and size
  ├── Store upload in a temporary workspace
  ├── PCAP/PCAPNG ── CICFlowMeter ──┐
  └── Flow CSV ────────────────────┤
                                   ▼
                           Input-contract detection
                                   │
                                   ▼
                         Existing NetraX detectors
                                   │
                                   ▼
                       One-way evidence/separability
                                   │
                                   ▼
                       Standardized findings + summary
                                   │
                                   ▼
                         Dashboard + JSON report
```

The detector and separability modules remain separate from the API and UI.
This keeps the existing research logic independently testable and makes the
upload/dashboard layer replaceable.

## Operational scope and security

- NetraX is passive. It analyzes supplied captures and does not send probes,
  modify firewall rules, or block traffic.
- The dashboard is not a packet-capture agent. Continuous monitoring would
  require a separately designed and secured capture/ingestion component.
- Use only traffic that you are authorized to collect and analyze.
- Do not expose the API publicly without adding authentication, request
  throttling, TLS termination, and a retention policy suitable for the
  environment.
- Treat trained `.joblib` files as executable trusted artifacts. Never load
  model files supplied by an untrusted user.
- Confidence values are model scores, not automatically calibrated
  probabilities of compromise. Validate each model on representative,
  held-out data before operational use.
- One-way visibility is incomplete by design. NetraX reports evidence limits;
  it cannot infer packets or metadata the sensor never observed.

## Explain the project

For an implementation walkthrough, architecture decisions, known limitations,
and a short demo script, see
[docs/INTERVIEW_GUIDE.md](docs/INTERVIEW_GUIDE.md).
