# NetraX

**NetraX** is a passive cyber-threat detection system designed for environments where traffic is observed in a **strictly one-way direction**.

It analyzes traffic evidence available inside a monitoring enclave and avoids assuming that reverse-direction or responder-side information exists. The project was developed for **Smart India Hackathon problem statement SIH26145**.

> **Project status:** Prototype / active development.

## What NetraX Does

NetraX currently supports detection and analysis for:

- Port scanning
- DDoS traffic
- C2 / botnet beaconing
- DNS-based threats and tunneling
- Encrypted-malware indicators
- Data-exfiltration indicators

The detection pipeline combines feature extraction, threat-specific detectors/models, and the **One-Way Threat Separability Engine**. Alerts are enriched with an evidence-aware classification:

- `DETECTABLE` — the available one-way evidence is sufficient
- `WEAKLY-SEPARABLE` — evidence exists, but confidence is limited
- `NOT-SEPARABLE` — the available one-way observation cannot reliably establish the threat

This is an important design constraint: NetraX is intended to avoid presenting conclusions as certain when the required evidence is unavailable.

## Architecture

```text
                 One-way traffic / captured data
                              |
                              v
                    Feature extraction
                              |
                              v
                    Threat detection
                              |
                              v
              One-Way Threat Separability Engine
                              |
                              v
                    Evidence-aware alerts
                              |
                 +------------+------------+
                 |                         |
                 v                         v
            FastAPI API              React/Vite UI
```

The repository contains the backend API, detection models and training scripts, feature extraction/streaming code, metadata, and the React/Vite dashboard.

## Repository Structure

```text
NetraX/
├── api/                 # FastAPI service and API integration tests
├── detection/           # Detection logic, trained models, training/evaluation scripts
├── features/            # Feature extraction and feature adapters
├── separability/        # One-way evidence/separability logic
├── streaming/           # Replay, CSV, C2 and streaming pipeline components
├── data/                # Dataset metadata and project data
├── frontend/            # React + Vite dashboard
└── README.md
```

## Requirements

For the current repository, the safest development setup is:

- Git
- **Python 3.12+**
- `pip` and `venv`
- **Node.js 20.19+** (or Node.js 22.12+)
- npm
- A Linux/macOS environment is recommended for the PCAP/CICFlowMeter workflow

The frontend uses Vite. Current Vite releases require Node.js 20.19+ or 22.12+. citeturn0search0turn0search3

PCAP/PCAPNG analysis requires the `cicflowmeter` command. The current Python CICFlowMeter package requires Python 3.12+. citeturn0search1

## 1. Clone the Repository

```bash
git clone https://github.com/Chetan-code-lrca/NetraX.git
cd NetraX
```

## 2. Set Up the Python Environment

Create and activate a virtual environment:

### Linux / macOS

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
```

Install the Python packages used by the API and detection pipeline:

```bash
python -m pip install --upgrade pip
python -m pip install fastapi uvicorn python-multipart pandas numpy scikit-learn joblib
```

> The repository currently does not contain a `requirements.txt`/lock file, so dependencies are installed explicitly here rather than pretending there is a reproducible dependency lock.

## 3. Install CICFlowMeter for PCAP/PCAPNG Input

NetraX invokes a `cicflowmeter` executable when a PCAP/PCAPNG file is uploaded. The backend looks for it at `.venv-cicflow/bin/cicflowmeter` by default and also supports the `NETRAX_CICFLOWMETER_PATH` environment variable.

A convenient isolated setup is:

```bash
python3.12 -m venv .venv-cicflow
source .venv-cicflow/bin/activate
python -m pip install --upgrade pip
python -m pip install cicflowmeter
deactivate
```

Verify it:

```bash
.venv-cicflow/bin/cicflowmeter --help
```

If the executable is installed somewhere else, point NetraX to it:

```bash
export NETRAX_CICFLOWMETER_PATH=/absolute/path/to/cicflowmeter
```

On Windows, use the equivalent environment-variable syntax and provide the path to the installed executable. The default `.venv-cicflow/bin/cicflowmeter` path is Unix-style.

## 4. Run the Backend

From the repository root, with the main `.venv` activated:

```bash
PYTHONPATH=. python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

The API will be available at:

- API: `http://127.0.0.1:8000`
- Health check: `http://127.0.0.1:8000/api/health`
- FastAPI documentation: `http://127.0.0.1:8000/docs`

Check the health endpoint:

```bash
curl http://127.0.0.1:8000/api/health
```

Expected response shape:

```json
{
  "status": "ok",
  "service": "netrax-api",
  "version": "0.4.0"
}
```

### Windows PowerShell

If `PYTHONPATH=.` is not accepted by your shell, use:

```powershell
$env:PYTHONPATH = "."
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

## 5. Run the Frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

The Vite development server proxies `/api/*` requests to the local FastAPI service.

Keep the backend running on port `8000` while using the dashboard.

## 6. Build the Frontend for Production

```bash
cd frontend
npm install
npm run build
```

To preview the production build locally:

```bash
npm run preview
```

## 7. Using the API Directly

The main analysis endpoint accepts a file upload:

```text
POST /api/analyze
```

Supported upload types:

- `.pcap`
- `.pcapng`
- `.csv`

Example:

```bash
curl -X POST \
  -F "file=@/path/to/traffic.pcap" \
  http://127.0.0.1:8000/api/analyze
```

For CSV input, the file must contain the NetraX-compatible flow features expected by the detection pipeline. PCAP/PCAPNG files are converted to flow features by CICFlowMeter before inference.

The API currently limits uploaded files to **100 MB**.

## 8. Tests

The repository includes API integration tests and detection tests. With the Python environment activated, run:

```bash
python -m pytest
```

If `pytest` is not installed:

```bash
python -m pip install pytest
python -m pytest
```

You can also run the API integration test directly:

```bash
python -m pytest api/test_api_integration.py
```

## 9. Model Training and Evaluation

The `detection/` directory contains scripts for training/evaluating several detectors, including:

```text
detection/
├── train_portscan.py
├── train_ddos.py
├── train_dns.py
├── train_dns_v2.py
├── train_dns_ngrams.py
├── train_dns_tunnel.py
├── train_encrypted.py
└── evaluate_cicids.py
```

These scripts expect their corresponding datasets at the paths defined inside each script. Do not assume that every dataset referenced by a training script is bundled with this repository; check the script and `data/` contents before starting a training run.

For example, the PortScan and DDoS training scripts write trained models to the `detection/` directory. fileciteturn11file1 fileciteturn11file4

## 10. Important Notes About the Data

NetraX distinguishes between:

1. **Observable evidence** available from the monitored/forward direction.
2. **Responder-dependent evidence** that cannot safely be inferred when the observation point is strictly one-way.

The repository includes feature-mapping and threat-evidence metadata under `data/metadata/` to document these constraints. fileciteturn15file4

## 11. Deployment / CORS Configuration

The FastAPI service allows the local Vite development origins by default. Additional frontend origins can be supplied through:

```bash
export NETRAX_ALLOWED_ORIGINS="https://your-frontend.example.com"
```

Multiple origins can be comma-separated:

```bash
export NETRAX_ALLOWED_ORIGINS="https://example.com,https://preview.example.com"
```

For a deployed frontend, set the frontend's API URL according to the deployment environment. The frontend README contains the Vercel-specific configuration.

## 12. Troubleshooting

### `ModuleNotFoundError`

Make sure the main virtual environment is activated and reinstall the Python dependencies:

```bash
python -m pip install fastapi uvicorn python-multipart pandas numpy scikit-learn joblib pytest
```

Run the backend from the repository root with `PYTHONPATH=.`.

### `cicflowmeter` not found

Check the default executable:

```bash
ls -l .venv-cicflow/bin/cicflowmeter
```

Or configure an explicit path:

```bash
export NETRAX_CICFLOWMETER_PATH=/absolute/path/to/cicflowmeter
```

### Frontend cannot reach the API

Confirm that:

1. The backend is running on port `8000`.
2. `http://127.0.0.1:8000/api/health` returns `status: ok`.
3. The frontend is running on port `5173`.
4. You started the frontend from `frontend/`.

### PCAP upload fails

PCAP/PCAPNG processing depends on CICFlowMeter. Check that the executable works independently before debugging the NetraX API.

### CSV upload fails

A generic CSV is not necessarily a valid NetraX input. The CSV must contain the flow features expected by the relevant detector/model.

## Security and Scope

NetraX is a **passive analysis prototype**. It does not send probes, handshakes, queries, or mitigation commands back into the production network as part of its detection design.

Do not use traffic captures or datasets that you are not authorized to process. When testing with real network traffic, follow applicable organizational, privacy, and security requirements.

## Project Status

NetraX is under active development. APIs, models, feature mappings, datasets, and deployment procedures may change as the project evolves.

For the most reliable setup, use the commands in this README together with the current repository contents rather than relying on older examples or screenshots.
