# NetraX

NetraX is a passive cyber-threat detection system for environments where traffic is observed in a strictly one-way direction. It was developed around Smart India Hackathon problem statement SIH26145.

The system combines flow-feature extraction, threat-specific detectors, and a One-Way Threat Separability Engine. Alerts are classified as `DETECTABLE`, `WEAKLY-SEPARABLE`, or `NOT-SEPARABLE` according to the evidence available from the observed direction.

## Detects

- Port scanning
- DDoS traffic
- C2 / botnet beaconing
- DNS threats and tunneling
- Encrypted-malware indicators
- Data-exfiltration indicators

## Architecture

```text
traffic / PCAP / CSV
        │
        ▼
feature extraction
        │
        ▼
threat detection
        │
        ▼
one-way separability
        │
        ▼
evidence-aware alerts
        │
   ┌────┴────┐
   ▼         ▼
FastAPI    React/Vite
```

## Repository structure

```text
NetraX/
├── api/
├── detection/
├── features/
├── separability/
├── streaming/
├── data/metadata/
├── frontend/
└── README.md
```

## Requirements

- Git
- Python 3.12+
- Node.js and npm for the dashboard
- CICFlowMeter for PCAP/PCAPNG conversion

## Setup

Clone the repository:

```bash
git clone https://github.com/Chetan-code-lrca/NetraX.git
cd NetraX
```

Create the Python environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install fastapi uvicorn python-multipart pandas numpy scikit-learn joblib pytest
```

For Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install fastapi uvicorn python-multipart pandas numpy scikit-learn joblib pytest
```

### CICFlowMeter

PCAP and PCAPNG uploads are converted to flow features with CICFlowMeter. The backend looks for the executable at `.venv-cicflow/bin/cicflowmeter` by default.

```bash
python3.12 -m venv .venv-cicflow
source .venv-cicflow/bin/activate
python -m pip install --upgrade pip
python -m pip install cicflowmeter
deactivate
```

You can override the path with:

```bash
export NETRAX_CICFLOWMETER_PATH=/absolute/path/to/cicflowmeter
```

## Run the API

From the repository root:

```bash
PYTHONPATH=. python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Useful endpoints:

```text
http://127.0.0.1:8000/api/health
http://127.0.0.1:8000/docs
```

## Run the dashboard

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

The Vite development server proxies `/api/*` to the local FastAPI service.

## Analyze a file through the API

```bash
curl -X POST \
  -F "file=@/path/to/traffic.pcap" \
  http://127.0.0.1:8000/api/analyze
```

Supported uploads:

- `.pcap`
- `.pcapng`
- `.csv`

CSV files must already contain the flow features expected by the detectors. Uploaded files are limited to 100 MB by the API.

## Tests

```bash
python -m pytest
```

The API integration test can also be run directly:

```bash
python -m pytest api/test_api_integration.py
```

## Model training

Training and evaluation scripts live under `detection/`, including PortScan, DDoS, DNS, DNS tunneling, encrypted-malware, and CICIDS evaluation workflows. Dataset paths are defined by the individual scripts, while threat and feature mappings are kept under `data/metadata/`.

## Configuration

The API supports `NETRAX_ALLOWED_ORIGINS` for additional frontend origins and `NETRAX_CICFLOWMETER_PATH` for a custom CICFlowMeter executable.

## Security and scope

NetraX is a passive analysis project. It is designed to observe traffic rather than send probes or mitigation commands into the monitored network.

Use only traffic captures and datasets you are authorized to process.

## Project status

NetraX is under active development. Detection models, feature mappings, APIs, and deployment configuration may change as the project evolves.
