# NetraX — Architecture and interview guide

This document explains the system in terms you should be able to demonstrate
and defend. Do not claim that a detector is production-validated unless you
have the corresponding evaluation report and model artifact.

## 1. The problem

Many network monitoring systems rely on observing both directions of a
connection. NetraX explores a narrower problem: what can be detected when a
sensor receives only a one-way copy of traffic?

The key engineering constraint is **partial observability**. A detector must
not pretend that reverse-direction fields or unavailable packet metadata were
observed. NetraX therefore attaches evidence and observability information to
its findings.

## 2. What a user can do

The current product workflow is offline capture analysis:

1. Upload an authorized PCAP/PCAPNG file or supported flow CSV.
2. Convert packet captures into flow records when CICFlowMeter is available.
3. Route the resulting data to a compatible detector contract.
4. Run the existing detection and one-way evidence pipeline.
5. Review findings in the dashboard and export a JSON report.

This is not a live network sensor. The browser does not capture packets, and
the application does not block, quarantine, or reconfigure hosts.

## 3. System architecture

| Component | Responsibility | Why it is separate |
| --- | --- | --- |
| React dashboard | Upload, progress, results, filtering, report export | User interface should not implement security detection |
| FastAPI API | Validate uploads, manage temporary workspaces, expose health/readiness and analysis endpoints | Central place for input and service boundaries |
| CICFlowMeter adapter | Convert PCAP/PCAPNG to tabular flow records | Packet parsing is a distinct external dependency |
| Input-contract detection | Identify the supported CSV feature schema | The detector should receive the data shape it expects |
| Detection modules | PortScan, DDoS, C2, DNS, encrypted-malware and exfiltration indicators | Each detector can be tested and evaluated independently |
| Separability/evidence layer | Describe what can and cannot be inferred from one-way observations | Prevents unsupported conclusions from incomplete data |
| Docker Compose | Run API and static dashboard together | Reproducible local setup without manually starting two processes |

## 4. Request lifecycle

The normal analysis request is:

```text
Browser -> POST /api/analyze
        -> validate filename extension
        -> stream upload to a generated temporary path
        -> enforce the 100 MB upload limit
        -> convert PCAP if needed
        -> read no more than 100,000 flow rows
        -> detect supported input contract
        -> run the appropriate detector(s)
        -> enrich and validate alert evidence
        -> return summary and up to 500 findings
        -> display findings / export JSON report
```

Uploads are written to a server-generated temporary filename. The user-supplied
filename is metadata only; it is not used as a filesystem path. The temporary
workspace is deleted after the request finishes.

## 5. Why these implementation choices?

### FastAPI

The existing detection code is Python. FastAPI provides a thin HTTP boundary
without forcing the detector modules into a web framework. The expensive
analysis function runs in a worker thread so the asynchronous upload route
does not execute the CPU/blocking analysis directly on the event loop.

### Temporary upload workspace

A capture can be large and must be processed by an external converter. A
request-scoped temporary directory keeps intermediate files isolated and
ensures they are removed after the request. It also avoids using the uploaded
filename as a path.

### Bounded ingestion

The API caps file uploads at 100 MB. CSV reading is bounded to 100,001 rows
(the configured limit plus one detection row) so an oversized CSV is rejected
before building an unbounded dataframe. CICFlowMeter conversion has a timeout.

### Model artifacts are not committed

Trained `.joblib` artifacts are generated outputs and can be large. They are
kept outside source control and are mounted/configured at runtime. The
`/api/readiness` endpoint checks their presence without deserializing them.
The runtime only loads trusted artifacts when the relevant detector is used.

### Docker Compose

One command builds and runs the API and the pre-built React dashboard.
Nginx serves static files and proxies `/api/` to FastAPI, so the browser uses
one origin in the local deployment. The API container is not published as a
host port by default.

### JSON report

The browser exports the analysis response plus generation time and scope
limitations. This creates a portable result without adding a database,
accounts, or a complex reporting service.

## 6. Detection and observability terms

- **DETECTED**: the detector produced a positive finding under its current
  logic/model.
- **AMBIGUOUS**: the available evidence supports review but is not sufficient
  for a decisive finding.
- **INSUFFICIENT**: the available evidence did not support a positive finding.
- **Available evidence**: evidence categories visible to the current sensor/input.
- **Missing evidence**: evidence that would improve the decision but is not
  present in the observed direction.
- **Confidence**: the detector's score. Unless calibration has been measured,
  do not present it as the probability that an attack occurred.

The exact semantics are implemented in the alert and separability modules.
When explaining a detector, open its implementation and trace one real
input row through feature preparation, prediction/scoring, and alert building.

## 7. Five-minute demo

Before the demo:

1. Make sure the trusted model artifacts are present.
2. Run `docker compose up --build`.
3. Open `http://localhost:8080/api/readiness` and resolve any missing
   dependencies shown there.
4. Prepare a small capture/flow CSV that you are authorized to use.

During the demo:

1. Open `http://localhost:8080`.
2. Upload the prepared file and run analysis. On a fresh clone without model
   artifacts, use the dashboard's synthetic C2 sample link to exercise the
   rule-based path.
3. Pick one finding and explain its evidence, missing evidence, and
   observability status.
4. Download the JSON report and open it to show that the output is portable.
5. Explain why no automatic mitigation occurs.

Never use a fabricated screenshot or a hand-written alert as proof that a
model works. Use the actual API response from a reproducible test capture.

## 8. Questions you should be able to answer

**Why is this called passive?**

It observes a supplied capture or passive copy and does not send probes or
intervention commands into the monitored network.

**Why not put all logic in the React frontend?**

The frontend is untrusted client code and should not carry model files or
security decisions. The backend validates input and runs the detector in a
controlled environment.

**Why have a readiness endpoint if there is already a health endpoint?**

Health answers whether the API process is alive. Readiness explains whether
optional runtime dependencies needed for full analysis (model artifacts and
PCAP conversion) are available.

**Why aren't model files in Git?**

They are generated binary artifacts and may be large. They should be versioned
and distributed through a trusted artifact process with provenance, rather
than committed blindly into source history.

**Can the dashboard inspect live traffic by itself?**

No. A separate passive capture agent and a secure ingest design are needed
for continuous monitoring. The dashboard only uploads and presents files in
the current release.

**Does 95% confidence mean 95% chance of an attack?**

Not automatically. Model scores need calibration on representative validation
data before they can be interpreted as real-world probabilities.

**What would be needed before exposing this to the public internet?**

Authentication/authorization, TLS, rate and concurrency limits, a queue for
long-running analysis, storage/retention controls, audit logging, monitoring,
and a deployment-specific threat model. The current Compose setup is a
reproducible single-host deployment, not a fully managed multi-tenant SOC
platform.

## 9. Current limitations

- Model artifacts are not included in the repository.
- Model performance depends on the supplied artifact and its training data.
- CSV inputs must match one of the implemented detector contracts.
- PCAP processing depends on CICFlowMeter and is time/resource bounded.
- The API has no user accounts, persistent analysis history, or multi-tenant
  access control.
- Continuous capture, alert streaming, automated response, and distributed
  processing are outside the current release scope.

These are explicit boundaries, not features to pretend are complete.
