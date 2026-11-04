# NetraX production-readiness gates

**Current release classification: local offline-analysis preview.**

Passing the build and unit tests proves that the software can be built and
that the tested code paths behave as expected. It does not prove that the
detectors are accurate on real networks, that the model artifacts are valid,
or that the service is safe for an internet-facing deployment.

This document defines the evidence required before making those claims. The
current feature-level discrepancy and model-validation limitations are
recorded in [ONE_WAY_FEATURE_AND_MODEL_AUDIT.md](ONE_WAY_FEATURE_AND_MODEL_AUDIT.md).

## What is implemented today

- Browser upload of PCAP, PCAPNG, and supported CSV inputs.
- Bounded upload and flow-row ingestion.
- PCAP conversion through CICFlowMeter when the executable is installed.
- Existing detector and one-way evidence pipeline.
- Input-specific runtime readiness checks.
- Local Docker Compose deployment with a loopback-only dashboard binding by
  default.
- Temporary request-scoped processing files and JSON report export.
- Backend tests, frontend dependency audit/build, container build, and CodeQL
  static analysis workflow.

## What is not production-ready yet

- No continuous capture agent, network tap integration, or streaming ingest.
- No authentication, user or tenant isolation, or role-based access control.
- No durable job queue, analysis history, or retention/deletion controls.
- No operator audit trail or production alert delivery.
- No verified production model registry or signed artifact distribution.
- No evidence in this repository that all six detector paths meet a defined
  false-positive/false-negative target on representative, held-out traffic.
- No deployment-specific load, failover, or recovery evidence.

Do not describe the current dashboard as live monitoring. It processes files
that a user uploads.

## Gate 1 — detector validity and model governance

Before enabling a model-backed detector outside a controlled evaluation:

1. Record each artifact's SHA-256, model format, framework/runtime versions,
   training-code commit, dataset names and licenses, feature schema, label
   mapping, training date, and owner.
2. Keep training, validation, and test captures separated by host, time, or
   collection source where possible. Randomly splitting adjacent flows from
   the same capture can leak environment-specific patterns between splits.
3. Report per-class precision, recall, F1, confusion matrix, and PR-AUC at the
   chosen operating threshold. Report false positives per hour or per
   monitored host where the deployment supports that measurement.
4. Evaluate calibration separately before interpreting a score as a
   probability. Until then, call it a model score.
5. Test the one-way observation constraint explicitly: remove reverse-path
   fields, compare the resulting performance, and record which evidence is
   unavailable.
6. Validate against benign traffic from the intended environment and against
   attack captures that were not used for training or threshold selection.
7. Fail closed when an artifact is missing, has an unknown schema, or cannot
   load. Never accept joblib/pickle artifacts from untrusted users.

A passing software integration test that creates a tiny synthetic model is
only a test of the API-to-model interface. It is not evidence of detector
accuracy.

## Gate 2 — secure service operation

Before exposing the service beyond a developer workstation:

- Add authentication and authorization at the API boundary; CORS is not
  authentication.
- Use TLS at the ingress, and restrict network access to the dashboard and API.
- Review the PCAP parser dependency before production use. CICFlowMeter is
  pinned and audited as a dependency, but its upstream PyPI page states that
  the project is not actively maintained and the 0.5.0 release has no
  publication provenance. Evaluate a maintained, compatible alternative or
  establish an internal fork and patch/verification process.
- Move long-running analysis to a durable bounded job queue with cancellation,
  status, retry policy, and per-job resource limits.
- Apply request size, time, row-count, CPU, memory, and process limits. The
  current API has a per-process concurrency gate; CPU/memory quotas and a
  durable queue still need deployment-level validation.
- Store captures only when necessary, encrypt them at rest, and define
  retention and deletion behavior.
- Keep secrets outside source control; rotate credentials and document the
  deployment secret-management mechanism.
- Add structured logs, request/job correlation IDs, metrics, health alerts,
  backup/recovery procedures, and an incident-response runbook.
- Generate an SBOM, scan dependencies and container images, and pin release
  artifacts to immutable digests.

The current Docker Compose profile is intended for a single-host local
workflow. Do not put it directly on a public IP.

## Gate 3 — passive sensor and ingestion

A live sensor is a separate system component, not a browser feature.

The sensor design must document:
- How traffic is copied from an approved SPAN/TAP or data-diode interface.
- Whether packet payloads are discarded after feature extraction.
- Capture filters, snap length, interface loss counters, and clock handling.
- Backpressure and bounded buffering when the analysis service is slow.
- Authenticated transport from sensor to ingest service.
- Sensor identity, configuration version, and tamper/error reporting.
- How duplicate, late, malformed, and partial flow records are handled.
- How missing direction and packet visibility are represented in every event.

Start with offline replay of known captures. Add a sensor only after replay,
loss, restart, and backpressure tests pass.

## Gate 4 — release validation

A release candidate should not be promoted until all applicable checks pass:

- Backend tests and frontend build pass on the release commit.
- Dependency audit, CodeQL, and container-image scans have no unresolved
  critical/high findings or documented risk acceptance.
- Valid, malformed, empty, oversized, and unsupported inputs return the
  expected status and do not crash the service.
- Model artifacts match the documented schema and load from the intended
  runtime image.
- Representative PCAP and CSV replay tests pass with recorded outputs.
- Load tests cover the target concurrency and maximum input size.
- A soak test demonstrates stable memory, CPU, and temporary-disk behavior.
- Restart, cancellation, timeout, and corrupted-artifact behavior are tested.
- A human operator reviews alert interpretation and false-positive handling.
- A rollback procedure and known-limitations release note are available.

## Near-term engineering order

1. Make the file-analysis path honest, bounded, testable, and safe by default.
2. Establish model provenance and reproducible detector evaluation.
3. Add a bounded background-job service and authenticated analyst workflow.
4. Add a passive sensor/ingest contract and replay it before live deployment.
5. Add monitoring, retention, operational runbooks, and controlled deployment
   packaging.

Each phase should be accepted with test data and recorded evidence before the
next phase expands the system's operational scope.
