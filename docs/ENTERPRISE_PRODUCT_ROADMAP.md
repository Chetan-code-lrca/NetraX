# NetraX Enterprise — product roadmap

**Status:** Architecture baseline and engineering roadmap  
**Release classification:** Research / engineering preview. Not a production network detection system.

## Product objective

NetraX is an organization-focused passive network security monitoring and investigation platform. It observes traffic copies at approved network monitoring points, derives flow-level telemetry, detects suspicious behavior, and gives security analysts evidence they can inspect.

NetraX is not an inline firewall, endpoint agent, browser extension, vulnerability scanner, or automated response product. It must not inject packets, disrupt traffic, or claim visibility into packets that were not observed.

## Product principles

1. **Passive by construction.** Sensors receive traffic copies from an approved TAP, SPAN/mirror, or equivalent source. There is no inline forwarding path.
2. **Evidence before conclusions.** Every detection records the observations, feature schema, detector/model version, limitations, and provenance behind it.
3. **Visibility is explicit.** Direction, capture loss, sampling, truncation, time quality, and missing fields must be represented. An arbitrary PCAP is direction-unverified.
4. **Fail closed on trust boundaries.** Sensors authenticate; schemas are versioned; model artifacts are trusted, hashed, and compatibility-checked; unknown data is rejected or quarantined.
5. **Bounded resource use.** Capture buffers, queues, file sizes, processing concurrency, timeouts, retention, and retry policies are explicit.
6. **Self-hosted first.** The first organization deployment is a single-customer, self-hosted installation. Hybrid and SaaS are later deployment profiles, not assumed requirements.
7. **Operational honesty.** Health means a component is alive; readiness means a capability is available; neither means detector accuracy is validated.

## Target users

- Network administrator: sites, sensors, interfaces, capture coverage, and sensor health.
- SOC analyst: alerts, timelines, evidence, triage, and investigation cases.
- Detection engineer: feature contracts, rule tuning, model versions, and benchmark results.
- Security manager: coverage, incident outcomes, service health, retention, and reports.
- Organization administrator: accounts, roles, certificates, policies, and audit.

## System context

```text
Organization networks
  |-- Office / campus
  |-- Data center
  |-- Branch locations
  |-- Cloud VPC / VNet
       |
       | traffic copy from approved TAP / SPAN / cloud mirror
       v
NetraX sensor
  |-- capture health and loss counters
  |-- directional/visibility metadata
  |-- bounded flow extraction
  |-- local bounded spool
  |-- mutually authenticated telemetry client
       |
       v
Secure ingest boundary
  |-- sensor identity and authorization
  |-- schema/version validation
  |-- replay/duplicate protection
  |-- rate and payload limits
  |-- tenant/site/sensor context
       |
       v
Durable bounded queue
       |
       v
Detection workers
  |-- feature contract validation
  |-- deterministic rules
  |-- ML detectors
  |-- evidence/separability
  |-- alert correlation and suppression
       |
       +--> telemetry store
       +--> incident/metadata database
       +--> optional restricted packet evidence object store
       |
       v
NetraX Security Console
  |-- overview / coverage
  |-- assets / sites / sensors
  |-- flows / traffic analytics
  |-- threat detections
  |-- investigations / cases
  |-- reports / audit / administration
```

## Release plan and acceptance gates

### R0 — trustworthy offline analysis (current foundation)

Deliver:
- Explicit capability/readiness reporting.
- Bounded file ingestion and analysis concurrency.
- Honest file-analysis UI; no fabricated live state.
- Stable, versioned input and alert contracts.
- Per-analysis capture-direction validation state.
- Trusted model manifest, SHA-256, model schema, runtime compatibility, provenance and evaluation.
- Golden fixtures for supported PCAP/CSV paths.
- Strict one-way feature contract and held-out evaluation.

Acceptance:
- API rejects malformed, unsupported, oversized, and over-capacity inputs with documented responses.
- Model load failures are safe and observable.
- Every report includes input hash, tool versions, model/rule versions, feature schema version, direction state, and limitations.
- Strict one-way claims are supported by a verified capture source and fixtures.
- Group-separated and external evaluation results are reproducible.

### R1 — NetraX Linux sensor (first live-network component)

**Initial non-privileged replay slice implemented:** classic PCAP and
single-interface Ethernet PCAPNG can be replayed into schema-validated
telemetry v1. Replay is direction-unverified and does not open a live
interface. See [Sensor Replay](SENSOR_REPLAY.md).

Remaining live-sensor deliverables:
- A dedicated Linux sensor service, initially unprivileged except for the minimal capture capability.
- Explicit interface allowlist and passive capture mode.
- Capture loss, packet counts, timestamps, truncation and interface state metrics.
- Bounded packet/flow processing and disk spool.
- Versioned sensor manifest and telemetry envelope.
- Mutual TLS identity, enrollment and revocation.
- Replay tool to feed deterministic PCAP fixtures through exactly the same pipeline.

Acceptance:
- Prove no forwarding/packet injection path exists.
- Verify traffic-copy-only deployment in a lab.
- Test loss, burst load, backpressure, disk-full, disconnect/reconnect, clock skew, restart, malformed packets and revocation.
- Verify captured direction from the configured mirror topology; never infer it from filename or file extension.
- Publish resource use and measured capture-loss limits for named hardware and traffic profiles.

### R2 — single-organization control plane

Deliver:
- Sensor registry and enrollment workflow.
- Secure telemetry ingest API.
- Schema validation and durable bounded queue.
- Idempotency and duplicate handling.
- PostgreSQL for organizations, users, sites, sensors, policies and cases.
- ClickHouse (or another benchmark-selected store) for flow telemetry.
- Object storage only for explicitly retained evidence.
- Worker pool and bounded per-tenant processing.
- Sensor configuration and version rollouts.

Acceptance:
- Authentication/authorization tests at every endpoint.
- Sensor certificate rotation and revocation tests.
- Queue durability, replay and recovery tests.
- Tenant/site scoping tests even in the first single-org release.
- Load tests with declared throughput, latency, storage and retention budgets.

### R3 — Security Operations Console

Deliver:
- Organization overview and coverage map.
- Site, asset and sensor inventory.
- Detection feed with filtering and evidence explanations.
- Case creation, assignment, comments, triage state and audit.
- Role-based access: admin, detection engineer, analyst, read-only.
- Searchable timelines and report exports.
- Alert routing integrations after secure secret management is implemented.

Acceptance:
- Every analyst action is auditable.
- Evidence is immutable or has versioned provenance.
- Access-control and data-export tests pass.
- Retention and deletion policies are enforceable and observable.

### R4 — hybrid and managed deployments

Only after the self-hosted product is validated:
- Cloud control plane with customer-hosted sensors.
- Tenant isolation and tenant-key strategy.
- Per-tenant retention, export, deletion and residency policy.
- High availability, backup/restore, disaster recovery and upgrades.
- SaaS operational readiness and service-level objectives.

## Initial technology direction

This is a proposed stack; each choice requires a small validation spike before commitment.

| Area | Starting choice | Decision rule |
|---|---|---|
| Sensor runtime | Linux service, Python orchestration; native capture/feature components where profiling requires | Validate packet loss, CPU, memory, privileges |
| Packet capture | libpcap/AF_PACKET or a proven flow sensor | Prefer mature parsers; compare Zeek and alternatives |
| Local spool | Bounded disk-backed queue | Survive restart and temporary disconnect |
| Sensor transport | HTTPS/mTLS initially | Add streaming transport only when justified |
| Ingest API | FastAPI initially | Explicit auth, schema and rate limits |
| Durable queue | NATS JetStream or equivalent | Benchmark delivery, persistence and operations |
| Detection workers | Python, existing detector modules | Versioned schemas and reproducible environments |
| Operational DB | PostgreSQL | Transactional metadata and case management |
| Flow analytics | ClickHouse after benchmark | High-cardinality queries and retention cost |
| Evidence storage | S3-compatible object storage | Encryption, lifecycle, access logs |
| Console | React + TypeScript | Reuse existing frontend foundations |
| Packaging | Docker Compose for initial self-hosted stack | Kubernetes only when operational scale requires it |
| Observability | OpenTelemetry + Prometheus/Grafana | Standard traces, metrics and structured logs |

## Data classes and retention

- **Flow telemetry:** normalized, minimized metadata; default retention must be configured by the customer.
- **Packet evidence:** disabled by default; explicit policy, narrow scope, access logging, encryption and short retention.
- **Operational records:** users, policies, sensor inventory and cases; PostgreSQL with audit history.
- **Security secrets:** certificates and keys managed outside the repository and never stored in telemetry.
- **Model artifacts:** trusted distribution, cryptographic digest, compatibility metadata and approval record.

Never put full packet payloads, credentials, API keys, private certificates, or unrestricted customer data into application logs.

## Enterprise non-functional requirements

- Authentication and role-based authorization.
- Sensor mTLS, revocation, and key rotation.
- TLS at every network boundary.
- No public unauthenticated API.
- Explicit resource caps, timeouts, queue depth and backpressure.
- Durable, idempotent telemetry ingestion.
- Audit trails for administration, configuration, evidence access, and exports.
- Configurable retention and verifiable deletion.
- Backup/restore and upgrade/rollback procedures.
- SBOM, dependency and container scanning, signed release artifacts.
- Threat model, security review, and incident-response runbook.
- Accessibility and operator-focused UX.
- Performance claims tied to reproducible hardware/network test profiles.

## Out of scope until a separate product decision

- Browser extension as primary product.
- Inline firewall / automatic blocking.
- Endpoint detection and response.
- Full packet retention by default.
- Multi-tenant SaaS before tenant isolation is proven.
- AI assistant features that cannot cite underlying evidence.
- Kubernetes-first deployment.

## Decision log

- Product audience: organizations.
- Primary first deployment: self-hosted, single organization.
- Initial customer profile: mid-sized organization, subject to pilot feedback.
- Initial sensor: dedicated Linux passive sensor.
- Default telemetry policy: flow metadata only; selective packet evidence only by explicit policy.
- Browser extension: not part of the core product.
- Live capture: not claimed until sensor and capture-provenance gates pass.
