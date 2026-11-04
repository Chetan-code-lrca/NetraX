# NetraX engineering backlog

This backlog is ordered by dependency. Do not begin downstream work before its acceptance gates pass.

## EPIC 0 — trustworthy offline baseline

- [ ] Merge and stabilize the current hardening PR only after reviewing CI and feature changes.
- [ ] Publish versioned schemas for every detector input.
- [ ] Reconcile the Flow Duration allowlist vs evidence mapping discrepancy.
- [ ] Audit all directional features against actual packet-level semantics.
- [ ] Create strict unidirectional and bidirectional PCAP fixtures with expected extracted features.
- [ ] Build model cards and SHA-256 manifests for every trained model.
- [x] Enforce the 26-feature one-way contract for PortScan/DDoS and reject responder-dependent legacy model artifacts.
- [x] Require capture-group-disjoint PortScan/DDoS holdout splits; fail closed when group provenance is missing or class coverage is impossible.
- [ ] Re-run evaluation on real datasets with capture/host/time-disjoint splits and an external dataset.
- [ ] Add calibrated-threshold and false-positive-per-host-hour reporting where data permits.
- [ ] Ensure every report exposes direction validation, schema version, detector/model version, and visibility limitations.

## EPIC 1 — Linux sensor

- [ ] Threat model the sensor and privileged capture boundary.
- [ ] Compare Zeek, libpcap/AF_PACKET and other maintained capture/flow options using a reproducible benchmark.
- [ ] Define supported Linux versions, NIC/offload assumptions, clock synchronization and mirror topology.
- [ ] Implement an allowlisted interface configuration; no default "capture everything" behavior.
- [ ] Implement bounded packet acquisition and measurable drop counters.
- [ ] Implement direction-aware flow extraction from observed packets.
- [ ] Implement local disk spool with quotas, expiry and restart recovery.
- [ ] Implement sensor heartbeat and health status.
- [ ] Implement mTLS enrollment, certificate rotation and revocation.
- [ ] Implement signed, validated configuration and safe update/rollback.
- [x] Add deterministic, non-privileged PCAP/PCAPNG replay into schema-validated telemetry v1 (Ethernet, single-interface PCAPNG only).
- [ ] Test backpressure, full disk, disconnect, clock skew, packet loss and restart.
- [ ] Prove no inline forwarding, injection or active probing code path exists.

## EPIC 2 — ingest and control plane

- [ ] Define JSON Schema and compatibility policy for telemetry v1.
- [ ] Implement sensor registry, site registry and certificate binding.
- [ ] Implement mTLS ingest gateway and strict scope enforcement.
- [ ] Implement schema/payload/rate limits.
- [ ] Implement duplicate detection and idempotent retries.
- [ ] Implement bounded durable queue and dead-letter/quarantine path.
- [ ] Implement worker autoscaling policy with hard resource ceilings.
- [ ] Select and benchmark PostgreSQL/ClickHouse/object storage topology.
- [ ] Implement retention, deletion, backup and restore.
- [ ] Add service-level metrics and traces.

## EPIC 3 — security operations console

- [ ] Replace prototype language with actual organization/site/sensor views.
- [ ] Implement authenticated users, role-based access and session security.
- [ ] Implement auditable case workflow and analyst notes.
- [ ] Implement alert grouping, deduplication, suppression and assignment.
- [ ] Implement evidence view with feature lineage and raw-source references.
- [ ] Implement report export and access auditing.
- [ ] Add tenant/site isolation tests before multi-organization support.

## EPIC 4 — production operations

- [ ] Create SBOM and scan dependencies, containers and release artifacts.
- [ ] Establish reproducible builds, release signing and provenance.
- [ ] Define upgrades, migrations, rollback and disaster recovery.
- [ ] Define data classification, retention and deletion policy.
- [ ] Complete penetration test and threat-model review.
- [ ] Load test, soak test and fault-injection test named hardware profiles.
- [ ] Create operator runbooks and incident response procedures.
- [ ] Run a controlled pilot with an organization that has approved traffic collection.

## Explicit non-goals for the first releases

- Browser extension as primary product.
- Automatic blocking or inline mitigation.
- Full packet capture by default.
- Public unauthenticated SaaS.
- Kubernetes-first implementation.
- Claims of production detector accuracy without measured external evidence.
