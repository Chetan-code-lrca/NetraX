# NetraX one-way feature and model-evaluation audit

**Audit status: open. No production-validation claim is approved by this document.**

This review was performed against the source currently in `main` on
2026-11-04. It is a code and documentation review, not a re-evaluation of
the underlying models: the trained artifacts and derived training CSVs are
not present in the repository tree, so their contents cannot currently be
reproduced or inspected.

## Findings

### 1. The directional feature contract is inconsistent

Two repository sources currently disagree about at least one important
feature:

- `features/one_way_features.py` includes ` Flow Duration` in
  `ORIGINATOR_ONLY`.
- `data/metadata/MASTER_Feature_Mapping_Deliverable_A.csv` classifies
  PortScan `Flow Duration` as `Responder-dependent`.

The metadata also classifies several aggregate TCP flag counters (including
SYN/RST/PSH/ACK/URG) as responder-dependent, while the one-way feature
allowlist includes forward-direction flag counters such as
`Fwd PSH Flags`, `Fwd URG Flags` and aggregate flag counters.

This does not prove the training data leaked reverse-direction information.
It does mean that the current repository does not provide one unambiguous,
machine-enforced answer about which fields are safe under a strict one-way
capture. The feature contract must be reconciled before a model is called
one-way validated.

Required resolution:
1. Define precisely what “one-way” means for the deployed sensor: physical
   direction of the mirror, TCP initiator/originator direction, or a
   flow record whose reverse direction was intentionally removed.
2. For every feature, document how it is computed from only the packets
   actually visible to that sensor.
3. Generate a canonical, versioned feature schema from that definition.
4. Assert at training time and inference time that the model feature list is
   a subset of the approved schema. Fail closed on an unknown or forbidden
   field.
5. Rebuild and evaluate affected artifacts only after the schema is fixed.

Do not silently delete or rename a feature from a deployed model. That changes
the model input contract and requires retraining, a new artifact version, and
a regression/evaluation run.

### 2. Current training scripts do not establish capture-independent validation

The PortScan, DDoS, DNS, and encrypted-training scripts use ordinary
random stratified train/test splits. These are useful for an initial
engineering baseline, but by themselves they do not establish that a model
generalizes to a different day, host, capture, or network environment.

A flow-level random split can place highly related observations from the same
capture or host in both training and test partitions. This is a risk to
investigate, not proof that leakage occurred in a particular artifact.

Required evaluation:
- Keep train/validation/test capture groups disjoint where capture IDs are
  available; otherwise use documented time- or host-based holdouts.
- Preserve class proportions where possible, but do not sacrifice group
  separation to force stratification.
- Report the grouping unit, dataset/source hashes, dataset license, row
  counts, label distributions, and any exclusions.
- Report per-class precision, recall, F1, confusion matrix, PR-AUC and
  threshold selection. Include operational false alerts per host-hour or
  equivalent when data allows.
- Run a genuinely external evaluation on a dataset/capture source not used
  for feature selection, threshold setting, or training.
- Re-evaluate on strictly one-way packet captures and compare with the
  bidirectional baseline.

### 3. The actual deployed model artifacts are not in source control

The repository documents five required model files, but excludes the trained
joblib artifacts. The repository tests construct tiny synthetic models to
check integration contracts. Those tests verify wiring, not accuracy.

No operator should infer detector quality from:
- API health or readiness;
- a successful Docker build;
- an integration test using synthetic models;
- a positive result from the bundled synthetic C2 CSV; or
- preliminary separability results on CICIDS2017.

Every artifact needs a model card and provenance record containing at least:
artifact SHA-256, detector name, schema version, training-code commit,
framework versions, dataset provenance/license, split manifest, label
mapping, threshold, metrics, calibration status, and approval owner.

### 4. PCAP feature semantics must be tested against actual one-way captures

NetraX uses CICFlowMeter to turn packet captures into flow CSV records.
The deployment must not assume that a familiar column name means a feature
was calculated under the correct visibility assumptions.

For each approved one-way PCAP fixture:
- record which physical direction was captured;
- record whether the reverse path is absent by construction;
- compare extracted flow rows to independently computed expected values;
- verify that no reverse-only values are synthesized or inferred;
- test missing, truncated, out-of-order, and asymmetric traffic;
- record sensor drop counters and capture limits.

A bidirectional CICIDS CSV is not a substitute for a strict one-way replay
fixture.

## Release decision

Until the directional schema conflict is resolved and model artifacts have
reproducible provenance plus group-separated/external evaluation, classify
NetraX as an **offline-analysis engineering preview**. The software may be
used for controlled experiments with authorized data, but its six named
detector categories must not be marketed as production-validated protection.
