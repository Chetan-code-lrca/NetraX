# Strict one-way flow feature contract

**Contract:** `netrax.flow.forward.v1`  
**Status:** Enforced for PortScan/DDoS training helpers and model inference.  
**Validation boundary:** Feature names and observability classification; not a detector-accuracy claim.

## Why this change was required

The previous `features/one_way_features.py` allowlist included nine fields that the master feature mapping classifies as responder-dependent for the flow-based detectors:

- ` Flow Duration`
- ` FIN Flag Count`
- ` SYN Flag Count`
- ` RST Flag Count`
- ` PSH Flag Count`
- ` ACK Flag Count`
- ` URG Flag Count`
- ` CWE Flag Count`
- ` ECE Flag Count`

The master mapping marks classic CICFlowMeter `Flow Duration` as a bidirectional/flow-wide value. It also marks aggregate TCP flag counters as responder-dependent because they can include packets from the reverse direction. A field being present in a CSV does not prove it is safe for one-way inference.

Forward-specific features such as `Fwd PSH Flags` and `Fwd URG Flags` remain separate and observable when computed only from packets in the monitored direction.

## Canonical contract

The machine-readable source is:

`schemas/feature-contracts/netrax.flow.forward.v1.json`

It defines 26 approved features, the observation model, schema ID/version, and the excluded legacy fields. `features/one_way_features.py` loads this file at runtime; training and model-loading code use the same allowlist.

The contract test also compares every approved feature against the master mapping for:

- PortScan
- DDoS
- Data_Exfiltration

A feature must be classified `Observable` for all three families to remain in this shared flow schema. A change to the mapping or allowlist must update the versioned contract and pass this comparison.

## Training behavior

`detection/train_portscan.py` and `detection/train_ddos.py` now use the shared `select_one_way_training_features` helper.

Training:
1. Requires the expected label column.
2. Requires every v1 feature; missing columns stop training.
3. Selects only the 26 contract features, in canonical order.
4. Rejects missing feature values rather than silently filling them.
5. Fits models on a pandas DataFrame so `feature_names_in_` is preserved.

Additional columns in a training CSV (including responder-dependent fields) are ignored by the selector. This prevents them from leaking into the trained model by accident.

## Runtime behavior and migration

Before prediction, the PortScan/DDoS model loader validates `feature_names_in_` against `netrax.flow.forward.v1`.

- Compatible named models can be used.
- Models that expect classic `Flow Duration`, aggregate flag counters, unknown features, or an unnamed feature matrix are rejected.
- The API returns `503` with error code `model_contract_invalid` and instructs the operator to retrain.
- The CICFlow adapter no longer maps those excluded legacy fields into one-way model inputs.

**Do not edit old model metadata or delete columns from an already-trained artifact.** Removing inputs changes the model's learned contract; it does not produce a valid v1 model. Retrain from authorized source data, then evaluate the new artifact.

## Important semantic distinction

A future sensor may calculate an observation-window duration from only the packets it actually sees. That measurement must have a distinct name and precise time-window semantics (for example, `observed_forward_duration_ms`). It must not be passed as the classic CICFlowMeter `Flow Duration` feature. It requires a new schema version and a model retraining/evaluation cycle.

## What this does not prove

This contract does not prove that an arbitrary PCAP contains only one direction. Capture provenance must come from a trusted sensor and approved monitoring-point configuration.

It also does not prove model accuracy. The repository does not currently contain the PortScan/DDoS training CSVs or production `.joblib` artifacts, so the corrected training scripts cannot be run against the real datasets in this change. CI uses synthetic models only to verify software behavior.

## Capture-group-disjoint evaluation

PortScan and DDoS training now require an explicit `--group-column` that
identifies the original PCAP/capture or another defensible independent source
group. They use a five-fold `StratifiedGroupKFold` holdout and require at least
five distinct groups, every label in both partitions, and zero group overlap.
Missing or unsuitable group metadata stops training; there is no random
row-level fallback.

Example (replace `capture_id` with the actual provenance column in your
derived dataset):

```bash
python detection/train_portscan.py --group-column capture_id
python detection/train_ddos.py --group-column capture_id
```

A capture identifier is not interchangeable with a flow ID. The grouping unit
must match the generalization claim: group by original capture to prevent
within-capture leakage; use host/time/site-based groups for stronger claims
where the dataset supports them. The current repository does not include the
training CSVs, so the actual group column and number of independent captures
must be confirmed before these commands can be run.

This is an internal group-disjoint holdout, not a genuinely external dataset
evaluation. DNS/encrypted model training scripts have not yet been migrated
to this evaluation policy. An external holdout, per-class precision/recall/F1,
PR-AUC, threshold selection and operational false-alert rates remain required
before any production detector-performance claim.
