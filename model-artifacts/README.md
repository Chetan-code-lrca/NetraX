# NetraX model artifacts

NetraX keeps trained model binaries out of Git because they are generated from
training data and may be large. Supply the artifacts from your own verified
training/evaluation run in this directory before enabling model-based analysis.

The current model-based inference paths expect these files:

| Artifact | Detector |
| --- | --- |
| `portscan_model.joblib` | PortScan |
| `ddos_model.joblib` | DDoS |
| `dns_char_vectorizer.joblib` | DNS / DGA |
| `dns_ngram_model.joblib` | DNS / DGA |
| `encrypted_malware_model.joblib` | Encrypted-malware indicators |

C2 beaconing and data-exfiltration evidence scoring have rule/feature-based paths
and do not use one of the files above.

## PortScan and DDoS feature compatibility

PortScan and DDoS model artifacts must use the exact approved input features
defined by `schemas/feature-contracts/netrax.flow.forward.v1.json`. The
training scripts select this feature set and fail when any required field is
missing or contains missing values.

Legacy artifacts that include classic `Flow Duration`, aggregate TCP flag
counts, unknown fields, or no named `feature_names_in_` schema are rejected by
the model loader with `model_contract_invalid`. This is deliberate. Removing
columns from an old artifact does not retrain it and does not make its learned
decision function valid for the new input schema.

Retrain from the authorized one-way datasets and run the required held-out
evaluation before copying the new artifacts here:

```bash
python detection/train_portscan.py --group-column capture_id
python detection/train_ddos.py --group-column capture_id
```

Replace `capture_id` with the verified grouping column in your dataset. It
must identify the original independent capture/source, not a per-flow ID.
The scripts use a five-fold stratified group split and fail if there are fewer
than five groups, any class appears in fewer than five independent groups,
missing group IDs, or any class cannot be represented in both partitions. They never fall back to random row-level splitting.

The expected training datasets are not distributed in this repository.
Do not treat successful synthetic CI model tests as evidence of detector
accuracy. Record dataset provenance, split strategy, schema ID, artifact
SHA-256 and evaluation metrics for each deployed model.

## Local setup

After training and evaluating the models, copy the artifacts into this folder:

```bash
mkdir -p model-artifacts
cp detection/portscan_model.joblib model-artifacts/
cp detection/ddos_model.joblib model-artifacts/
cp detection/dns_char_vectorizer.joblib model-artifacts/
cp detection/dns_ngram_model.joblib model-artifacts/
cp detection/encrypted_malware_model.joblib model-artifacts/
```

For Docker Compose, this directory is mounted read-only at `/models`.
For a direct local API run, set `NETRAX_MODEL_DIR` to this directory.

**Important:** only load model files that you created or obtained from a trusted
source. Joblib/pickle artifacts can execute code when loaded. Do not accept
model uploads from untrusted users.

A fresh source checkout without these files can start the API, but model-based
analysis returns a clear model-unavailable response until the artifacts are
supplied. Do not describe the model-based detectors as operational until their
artifacts and evaluation results are available.

## First-run demonstration without model files

A fresh clone can still run the rule-based C2 behavioral path using the
synthetic dashboard sample at
`frontend/public/examples/c2-behavioral-sample.csv`. It is intentionally
labelled as synthetic and is not a real capture. This does not enable the
model-based PortScan, DDoS, DNS, or encrypted-malware paths.
