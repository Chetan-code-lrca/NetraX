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
