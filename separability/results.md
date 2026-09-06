# NetraX — Initial One-Way Separability Results

## PortScan

Dataset:
- CICIDS2017
- 286,467 flows
- 29 one-way features

Evaluation:
- Chronological 70/30 split
- Decision Tree
- Max depth: 3
- Features:
  - Fwd Packet Length Mean
  - Total Fwd Packets

Result:
- Accuracy: ~97%
- PortScan F1: ~97%
- PortScan Recall: ~99%

Interpretation:
PortScan appears highly separable using limited originator-side
traffic information.

---

## DDoS

Dataset:
- CICIDS2017
- 225,745 flows
- 29 one-way features

Evaluation:
- Chronological 70/30 split
- Decision Tree
- Max depth: 3
- Same two features as PortScan

Result:
- Accuracy: ~100%
- DDoS F1: ~99%
- DDoS Recall: ~100%

Interpretation:
DDoS also appears highly separable using limited originator-side
traffic information.

---

## Important limitation

These are preliminary results from CICIDS2017.

They should NOT be presented as proof that NetraX is universally
100% accurate.

The purpose of these experiments is to measure how well individual
threat classes remain distinguishable under one-way observation.
