"""
NetraX Unified Inference Interface

Single entry point for all currently supported threat detectors.

Supported threat classes:
    PortScan
    DDoS
    C2_Beaconing
    DGA_DNS_Tunneling
    Encrypted_Malware
    Data_Exfiltration

The dispatcher normalizes detector outputs into the standard
NetraX alert schema.

Important:
- No reverse-direction traffic is required.
- No payload decryption is performed.
- Heuristic scores are not necessarily calibrated probabilities.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

import pandas as pd

from detection.model_detector import detect_model
from detection.c2.c2_detector import c2_score
from detection.dns_detector import detect_dns
from detection.encrypted_malware_detector import (
    detect_encrypted_malware,
)
from detection.exfiltration_detector import (
    detect_exfiltration,
)
from detection.pipeline import build_alert


SUPPORTED_THREATS = (
    "PortScan",
    "DDoS",
    "C2_Beaconing",
    "DGA_DNS_Tunneling",
    "Encrypted_Malware",
    "Data_Exfiltration",
)


def _require_mapping(data: Any, threat_class: str) -> Mapping[str, Any]:
    """Validate dictionary-like detector input."""

    if not isinstance(data, Mapping):
        raise TypeError(
            f"{threat_class} requires mapping-like input, "
            f"got {type(data).__name__}"
        )

    return data


def _to_series(data: Any, threat_class: str) -> pd.Series:
    """
    Convert detector input into a pandas Series.

    Supports:
        pandas.Series
        dict-like objects
    """

    if isinstance(data, pd.Series):
        return data

    if isinstance(data, Mapping):
        return pd.Series(dict(data))

    raise TypeError(
        f"{threat_class} requires a pandas Series or mapping-like "
        f"input, got {type(data).__name__}"
    )


def predict_model(
    threat_class: str,
    features: Mapping[str, Any],
    flow_id: str = "unknown",
) -> Dict[str, Any]:
    """
    Predict PortScan or DDoS using the existing trained model.
    """

    if threat_class not in {"PortScan", "DDoS"}:
        raise ValueError(
            "predict_model only supports PortScan and DDoS"
        )

    features = _require_mapping(
        features,
        threat_class,
    )

    return detect_model(
        threat_class=threat_class,
        features=dict(features),
        flow_id=flow_id,
    )


def predict_c2(
    features: Mapping[str, Any],
    flow_id: str = "unknown",
) -> Dict[str, Any]:
    """
    Predict C2 beaconing from behavioral features.
    """

    features = _require_mapping(
        features,
        "C2_Beaconing",
    )

    score, status, evidence = c2_score(
        pd.Series(dict(features))
    )

    return build_alert(
        threat_class="C2_Beaconing",
        confidence=score,
        status=status,
        evidence=evidence,
        flow_id=flow_id,
    )


def predict_dns(
    domain: str,
    flow_id: str = "unknown",
) -> Dict[str, Any]:
    """
    Analyze a DNS domain using the existing n-gram and
    tunnelling detectors.

    The final status comes from the evidence-based tunnelling
    scorer. The n-gram classifier contributes supporting evidence
    when it classifies the domain as DNS tunnelling.
    """

    result = detect_dns(domain)

    tunnelling_status = result["tunnelling_status"]
    tunnelling_score = float(
        result["tunnelling_score"]
    )

    evidence = list(
        result.get("tunnelling_evidence", [])
    )

    # DNS n-gram classes:
    #   0 = Benign
    #   1 = DGA
    #   2 = DNS_Tunnelling
    classification = int(
        result["classification"]
    )

    if classification == 2:
        evidence.append(
            "DNS tunnelling-like character n-gram pattern"
        )

    # The tunnelling scorer determines the actual alert status.
    # Its score is used as the alert confidence because the
    # unified alert represents the final one-way threat decision.
    return build_alert(
        threat_class="DGA_DNS_Tunneling",
        confidence=tunnelling_score,
        status=tunnelling_status,
        evidence=list(
            dict.fromkeys(evidence)
        ),
        flow_id=flow_id,
    )


def predict_encrypted_malware(
    row: Any,
    flow_id: str = "unknown",
) -> Dict[str, Any]:
    """
    Predict encrypted malware from TLS/traffic metadata.
    """

    row = _to_series(
        row,
        "Encrypted_Malware",
    )

    return detect_encrypted_malware(
        row,
        flow_id=flow_id,
    )


def predict_exfiltration(
    features: Mapping[str, Any],
    flow_id: str = "unknown",
) -> Dict[str, Any]:
    """
    Predict possible Data Exfiltration using the
    one-way evidence scorer.
    """

    features = _require_mapping(
        features,
        "Data_Exfiltration",
    )

    return detect_exfiltration(
        features=dict(features),
        flow_id=flow_id,
    )


def predict(
    threat_class: str,
    data: Any,
    flow_id: str = "unknown",
) -> Dict[str, Any]:
    """
    Unified NetraX inference entry point.

    Examples:

        predict(
            "PortScan",
            cicflow_features,
            flow_id="flow-001",
        )

        predict(
            "DGA_DNS_Tunneling",
            "example-domain.test",
            flow_id="dns-001",
        )

        predict(
            "C2_Beaconing",
            behavioral_features,
            flow_id="c2-001",
        )

        predict(
            "Encrypted_Malware",
            encrypted_flow_row,
            flow_id="tls-001",
        )

        predict(
            "Data_Exfiltration",
            forward_features,
            flow_id="exfil-001",
        )
    """

    if threat_class not in SUPPORTED_THREATS:
        raise ValueError(
            f"Unsupported threat class: {threat_class}. "
            f"Supported classes: {', '.join(SUPPORTED_THREATS)}"
        )

    if threat_class in {"PortScan", "DDoS"}:
        return predict_model(
            threat_class=threat_class,
            features=data,
            flow_id=flow_id,
        )

    if threat_class == "C2_Beaconing":
        return predict_c2(
            features=data,
            flow_id=flow_id,
        )

    if threat_class == "DGA_DNS_Tunneling":
        if not isinstance(data, str):
            raise TypeError(
                "DGA_DNS_Tunneling requires a DNS domain string"
            )

        return predict_dns(
            domain=data,
            flow_id=flow_id,
        )

    if threat_class == "Encrypted_Malware":
        return predict_encrypted_malware(
            row=data,
            flow_id=flow_id,
        )

    if threat_class == "Data_Exfiltration":
        return predict_exfiltration(
            features=data,
            flow_id=flow_id,
        )

    # Defensive fallback; all supported classes are handled above.
    raise RuntimeError(
        f"No dispatcher implementation for {threat_class}"
    )


def validate_alert(alert: Mapping[str, Any]) -> None:
    """
    Validate the common NetraX alert contract.
    """

    required = {
        "timestamp",
        "flow_id",
        "threat_class",
        "confidence",
        "status",
        "evidence",
        "observability",
        "observability_status",
        "available_evidence",
        "missing_evidence",
        "evidence_coverage",
    }

    missing = required.difference(
        alert.keys()
    )

    if missing:
        raise ValueError(
            f"Alert missing required fields: "
            f"{sorted(missing)}"
        )

    if alert["status"] not in {
        "DETECTED",
        "AMBIGUOUS",
        "INSUFFICIENT",
    }:
        raise ValueError(
            f"Invalid alert status: {alert['status']}"
        )

    coverage = float(
        alert["evidence_coverage"]
    )

    if not 0.0 <= coverage <= 1.0:
        raise ValueError(
            f"Evidence coverage must be between 0 and 1, "
            f"got {coverage}"
        )

    float(alert["confidence"])


if __name__ == "__main__":
    print("Supported NetraX threats:")

    for threat in SUPPORTED_THREATS:
        print(f"  - {threat}")

    print("\nUnified inference interface ready.")
