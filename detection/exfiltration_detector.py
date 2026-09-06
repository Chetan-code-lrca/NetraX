"""
NetraX One-Way Data Exfiltration Detector

Evidence-based detection of potential data exfiltration using
only originator/forward-direction traffic features.

IMPORTANT:
- This is not a calibrated probability.
- Detection does not prove successful exfiltration.
- No responder-side or payload-dependent features are used.
"""

from typing import Any, Dict

from detection.pipeline import build_alert


THRESHOLDS = {
    "forward_bytes": 1_000_000.0,
    "forward_packets": 1_000.0,
    "forward_packet_mean": 800.0,
    "forward_packet_max": 1200.0,
    "forward_packet_rate": 100.0,
    "forward_iat_mean": 100_000.0,
    "forward_iat_std": 1_000_000.0,
}


def _num(
    features: Dict[str, Any],
    *names: str,
    default: float = 0.0,
) -> float:
    """Return the first available numeric feature."""

    for name in names:
        if name not in features:
            continue

        try:
            return float(features[name])
        except (TypeError, ValueError):
            continue

    return default


def score_exfiltration(
    features: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Calculate an evidence score for possible data exfiltration.

    Returns a dictionary containing:
        score
        status
        evidence
        features

    The score is a heuristic evidence score, NOT a probability.
    """

    forward_packets = _num(
        features,
        " Total Fwd Packets",
        "Total Fwd Packets",
        "forward_packets",
    )

    forward_bytes = _num(
        features,
        "Total Length of Fwd Packets",
        " Subflow Fwd Bytes",
        "Subflow Fwd Bytes",
        "forward_bytes",
    )

    packet_mean = _num(
        features,
        " Fwd Packet Length Mean",
        "Fwd Packet Length Mean",
        "forward_packet_mean",
    )

    packet_max = _num(
        features,
        " Fwd Packet Length Max",
        "Fwd Packet Length Max",
        "forward_packet_max",
    )

    packet_rate = _num(
        features,
        "Fwd Packets/s",
        " Fwd Packets/s",
        "forward_packet_rate",
    )

    iat_mean = _num(
        features,
        " Fwd IAT Mean",
        "Fwd IAT Mean",
        "forward_iat_mean",
    )

    iat_std = _num(
        features,
        " Fwd IAT Std",
        "Fwd IAT Std",
        "forward_iat_std",
    )

    score = 0.0
    evidence = []

    if forward_bytes >= THRESHOLDS["forward_bytes"]:
        score += 0.30
        evidence.append(
            "High outbound byte volume"
        )

    if forward_packets >= THRESHOLDS["forward_packets"]:
        score += 0.15
        evidence.append(
            "High forward packet volume"
        )

    if packet_mean >= THRESHOLDS["forward_packet_mean"]:
        score += 0.15
        evidence.append(
            "Large average forward packet size"
        )

    if packet_max >= THRESHOLDS["forward_packet_max"]:
        score += 0.10
        evidence.append(
            "Large forward packet size"
        )

    if packet_rate >= THRESHOLDS["forward_packet_rate"]:
        score += 0.15
        evidence.append(
            "Sustained outbound packet rate"
        )

    if (
        iat_mean > 0
        and iat_mean <= THRESHOLDS["forward_iat_mean"]
    ):
        score += 0.075
        evidence.append(
            "Frequent forward traffic"
        )

    if iat_std >= THRESHOLDS["forward_iat_std"]:
        score += 0.075
        evidence.append(
            "Bursty outbound traffic timing"
        )

    score = min(score, 1.0)

    if score >= 0.60:
        status = "DETECTED"
    elif score >= 0.30:
        status = "AMBIGUOUS"
    else:
        status = "INSUFFICIENT"

    return {
        "score": round(score, 3),
        "status": status,
        "evidence": list(dict.fromkeys(evidence)),
        "features": {
            "forward_packets": forward_packets,
            "forward_bytes": forward_bytes,
            "forward_packet_mean": packet_mean,
            "forward_packet_max": packet_max,
            "forward_packet_rate": packet_rate,
            "forward_iat_mean": iat_mean,
            "forward_iat_std": iat_std,
        },
    }


def detect_exfiltration(
    features: Dict[str, Any],
    flow_id: str = "unknown",
) -> Dict[str, Any]:
    """
    Convert the one-way exfiltration evidence score into
    the standard NetraX alert schema.
    """

    result = score_exfiltration(
        features
    )

    return build_alert(
        threat_class="Data_Exfiltration",

        # IMPORTANT:
        # This is the detector's evidence score, not a
        # calibrated probability.
        confidence=result["score"],

        status=result["status"],

        evidence=result["evidence"],

        flow_id=flow_id,
    )


if __name__ == "__main__":

    suspicious = {
        " Total Fwd Packets": 5000,
        "Total Length of Fwd Packets": 8_000_000,
        " Fwd Packet Length Mean": 1100,
        " Fwd Packet Length Max": 1460,
        "Fwd Packets/s": 180,
        " Fwd IAT Mean": 50_000,
        " Fwd IAT Std": 1_500_000,
    }

    benign = {
        " Total Fwd Packets": 20,
        "Total Length of Fwd Packets": 12_000,
        " Fwd Packet Length Mean": 400,
        " Fwd Packet Length Max": 800,
        "Fwd Packets/s": 5,
        " Fwd IAT Mean": 500_000,
        " Fwd IAT Std": 50_000,
    }

    print("\n=== SUSPICIOUS FLOW ===")

    alert = detect_exfiltration(
        suspicious,
        flow_id="exfil-demo-001",
    )

    for key, value in alert.items():
        print(f"{key}: {value}")

    print("\n=== BENIGN FLOW ===")

    alert = detect_exfiltration(
        benign,
        flow_id="exfil-demo-002",
    )

    for key, value in alert.items():
        print(f"{key}: {value}")