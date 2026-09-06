"""
NetraX One-Way Threat Separability Engine

Determines how observable a threat is when only one direction
of network traffic is available.
"""

THREAT_PROFILES = {
    "PortScan": {
        "observability": "HIGH",
        "status": "DETECTABLE",
        "available_evidence": [
            "Destination-port fan-out",
            "Destination-host fan-out",
            "Source-side packet behavior",
            "Flow timing"
        ],
        "missing_evidence": [
            "Reverse traffic",
            "Target response"
        ]
    },

    "DDoS": {
        "observability": "HIGH",
        "status": "DETECTABLE",
        "available_evidence": [
            "Packet/flow rate",
            "Source-side packet volume",
            "Destination concentration",
            "Protocol distribution",
            "Packet-size characteristics"
        ],
        "missing_evidence": [
            "Target response",
            "Mitigation outcome"
        ]
    },

    "C2_Beaconing": {
        "observability": "MEDIUM",
        "status": "WEAKLY-SEPARABLE",
        "available_evidence": [
            "Repeated destination-port communication",
            "Connection frequency",
            "Inter-arrival timing",
            "Periodicity",
            "Timing jitter",
            "Destination persistence"
        ],
        "missing_evidence": [
            "Reverse traffic",
            "Application response",
            "Command/response confirmation"
        ]
    },

    "DGA_DNS_Tunneling": {
        "observability": "MEDIUM",
        "status": "WEAKLY-SEPARABLE",
        "available_evidence": [
            "DNS query names",
            "Query length",
            "Character entropy",
            "N-gram characteristics",
            "Query frequency"
        ],
        "missing_evidence": [
            "DNS response",
            "Resolution success"
        ]
    },

    "Encrypted_Malware": {
        "observability": "MEDIUM",
        "status": "WEAKLY-SEPARABLE",
        "available_evidence": [
            "TLS/QUIC metadata",
            "Packet sizes",
            "Packet timing",
            "Flow duration",
            "JA3/JA3S/JA4 when available"
        ],
        "missing_evidence": [
            "Encrypted payload",
            "Application content",
            "Server response"
        ]
    },

    "Data_Exfiltration": {
        "observability": "MEDIUM",
        "status": "WEAKLY-SEPARABLE",
        "available_evidence": [
            "Outbound byte volume",
            "Flow duration",
            "Destination persistence",
            "Packet-size patterns",
            "Source-side traffic timing"
        ],
        "missing_evidence": [
            "Reverse traffic",
            "Payload contents",
            "Confirmation of successful transfer"
        ]
    }
}


def get_separability(threat_class):
    """
    Return the one-way observability profile for a threat.
    """

    if threat_class not in THREAT_PROFILES:
        return {
            "observability": "UNKNOWN",
            "status": "INSUFFICIENT",
            "available_evidence": [],
            "missing_evidence": [
                "Threat profile not defined"
            ]
        }

    return THREAT_PROFILES[threat_class].copy()


def enrich_alert(alert):
    """
    Add one-way observability information to a detection alert.
    """

    threat_class = alert.get("threat_class")
    profile = get_separability(threat_class)

    alert = alert.copy()
    observed = alert.get("evidence", [])
    expected = profile["available_evidence"]

    matched = []

    for item in observed:
        text = item.lower()

        # C2
        if "periodic" in text or "jitter" in text:
            matched.extend(["Periodicity", "Timing jitter"])

        elif "destination-port" in text:
            matched.append("Repeated destination-port communication")

        elif "persistent" in text:
            matched.append("Destination persistence")

        elif "flow" in text or "connection" in text:
            matched.append("Connection frequency")

        elif "inter-arrival" in text:
            matched.append("Inter-arrival timing")

        # PortScan
        elif "port fan-out" in text:
            matched.append("Destination-port fan-out")

        elif "host fan-out" in text:
            matched.append("Destination-host fan-out")

        elif "source-side packet behavior" in text:
            matched.append("Source-side packet behavior")

        elif "flow timing" in text:
            matched.append("Flow timing")

        # DDoS
        elif "packet/flow rate" in text:
            matched.append("Packet/flow rate")

        elif "source-side packet volume" in text:
            matched.append("Source-side packet volume")

        elif "destination concentration" in text:
            matched.append("Destination concentration")

        elif "protocol distribution" in text:
            matched.append("Protocol distribution")

        elif "packet-size" in text:
            matched.append("Packet-size characteristics")

    matched = list(set(matched))

    evidence_coverage = (
        len(matched) / len(expected)
        if expected else 0.0
    )

    alert["observability"] = profile["observability"]
    alert["observability_status"] = profile["status"]
    alert["available_evidence"] = profile["available_evidence"]
    alert["missing_evidence"] = profile["missing_evidence"]
    alert["evidence_coverage"] = round(evidence_coverage, 2)

    return alert
