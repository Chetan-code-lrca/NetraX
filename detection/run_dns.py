from detection.dns_detector import detect_dns
from detection.pipeline import build_alert


def analyze_dns(domain, flow_id="dns-unknown"):
    result = detect_dns(domain)

    classification = result["classification"]
    tunnel_status = result["tunnelling_status"]

    evidence = list(result["tunnelling_evidence"])

    if classification == 1:
        evidence.append("DGA-like character n-gram pattern")

    elif classification == 2:
        evidence.append("DNS tunnelling-like character n-gram pattern")

    evidence = list(dict.fromkeys(evidence))

    # Strong agreement between the two detectors.
    if classification == 2 and tunnel_status == "DETECTED":
        status = "DETECTED"
        confidence = max(
            result["classification_confidence"],
            result["tunnelling_score"],
        )

    # Suspicious evidence without sufficient agreement.
    elif classification == 2 or tunnel_status == "AMBIGUOUS":
        status = "AMBIGUOUS"
        confidence = max(
            result["classification_confidence"],
            result["tunnelling_score"],
        )

    else:
        status = "INSUFFICIENT"
        confidence = result["classification_confidence"]

    threat_class = (
        "DGA_DNS_Tunneling"
        if classification in (1, 2) or tunnel_status != "INSUFFICIENT"
        else "DGA_DNS_Tunneling"
    )

    return build_alert(
        threat_class=threat_class,
        confidence=confidence,
        status=status,
        evidence=evidence,
        flow_id=flow_id,
    )


if __name__ == "__main__":
    tests = [
        "namazvakti",
        "r5r5sp3et32",
        "pafiifcy.securitytesting.online",
        "3eabapdnggydixon2aaaedrlp55zvgcamdmoehp2zp313hh4j5cibdeylkmqih.yddcaeir2gls.securitytesting.online",
    ]

    for i, domain in enumerate(tests, 1):
        alert = analyze_dns(
            domain,
            flow_id=f"dns-demo-{i}",
        )

        print("\n==============================")
        print("DOMAIN:", domain)

        for key, value in alert.items():
            print(f"{key}: {value}")
