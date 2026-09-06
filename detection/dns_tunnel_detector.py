from features.dns.dns_features import extract_dns_features


# Frozen from the TRAINING distribution.
# These are approximately the 99th percentile of DGA,
# giving us a high-specificity non-tunnelling reference.
THRESHOLDS = {
    "first_label_length": 34.0,
    "first_label_entropy": 4.25,
    "first_label_digit_ratio": 0.588,
    "domain_length": 38.0,
    "entropy": 4.404,
    "digit_letter_transitions": 19.0,
}


WEIGHTS = {
    "first_label_length": 0.25,
    "first_label_entropy": 0.25,
    "first_label_digit_ratio": 0.20,
    "domain_length": 0.10,
    "entropy": 0.10,
    "digit_letter_transitions": 0.10,
}


def _first_label(domain):
    labels = [
        label
        for label in str(domain).lower().strip(".").split(".")
        if label
    ]

    return labels[0] if labels else ""


def _entropy(text):
    from collections import Counter
    import math

    if not text:
        return 0.0

    counts = Counter(text)
    total = len(text)

    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts.values()
    )


def dns_tunnel_score(domain):
    """
    Evidence-based DNS tunnelling score.

    This is NOT a calibrated probability.
    Thresholds are frozen from training data only.
    """

    features = extract_dns_features(domain)

    first = _first_label(domain)

    first_features = {
        "first_label_length": len(first),
        "first_label_entropy": _entropy(first),
        "first_label_digit_ratio": (
            sum(c.isdigit() for c in first) / len(first)
            if first else 0.0
        ),
    }

    combined = {
        **features,
        **first_features,
    }

    score = 0.0
    evidence = []

    for feature, weight in WEIGHTS.items():
        value = combined[feature]

        if value > THRESHOLDS[feature]:
            score += weight

            if feature == "first_label_length":
                evidence.append(
                    "Unusually long first DNS label"
                )
            elif feature == "first_label_entropy":
                evidence.append(
                    "High first-label character entropy"
                )
            elif feature == "first_label_digit_ratio":
                evidence.append(
                    "High first-label digit ratio"
                )
            elif feature == "domain_length":
                evidence.append(
                    "Unusually long DNS query"
                )
            elif feature == "entropy":
                evidence.append(
                    "High DNS query entropy"
                )
            elif feature == "digit_letter_transitions":
                evidence.append(
                    "Unusual digit/letter transition pattern"
                )

    # Supporting structural evidence only.
    if features["num_labels"] >= 3:
        score += 0.10
        evidence.append(
            "Multi-label DNS query structure"
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
        "features": combined,
    }