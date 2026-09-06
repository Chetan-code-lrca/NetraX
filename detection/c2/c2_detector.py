import numpy as np


FEATURES = [
    "flows_per_window",
    "unique_destinations",
    "unique_ports",
    "repeated_pairs",
    "periodic_pairs_cv1",
    "periodic_pairs_cv05",
]


def c2_score(row):
    """
    Explainable behavioral C2 score.

    Returns:
        score: 0.0 - 1.0
        status: DETECTED / AMBIGUOUS / INSUFFICIENT
        evidence: list of observed behavioral signals
    """

    score = 0.0
    evidence = []

    flows = row["flows_per_window"]
    destinations = row["unique_destinations"]
    ports = row["unique_ports"]
    repeated = row["repeated_pairs"]
    periodic = row["periodic_pairs_cv1"]
    strong_periodic = row["periodic_pairs_cv05"]

    # Traffic persistence
    if flows >= 200:
        score += 0.20
        evidence.append("High repeated flow activity")

    # Destination repetition/diversity
    if destinations >= 50:
        score += 0.25
        evidence.append("High destination diversity")

    # Multiple repeated communication pairs
    if repeated >= 8:
        score += 0.20
        evidence.append("Persistent destination-port pairs")

    # Relatively stable timing
    if periodic >= 5:
        score += 0.20
        evidence.append("Repeated low-jitter timing patterns")

    # Strong periodicity
    if strong_periodic >= 2:
        score += 0.15
        evidence.append("Strong periodic communication")

    score = min(score, 1.0)

    if score >= 0.70:
        status = "DETECTED"
    elif score >= 0.40:
        status = "AMBIGUOUS"
    else:
        status = "INSUFFICIENT"

    return round(score, 3), status, evidence
