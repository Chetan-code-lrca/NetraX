import joblib
import pandas as pd
from pathlib import Path
import os

from detection.pipeline import build_alert


DEFAULT_MODEL_DIR = Path(
    os.getenv("NETRAX_MODEL_DIR", "detection")
)

MODELS = {
    "PortScan": "portscan_model.joblib",
    "DDoS": "ddos_model.joblib",
}


def get_model_path(threat_class):
    if threat_class not in MODELS:
        raise ValueError(f"No model available for {threat_class}")

    return DEFAULT_MODEL_DIR / MODELS[threat_class]


def load_model(threat_class):
    """Load the trained model for a threat class."""
    return joblib.load(get_model_path(threat_class))


def detect_model(
    threat_class,
    features,
    flow_id="unknown",
    model=None,
):
    """
    Run ML inference and convert the result into a NetraX alert.
    """

    model = model or load_model(threat_class)

    feature_names = list(model.feature_names_in_)

    X = pd.DataFrame(
        [[features[name] for name in feature_names]],
        columns=feature_names
    )

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]
    classes = list(model.classes_)
    confidence = probabilities[classes.index(prediction)]

    evidence = []

    if prediction == threat_class:
        status = "DETECTED"

        # PortScan evidence
        if threat_class == "PortScan":
            if features.get(" Destination Port", 0) > 0:
                evidence.append("Destination-port fan-out")

            if features.get(" Total Fwd Packets", 0) > 0:
                evidence.append("Source-side packet behavior")

            if features.get(" Flow Duration", 0) >= 0:
                evidence.append("Flow timing")

        # DDoS evidence
        elif threat_class == "DDoS":
            if features.get(" Total Fwd Packets", 0) > 0:
                evidence.append("Source-side packet volume")

            if features.get(" Fwd Packets/s", 0) > 100:
                evidence.append("Packet/flow rate")

            if (
                features.get(" Fwd Packet Length Mean", 0) > 0
                and features.get(" Fwd Packet Length Max", 0) > 0
            ):
                evidence.append("Packet-size characteristics")

    else:
        status = "INSUFFICIENT"
        evidence.append(
            f"Model classified traffic as {prediction}"
        )

    return build_alert(
        threat_class=threat_class,
        confidence=confidence,
        status=status,
        evidence=evidence,
        flow_id=flow_id
    )