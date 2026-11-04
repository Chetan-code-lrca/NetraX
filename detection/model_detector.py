import joblib
import pandas as pd

from detection.pipeline import build_alert
from detection.model_paths import get_model_path
from features.one_way_features import (
    ONE_WAY_FEATURE_SCHEMA_ID,
    validate_one_way_feature_names,
)


class ModelFeatureContractError(ValueError):
    """Raised when a trained model expects features outside the one-way contract."""


def validate_model_feature_contract(model):
    feature_names = getattr(model, "feature_names_in_", None)
    if feature_names is None:
        raise ModelFeatureContractError(
            "Model artifact has no named feature schema. Retrain it using a "
            "pandas DataFrame and the NetraX one-way feature contract."
        )

    try:
        return validate_one_way_feature_names(feature_names)
    except ValueError as error:
        raise ModelFeatureContractError(
            f"Model artifact is incompatible with {ONE_WAY_FEATURE_SCHEMA_ID}: {error}"
        ) from error


MODELS = {
    "PortScan": "detection/portscan_model.joblib",
    "DDoS": "detection/ddos_model.joblib",
}


def load_model(threat_class):
    """Load the trained model for a threat class."""
    if threat_class not in MODELS:
        raise ValueError(f"No model available for {threat_class}")

    model = joblib.load(get_model_path(MODELS[threat_class]))
    validate_model_feature_contract(model)
    return model


def _build_model_alert(
    threat_class,
    prediction,
    confidence,
    features,
    flow_id,
):
    """Build one alert using the existing detector semantics."""

    evidence = []

    if prediction == threat_class:
        status = "DETECTED"

        if threat_class == "PortScan":
            if features.get(" Destination Port", 0) > 0:
                evidence.append("Destination-port fan-out")

            if features.get(" Total Fwd Packets", 0) > 0:
                evidence.append("Source-side packet behavior")

            if features.get(" Fwd IAT Mean", 0) > 0:
                evidence.append("Forward inter-arrival timing")

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
        flow_id=flow_id,
    )


def detect_model(
    threat_class,
    features,
    flow_id="unknown",
    model=None,
):
    """
    Run single-row ML inference.

    Kept for compatibility with existing callers/tests.
    """
    if model is None:
        model = load_model(threat_class)

    feature_names = validate_model_feature_contract(model)

    X = pd.DataFrame(
        [[features[name] for name in feature_names]],
        columns=feature_names,
    )

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]
    classes = list(model.classes_)
    confidence = probabilities[classes.index(prediction)]

    return _build_model_alert(
        threat_class=threat_class,
        prediction=prediction,
        confidence=confidence,
        features=features,
        flow_id=flow_id,
    )


def detect_model_batch(
    threat_class,
    feature_rows,
    flow_ids,
    model=None,
):
    """
    Run batch ML inference while preserving existing alert semantics.

    The trained model is loaded once and predict/predict_proba are
    each called once for the complete batch.
    """
    if model is None:
        model = load_model(threat_class)

    if len(feature_rows) != len(flow_ids):
        raise ValueError(
            "feature_rows and flow_ids must have the same length"
        )

    feature_names = validate_model_feature_contract(model)

    if not feature_rows:
        return []

    X = pd.DataFrame(
        [
            [row[name] for name in feature_names]
            for row in feature_rows
        ],
        columns=feature_names,
    )

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)
    classes = list(model.classes_)

    alerts = []

    for row, flow_id, prediction, probability_row in zip(
        feature_rows,
        flow_ids,
        predictions,
        probabilities,
    ):
        confidence = probability_row[
            classes.index(prediction)
        ]

        alerts.append(
            _build_model_alert(
                threat_class=threat_class,
                prediction=prediction,
                confidence=confidence,
                features=row,
                flow_id=flow_id,
            )
        )

    return alerts