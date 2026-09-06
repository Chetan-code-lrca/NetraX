import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from detection.pipeline import build_alert
from features.cicflow_adapter import adapt_cicflow_row


MODEL_PATHS = {
    "PortScan": "detection/portscan_model.joblib",
    "DDoS": "detection/ddos_model.joblib",
}


def load_model(threat_class):
    """Load the trained model for the requested threat class."""

    if threat_class not in MODEL_PATHS:
        raise ValueError(
            f"Unsupported threat class: {threat_class}"
        )

    path = MODEL_PATHS[threat_class]

    if not Path(path).exists():
        raise FileNotFoundError(
            f"Model not found: {path}"
        )

    return joblib.load(path)


def detect_input_format(df, model):
    """
    Detect whether the CSV is:

    1. NetraX 29-feature format
    2. CICFlowMeter format
    """

    feature_names = list(model.feature_names_in_)

    if all(
        feature in df.columns
        for feature in feature_names
    ):
        return "NetraX 29-feature format"

    return "CICFlowMeter format"


def prepare_feature_matrix(df, model):
    """
    Convert the complete dataframe into the model's exact
    feature order.

    Returns:
        X
        feature_names
    """

    feature_names = list(model.feature_names_in_)

    # ---------------------------------------------------------
    # Already in NetraX 29-feature format
    # ---------------------------------------------------------

    if all(
        feature in df.columns
        for feature in feature_names
    ):
        X = df[
            feature_names
        ].apply(
            pd.to_numeric,
            errors="coerce",
        )

    # ---------------------------------------------------------
    # CICFlowMeter format
    # ---------------------------------------------------------

    else:
        rows = []

        for _, row in df.iterrows():
            features = adapt_cicflow_row(
                row,
                feature_names,
            )

            rows.append(
                [
                    features[name]
                    for name in feature_names
                ]
            )

        X = pd.DataFrame(
            rows,
            columns=feature_names,
        )

        X = X.apply(
            pd.to_numeric,
            errors="coerce",
        )

    # ---------------------------------------------------------
    # Validate
    # ---------------------------------------------------------

    if X.isna().any().any():

        bad_columns = [
            column
            for column in X.columns
            if X[column].isna().any()
        ]

        raise ValueError(
            "Invalid/missing numeric values in columns: "
            + ", ".join(bad_columns)
        )

    return X, feature_names


def evidence_for_portscan(row):
    evidence = []

    if float(row.get(" Destination Port", 0)) > 0:
        evidence.append(
            "Destination-port activity"
        )

    if float(row.get(" Total Fwd Packets", 0)) > 0:
        evidence.append(
            "Source-side packet behavior"
        )

    if float(row.get("Fwd Packets/s", 0)) > 0:
        evidence.append(
            "Forward packet rate"
        )

    evidence.append("Flow timing")

    return evidence


def evidence_for_ddos(row):
    evidence = []

    if float(row.get("Fwd Packets/s", 0)) > 0:
        evidence.append(
            "Packet/flow rate"
        )

    if float(row.get(" Total Fwd Packets", 0)) > 0:
        evidence.append(
            "Source-side packet volume"
        )

    if float(
        row.get(
            "Total Length of Fwd Packets",
            0,
        )
    ) > 0:
        evidence.append(
            "Packet-size characteristics"
        )

    return evidence


def build_evidence_rows(df, threat_class):
    """
    Build observable evidence strings from each row.

    The evidence is deliberately limited to one-way fields.
    """

    evidence_rows = []

    for _, row in df.iterrows():

        if threat_class == "PortScan":
            evidence = evidence_for_portscan(row)

        elif threat_class == "DDoS":
            evidence = evidence_for_ddos(row)

        else:
            evidence = []

        evidence_rows.append(
            evidence
        )

    return evidence_rows


def run(csv_path, threat_class, output_path=None):
    """Run batch NetraX inference."""

    print("Loading model...")

    model = load_model(
        threat_class
    )

    print("Reading input...")

    df = pd.read_csv(
        csv_path
    )

    print("Input:", csv_path)
    print("Threat class:", threat_class)
    print("Rows:", len(df))

    input_format = detect_input_format(
        df,
        model,
    )

    print(
        "Input format:",
        input_format,
    )

    # ---------------------------------------------------------
    # Prepare feature matrix
    # ---------------------------------------------------------

    print("Preparing feature matrix...")

    X, feature_names = prepare_feature_matrix(
        df,
        model,
    )

    print(
        "Feature matrix:",
        X.shape,
    )

    # ---------------------------------------------------------
    # Batch inference
    # ---------------------------------------------------------

    print("Running batch prediction...")

    predictions = model.predict(X)

    probabilities = model.predict_proba(X)

    classes = list(model.classes_)

    class_to_index = {
        cls: index
        for index, cls in enumerate(classes)
    }

    # ---------------------------------------------------------
    # Evidence
    # ---------------------------------------------------------

    evidence_rows = build_evidence_rows(
        df,
        threat_class,
    )

    alerts = []

    for index, prediction in enumerate(
        predictions
    ):

        confidence = float(
            probabilities[
                index,
                class_to_index[prediction],
            ]
        )

        evidence = evidence_rows[index]

        if str(prediction) == threat_class:

            status = "DETECTED"

        else:

            status = "INSUFFICIENT"

            evidence.append(
                f"Model classified traffic as {prediction}"
            )

        alert = build_alert(
            threat_class=threat_class,
            confidence=confidence,
            status=status,
            evidence=list(
                dict.fromkeys(evidence)
            ),
            flow_id=f"{threat_class}-{index}",
        )

        alerts.append(alert)

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------

    detected = sum(
        alert["status"] == "DETECTED"
        for alert in alerts
    )

    insufficient = sum(
        alert["status"] == "INSUFFICIENT"
        for alert in alerts
    )

    print(
        "\n=== NETRAX INFERENCE SUMMARY ==="
    )

    print(
        "Processed:",
        len(alerts),
    )

    print(
        "Detected:",
        detected,
    )

    print(
        "Insufficient:",
        insufficient,
    )

    print(
        "Skipped:",
        0,
    )

    # ---------------------------------------------------------
    # Save
    # ---------------------------------------------------------

    if output_path:

        output = Path(
            output_path
        )

        output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with output.open(
            "w",
            encoding="utf-8",
        ) as f:

            for alert in alerts:

                f.write(
                    json.dumps(alert)
                    + "\n"
                )

        print(
            "Saved:",
            output,
        )

    return alerts


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Run batch NetraX PortScan/DDoS "
            "inference on NetraX or CICFlowMeter CSV."
        )
    )

    parser.add_argument(
        "--input",
        required=True,
    )

    parser.add_argument(
        "--threat",
        required=True,
        choices=[
            "PortScan",
            "DDoS",
        ],
    )

    parser.add_argument(
        "--output",
        default=None,
    )

    args = parser.parse_args()

    run(
        csv_path=args.input,
        threat_class=args.threat,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()