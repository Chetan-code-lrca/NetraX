import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


MODELS = {
    "PortScan": "detection/portscan_model.joblib",
    "DDoS": "detection/ddos_model.joblib",
}


DATASETS = {
    "PortScan": (
        "data/raw/MachineLearningCVE/"
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    ),
    "DDoS": (
        "data/raw/MachineLearningCVE/"
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    ),
}


# Exact columns expected by the trained models.
MODEL_FEATURES = [
    " Destination Port",
    " Flow Duration",
    " Total Fwd Packets",
    "Total Length of Fwd Packets",
    " Fwd Packet Length Max",
    " Fwd Packet Length Min",
    " Fwd Packet Length Mean",
    " Fwd IAT Mean",
    " Fwd IAT Std",
    " Fwd IAT Max",
    " Fwd IAT Min",
    "Fwd PSH Flags",
    " Fwd URG Flags",
    " Fwd Header Length",
    "Fwd Packets/s",
    " SYN Flag Count",
    " RST Flag Count",
    " PSH Flag Count",
    " ACK Flag Count",
    " URG Flag Count",
    " CWE Flag Count",
    " ECE Flag Count",
    " Avg Fwd Segment Size",
    " Fwd Avg Packets/Bulk",
    " Fwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Init_Win_bytes_forward",
    " act_data_pkt_fwd",
    " min_seg_size_forward",
]


def clean_features(df):
    """
    Select exactly the 29 features used during model training.

    The official CICIDS2017 CSV already contains these columns,
    so no CICFlowMeter renaming is necessary here.
    """

    missing = [
        feature
        for feature in MODEL_FEATURES
        if feature not in df.columns
    ]

    if missing:
        raise KeyError(
            "Missing model features:\n"
            + "\n".join(missing)
        )

    X = df[MODEL_FEATURES].copy()

    # CICIDS2017 can contain Inf / -Inf values.
    X = X.replace(
        [float("inf"), float("-inf")],
        pd.NA,
    )

    X = X.apply(
        pd.to_numeric,
        errors="coerce",
    )

    valid = ~X.isna().any(axis=1)

    return X, valid


def evaluate(threat_class):

    print("\n" + "=" * 60)
    print(threat_class)
    print("=" * 60)

    model = joblib.load(
        MODELS[threat_class]
    )

    df = pd.read_csv(
        DATASETS[threat_class]
    )

    print(
        "Dataset rows:",
        len(df),
    )

    print("\nGround-truth distribution:")
    print(
        df[" Label"].value_counts()
    )

    X, valid = clean_features(df)

    print(
        "\nValid rows:",
        int(valid.sum()),
    )

    print(
        "Invalid rows:",
        int((~valid).sum()),
    )

    X = X.loc[valid]

    y = df.loc[
        valid,
        " Label"
    ].astype(str)

    print(
        "\nRunning batch inference..."
    )

    predictions = model.predict(X)

    # ---------------------------------------------------------
    # Metrics
    # ---------------------------------------------------------

    print("\n=== ACCURACY ===")

    print(
        round(
            accuracy_score(
                y,
                predictions,
            ),
            4,
        )
    )

    print(
        "\n=== CLASSIFICATION REPORT ==="
    )

    print(
        classification_report(
            y,
            predictions,
            labels=[
                "BENIGN",
                threat_class,
            ],
            digits=4,
            zero_division=0,
        )
    )

    print(
        "=== CONFUSION MATRIX ==="
    )

    print(
        confusion_matrix(
            y,
            predictions,
            labels=[
                "BENIGN",
                threat_class,
            ],
        )
    )


if __name__ == "__main__":

    evaluate("PortScan")

    evaluate("DDoS")