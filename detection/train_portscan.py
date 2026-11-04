import argparse

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

from detection.group_evaluation import stratified_group_holdout
from features.one_way_features import (
    ONE_WAY_FEATURE_SCHEMA_ID,
    select_one_way_training_features,
)

DATA = "data/portscan_one_way.csv"
MODEL_PATH = "detection/portscan_model.joblib"
LABEL_COLUMN = " Label"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Train PortScan using the NetraX one-way feature contract."
    )
    parser.add_argument("--data", default=DATA, help="Training CSV path.")
    parser.add_argument("--model-path", default=MODEL_PATH, help="Output model path.")
    parser.add_argument(
        "--group-column",
        required=True,
        help=(
            "Capture/source group ID column. Rows from the same capture must "
            "share one group value; this column is never used as a model feature."
        ),
    )
    return parser.parse_args()


def main():
    args = parse_args()
    df = pd.read_csv(args.data)

    if args.group_column not in df.columns:
        raise ValueError(
            f"Dataset is missing required capture group column "
            f"{args.group_column!r}. Add capture/source provenance; "
            "NetraX will not fall back to a random row-level split."
        )

    X, y = select_one_way_training_features(df, LABEL_COLUMN)
    (
        X_train,
        X_test,
        y_train,
        y_test,
        groups_train,
        groups_test,
    ) = stratified_group_holdout(
        X,
        y,
        df[args.group_column],
        n_splits=5,
        random_state=42,
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    print(f"Feature schema: {ONE_WAY_FEATURE_SCHEMA_ID}")
    print(f"Capture grouping column: {args.group_column}")
    print(
        "Independent capture groups — "
        f"train: {groups_train.nunique()}, test: {groups_test.nunique()}"
    )
    print("Features used:", list(model.feature_names_in_))
    print("\nCapture-group-disjoint classification report:")
    print(classification_report(y_test, predictions, zero_division=0))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    joblib.dump(model, args.model_path)
    print(f"\nModel saved to: {args.model_path}")


if __name__ == "__main__":
    main()
