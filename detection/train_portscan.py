import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from features.one_way_features import (
    ONE_WAY_FEATURE_SCHEMA_ID,
    ORIGINATOR_ONLY,
    validate_one_way_feature_names,
)

DATA = "data/portscan_one_way.csv"
MODEL_PATH = "detection/portscan_model.joblib"
LABEL_COLUMN = " Label"


def main():
    df = pd.read_csv(DATA)
    if LABEL_COLUMN not in df.columns:
        raise ValueError(f"Training dataset is missing label column {LABEL_COLUMN!r}.")

    feature_names = validate_one_way_feature_names(ORIGINATOR_ONLY)
    missing = [name for name in feature_names if name not in df.columns]
    if missing:
        raise ValueError(
            f"Dataset does not satisfy {ONE_WAY_FEATURE_SCHEMA_ID}; "
            f"missing features: {missing}"
        )

    X = df.loc[:, feature_names].copy()
    y = df[LABEL_COLUMN].copy()

    if X.isna().any().any():
        raise ValueError(
            "Training features contain missing values. Resolve them explicitly "
            "before training; do not silently substitute zeros."
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    print(f"Feature schema: {ONE_WAY_FEATURE_SCHEMA_ID}")
    print("Features used:", list(model.feature_names_in_))
    print("\nClassification Report:")
    print(classification_report(y_test, predictions))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()
