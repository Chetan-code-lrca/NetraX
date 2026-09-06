import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

from features.encrypted.encrypted_features import (
    extract_encrypted_features,
)


INPUT = "data/processed/encrypted_malware_dataset.pkl"
MODEL_PATH = "detection/encrypted_malware_model.joblib"


def main():
    df = pd.read_pickle(INPUT)

    print("Dataset shape:", df.shape)
    print("\nLabels:")
    print(df["label"].value_counts())

    # ---------------------------------------------------------
    # Feature extraction
    # ---------------------------------------------------------
    X = pd.DataFrame(
        [
            extract_encrypted_features(row)
            for _, row in df.iterrows()
        ]
    )

    y = df["label"].astype(int)

    print("\nFeature matrix:", X.shape)
    print("\nFeatures:")
    print(X.columns.tolist())

    # ---------------------------------------------------------
    # Train/test split
    # ---------------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    print("\nTrain samples:", len(X_train))
    print("Test samples:", len(X_test))

    # ---------------------------------------------------------
    # Model
    # ---------------------------------------------------------
    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    model.fit(
        X_train,
        y_train,
    )

    # ---------------------------------------------------------
    # Evaluation
    # ---------------------------------------------------------
    predictions = model.predict(X_test)

    print("\n=== INTERNAL TEST ===")

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Benign",
                "Encrypted_Malware",
            ],
            digits=4,
            zero_division=0,
        )
    )

    print("=== CONFUSION MATRIX ===")

    print(
        confusion_matrix(
            y_test,
            predictions,
        )
    )

    # ---------------------------------------------------------
    # Feature importance
    # ---------------------------------------------------------
    importance = (
        pd.Series(
            model.feature_importances_,
            index=X.columns,
        )
        .sort_values(ascending=False)
    )

    print("\n=== FEATURE IMPORTANCE ===")
    print(
        importance
        .head(20)
        .to_string()
    )

    # ---------------------------------------------------------
    # Save model
    # ---------------------------------------------------------
    joblib.dump(
        model,
        MODEL_PATH,
    )

    print("\nSaved model:", MODEL_PATH)


if __name__ == "__main__":
    main()