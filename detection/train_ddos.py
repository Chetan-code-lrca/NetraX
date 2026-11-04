import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from features.one_way_features import (
    ONE_WAY_FEATURE_SCHEMA_ID,
    select_one_way_training_features,
)

DATA = "data/ddos_one_way.csv"
MODEL_PATH = "detection/ddos_model.joblib"
LABEL_COLUMN = " Label"


def main():
    df = pd.read_csv(DATA)
    X, y = select_one_way_training_features(df, LABEL_COLUMN)

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
