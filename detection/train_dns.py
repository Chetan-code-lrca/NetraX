import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

DATA = "data/dns_features_train.csv"
MODEL_PATH = "detection/dns_model.joblib"

df = pd.read_csv(DATA)

X = df.drop(columns=["class"])
y = df["class"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("=== CLASSIFICATION REPORT ===")
print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Benign",
            "DGA",
            "DNS_Tunnelling"
        ]
    )
)

print("=== CONFUSION MATRIX ===")
print(confusion_matrix(y_test, predictions))

joblib.dump(model, MODEL_PATH)

print(f"\nSaved model: {MODEL_PATH}")
