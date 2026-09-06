import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

DATA = "data/ddos_one_way.csv"
MODEL_PATH = "detection/ddos_model.joblib"

df = pd.read_csv(DATA)

X = df.drop(columns=[" Label"])
y = df[" Label"]

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
    n_jobs=-1
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, predictions))

print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))

joblib.dump(model, MODEL_PATH)

print(f"\nModel saved to: {MODEL_PATH}")
