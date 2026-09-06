import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from features.dns.dns_features import extract_dns_features


INPUT = "data/raw/dns_threats/train_combined_multiclass.csv.gz"
MODEL_PATH = "detection/dns_tunnel_model.joblib"

df = pd.read_csv(INPUT)

# Tunnelling = 1
# Benign + DGA = 0
df["target"] = (df["class"] == 2).astype(int)

parts = []

# Keep all available tunnelling examples.
tunnel = df[df["target"] == 1]

# Sample an equal number of non-tunnelling examples.
non_tunnel = df[df["target"] == 0]

n = min(len(tunnel), len(non_tunnel))

non_tunnel = non_tunnel.sample(
    n=n,
    random_state=42
)

parts.append(tunnel)
parts.append(non_tunnel)

sample = pd.concat(parts, ignore_index=True)

print("Training samples:", len(sample))
print("\nTarget distribution:")
print(sample["target"].value_counts())

# Extract structural DNS features.
X = pd.DataFrame(
    [extract_dns_features(domain) for domain in sample["domain"]]
)

# Avoid using domain strings directly.
y = sample["target"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\n=== INTERNAL TEST ===")
print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Non_Tunnelling",
            "DNS_Tunnelling"
        ]
    )
)

print("=== CONFUSION MATRIX ===")
print(confusion_matrix(y_test, predictions))

joblib.dump(model, MODEL_PATH)

print(f"\nSaved model: {MODEL_PATH}")
