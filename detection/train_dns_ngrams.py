import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import FeatureUnion
from sklearn.model_selection import train_test_split


DATA = "data/raw/dns_threats/train_combined_multiclass.csv.gz"
VECTORIZER_PATH = "detection/dns_char_vectorizer.joblib"
MODEL_PATH = "detection/dns_ngram_model.joblib"


df = pd.read_csv(DATA)

# Balanced sample for the first n-gram experiment
parts = []

for cls in [0, 1, 2]:
    part = df[df["class"] == cls]
    n = min(len(part), 100000)
    parts.append(part.sample(n=n, random_state=42))

sample = pd.concat(parts, ignore_index=True)

X = sample["domain"].astype(str).str.lower()
y = sample["class"]


X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2, 5),
    min_df=3,
    max_features=50000,
    sublinear_tf=True
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

print("Training matrix:", X_train_vec.shape)
print("Test matrix:", X_test_vec.shape)


model = LogisticRegression(
    max_iter=300,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(X_train_vec, y_train)

predictions = model.predict(X_test_vec)


print("\n=== CLASSIFICATION REPORT ===")
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


joblib.dump(vectorizer, VECTORIZER_PATH)
joblib.dump(model, MODEL_PATH)

print(f"\nSaved vectorizer: {VECTORIZER_PATH}")
print(f"Saved model: {MODEL_PATH}")
