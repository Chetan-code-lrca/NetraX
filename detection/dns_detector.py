import joblib
import os
from pathlib import Path

from detection.dns_tunnel_detector import dns_tunnel_score


MODEL_DIR = Path(
    os.getenv("NETRAX_MODEL_DIR", "detection")
)
VECTORIZER_PATH = MODEL_DIR / "dns_char_vectorizer.joblib"
MODEL_PATH = MODEL_DIR / "dns_ngram_model.joblib"


def load_dns_model():
    vectorizer = joblib.load(VECTORIZER_PATH)
    model = joblib.load(MODEL_PATH)

    return vectorizer, model


def detect_dns(
    domain,
    vectorizer=None,
    model=None,
):
    """
    Unified DNS analysis.

    Returns:
        - n-gram classification/probabilities
        - tunnelling evidence score
    """

    if vectorizer is None or model is None:
        vectorizer, model = load_dns_model()

    domain = str(domain).strip().lower()

    X = vectorizer.transform([domain])

    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]
    classes = list(model.classes_)

    ngram_confidence = float(
        probabilities[classes.index(prediction)]
    )

    tunnel = dns_tunnel_score(domain)

    return {
        "domain": domain,
        "classification": int(prediction),
        "classification_confidence": round(
            ngram_confidence,
            3
        ),
        "classification_probabilities": {
            str(cls): round(float(prob), 3)
            for cls, prob in zip(classes, probabilities)
        },
        "tunnelling_score": tunnel["score"],
        "tunnelling_status": tunnel["status"],
        "tunnelling_evidence": tunnel["evidence"],
        "features": tunnel["features"],
    }
