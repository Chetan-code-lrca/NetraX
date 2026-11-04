"""Versioned feature contract for strictly one-direction CIC flow models."""

import json
from pathlib import Path


FEATURE_CONTRACT_PATH = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "feature-contracts"
    / "netrax.flow.forward.v1.json"
)

try:
    _CONTRACT = json.loads(
        FEATURE_CONTRACT_PATH.read_text(encoding="utf-8")
    )
except (OSError, json.JSONDecodeError) as error:
    raise RuntimeError(
        f"Cannot load NetraX feature contract at {FEATURE_CONTRACT_PATH}"
    ) from error

ONE_WAY_FEATURE_SCHEMA_ID = _CONTRACT["schema_id"]
ONE_WAY_FEATURE_SCHEMA_VERSION = _CONTRACT["version"]
ORIGINATOR_ONLY = list(_CONTRACT["allowed_features"])
ONE_WAY_FEATURES = tuple(ORIGINATOR_ONLY)
RESPONDER_DEPENDENT_LEGACY_FEATURES = tuple(
    item["name"] for item in _CONTRACT["excluded_legacy_features"]
)


if len(ONE_WAY_FEATURES) != len(set(ONE_WAY_FEATURES)):
    raise RuntimeError(
        f"Duplicate feature names in {ONE_WAY_FEATURE_SCHEMA_ID}"
    )


def get_one_way_features(columns):
    """Return v1 features present in columns, preserving contract order."""
    available = set(columns)
    return [column for column in ONE_WAY_FEATURES if column in available]


def select_one_way_training_features(frame, label_column):
    """Select the exact v1 feature set and label from a training DataFrame."""
    if label_column not in frame.columns:
        raise ValueError(
            f"Training dataset is missing label column {label_column!r}."
        )

    missing = [
        name for name in ONE_WAY_FEATURES
        if name not in frame.columns
    ]
    if missing:
        raise ValueError(
            f"Dataset does not satisfy {ONE_WAY_FEATURE_SCHEMA_ID}; "
            f"missing features: {missing}"
        )

    feature_names = validate_one_way_feature_names(ONE_WAY_FEATURES)
    features = frame.loc[:, feature_names].copy()
    if features.isna().any().any():
        raise ValueError(
            "Training features contain missing values. Resolve them explicitly "
            "before training; do not silently substitute zeros."
        )
    return features, frame[label_column].copy()


def unsupported_one_way_features(feature_names):
    """Return model features that are not approved by the v1 contract."""
    approved = set(ONE_WAY_FEATURES)
    return [
        str(name)
        for name in feature_names
        if name not in approved
    ]


def validate_one_way_feature_names(feature_names):
    """Validate a model's named input features against the v1 contract."""
    names = list(feature_names)
    if not names:
        raise ValueError(
            "Model has no named input features; retrain it using a pandas "
            "DataFrame and the NetraX one-way feature contract."
        )

    unsupported = unsupported_one_way_features(names)
    if unsupported:
        raise ValueError(
            "Model uses features outside "
            f"{ONE_WAY_FEATURE_SCHEMA_ID}: {unsupported}. "
            "Retrain the model with the approved one-way feature set."
        )
    return names
