"""Shared model-artifact path resolution and readiness checks for NetraX."""

import os
from pathlib import Path


MODEL_DIR_ENV_VAR = "NETRAX_MODEL_DIR"
DEFAULT_MODEL_DIR = Path(__file__).resolve().parent

# These are the files loaded by the current model-based inference routes.
REQUIRED_MODEL_ARTIFACTS = (
    "portscan_model.joblib",
    "ddos_model.joblib",
    "dns_char_vectorizer.joblib",
    "dns_ngram_model.joblib",
    "encrypted_malware_model.joblib",
)


def get_model_directory():
    """Return the configured model directory or the package default."""
    configured_dir = os.environ.get(MODEL_DIR_ENV_VAR)
    return Path(configured_dir).expanduser() if configured_dir else DEFAULT_MODEL_DIR


def get_model_path(configured_path):
    """Resolve a trusted model filename under the configured model directory.

    Only the filename is accepted from detector code. This prevents a
    configured detector path from escaping the model-artifact directory.
    """
    filename = Path(configured_path).name
    return get_model_directory() / filename


def get_model_artifact_status():
    """Describe which trained artifacts are present without loading them."""
    model_dir = get_model_directory()
    available = [
        name for name in REQUIRED_MODEL_ARTIFACTS
        if (model_dir / name).is_file()
    ]
    missing = [
        name for name in REQUIRED_MODEL_ARTIFACTS
        if name not in available
    ]
    return {
        "directory": str(model_dir),
        "required": list(REQUIRED_MODEL_ARTIFACTS),
        "available": available,
        "missing": missing,
        "ready": not missing,
    }
