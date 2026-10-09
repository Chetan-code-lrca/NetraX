"""Shared model-artifact path resolution for NetraX inference."""

import os
from pathlib import Path


MODEL_DIR_ENV_VAR = "NETRAX_MODEL_DIR"
DEFAULT_MODEL_DIR = Path(__file__).resolve().parent


def get_model_path(configured_path):
    """Resolve a trusted model filename under the configured model directory.

    ``NETRAX_MODEL_DIR`` is optional. When unset, model artifacts are read
    from this package's ``detection/`` directory, matching the training
    scripts' default output paths.
    """
    filename = Path(configured_path).name
    configured_dir = os.environ.get(MODEL_DIR_ENV_VAR)
    model_dir = Path(configured_dir) if configured_dir else DEFAULT_MODEL_DIR
    return model_dir / filename
