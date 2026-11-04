"""Load and validate a strict NetraX sensor configuration (no live capture)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "sensor-config-v1.schema.json"
MAX_CONFIG_BYTES = 1_048_576


class SensorConfigError(Exception):
    """Raised when a sensor configuration is absent, invalid, or unsafe."""


@dataclass(frozen=True)
class ValidatedSensorConfig:
    values: dict
    config_sha256: str


def load_sensor_config(path: str | Path) -> ValidatedSensorConfig:
    """Load JSON config and return a canonical digest after strict validation."""
    config_path = Path(path)
    if not config_path.is_file():
        raise SensorConfigError("Sensor configuration file does not exist.")

    try:
        raw = config_path.read_bytes()
    except OSError as error:
        raise SensorConfigError("Sensor configuration cannot be read.") from error

    if not raw or len(raw) > MAX_CONFIG_BYTES:
        raise SensorConfigError(
            f"Sensor configuration must be between 1 and {MAX_CONFIG_BYTES} bytes."
        )

    try:
        values = json.loads(raw.decode("utf-8"))
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (UnicodeDecodeError, json.JSONDecodeError, OSError, ValueError) as error:
        raise SensorConfigError("Sensor configuration or schema is malformed.") from error

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(
        validator.iter_errors(values),
        key=lambda item: (tuple(str(part) for part in item.absolute_path), item.message),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path)
        raise SensorConfigError(
            f"Invalid sensor configuration at {location}: {first.message}"
        )

    # The digest is a reproducible identifier for this config content. It is
    # not a signature, certificate, or proof of trusted monitoring topology.
    canonical = json.dumps(
        values,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return ValidatedSensorConfig(
        values=values,
        config_sha256=hashlib.sha256(canonical).hexdigest(),
    )
