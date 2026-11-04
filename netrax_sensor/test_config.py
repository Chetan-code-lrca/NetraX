import json
from pathlib import Path

import pytest

from netrax_sensor.config import SensorConfigError, load_sensor_config


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "schemas" / "examples" / "sensor-config-v1.json"


def _config():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def _write(tmp_path, values):
    path = tmp_path / "sensor-config.json"
    path.write_text(json.dumps(values), encoding="utf-8")
    return path


def test_example_config_validates_and_has_stable_canonical_digest():
    first = load_sensor_config(EXAMPLE)
    second = load_sensor_config(EXAMPLE)

    assert first.values["passive_mode"] is True
    assert first.config_sha256 == second.config_sha256
    assert len(first.config_sha256) == 64


def test_config_rejects_non_passive_mode(tmp_path):
    config = _config()
    config["passive_mode"] = False

    with pytest.raises(SensorConfigError, match="Invalid sensor configuration"):
        load_sensor_config(_write(tmp_path, config))


def test_config_requires_explicit_interface_allowlist(tmp_path):
    config = _config()
    config["capture"]["interfaces"] = []

    with pytest.raises(SensorConfigError, match="interfaces"):
        load_sensor_config(_write(tmp_path, config))


def test_config_rejects_wildcard_interface_name(tmp_path):
    config = _config()
    config["capture"]["interfaces"] = ["any"]

    with pytest.raises(SensorConfigError, match="interfaces"):
        load_sensor_config(_write(tmp_path, config))


def test_config_requires_nonempty_capture_filter(tmp_path):
    config = _config()
    config["capture"]["capture_filter"] = ""

    with pytest.raises(SensorConfigError, match="capture_filter"):
        load_sensor_config(_write(tmp_path, config))


def test_config_rejects_duplicate_interfaces(tmp_path):
    config = _config()
    config["capture"]["interfaces"] = ["eno2", "eno2"]

    with pytest.raises(SensorConfigError, match="interfaces"):
        load_sensor_config(_write(tmp_path, config))


def test_config_rejects_unknown_fields(tmp_path):
    config = _config()
    config["capture"]["allow_all_interfaces"] = True

    with pytest.raises(SensorConfigError, match="allow_all_interfaces"):
        load_sensor_config(_write(tmp_path, config))
