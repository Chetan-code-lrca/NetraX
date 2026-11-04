import json

from netrax_sensor.config import load_sensor_config
from netrax_sensor.replay_to_spool import main
from netrax_sensor.spool import DiskSpool
from netrax_sensor.test_pcap_replay import _ethernet_ipv4_tcp, _write_pcap


ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
CONFIG = ROOT / "schemas" / "examples" / "sensor-config-v1.json"


def _spool_for(directory):
    config = load_sensor_config(CONFIG)
    values = config.values["spool"]
    return DiskSpool(
        directory,
        max_bytes=values["max_bytes"],
        max_events=values["max_events"],
        max_event_age_seconds=values["max_event_age_seconds"],
        max_event_bytes=values["max_event_bytes"],
    )


def test_replay_to_spool_enqueues_valid_events_without_network_transport(tmp_path, capsys):
    capture = tmp_path / "capture.pcap"
    packet = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    _write_pcap(capture, [(1000.0, packet)])
    spool_dir = tmp_path / "spool"

    exit_code = main([
        "--input", str(capture),
        "--config", str(CONFIG),
        "--spool-dir", str(spool_dir),
    ])

    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["events_enqueued"] == 1
    assert result["duplicate_events"] == 0
    assert result["network_requests_sent"] == 0

    config = load_sensor_config(CONFIG)
    queued = _spool_for(spool_dir).read_batch()
    assert len(queued) == 1
    assert queued[0]["config_sha256"] == config.config_sha256
    assert queued[0]["direction_validation"]["status"] == "unverified"


def test_replay_to_spool_is_idempotent_for_same_capture_and_config(tmp_path, capsys):
    capture = tmp_path / "capture.pcap"
    packet = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    _write_pcap(capture, [(1000.0, packet)])
    spool_dir = tmp_path / "spool"
    args = [
        "--input", str(capture),
        "--config", str(CONFIG),
        "--spool-dir", str(spool_dir),
    ]

    assert main(args) == 0
    capsys.readouterr()
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)

    assert result["events_enqueued"] == 0
    assert result["duplicate_events"] == 1
    assert result["spool"]["queued_events"] == 1


def test_replay_to_spool_uses_config_digest_in_event_identity(tmp_path, capsys):
    capture = tmp_path / "capture.pcap"
    packet = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    _write_pcap(capture, [(1000.0, packet)])
    config_values = json.loads(CONFIG.read_text(encoding="utf-8"))
    config_values["config_version"] = "cfg-0002"
    second_config = tmp_path / "sensor-config-v2.json"
    second_config.write_text(json.dumps(config_values), encoding="utf-8")
    spool_dir = tmp_path / "spool"

    assert main([
        "--input", str(capture),
        "--config", str(CONFIG),
        "--spool-dir", str(spool_dir),
    ]) == 0
    capsys.readouterr()
    assert main([
        "--input", str(capture),
        "--config", str(second_config),
        "--spool-dir", str(spool_dir),
    ]) == 0
    result = json.loads(capsys.readouterr().out)

    assert result["events_enqueued"] == 1
    assert result["duplicate_events"] == 0
    assert result["spool"]["queued_events"] == 2
