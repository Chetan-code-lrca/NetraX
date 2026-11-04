import copy
import hashlib
import json
import os
import time

import pytest

from netrax_sensor.spool import (
    DiskSpool,
    DuplicateEventConflict,
    SpoolCapacityError,
    SpoolCorruptionError,
    SpoolError,
    SpoolFullError,
)


ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
EVENT_PATH = ROOT / "schemas" / "examples" / "telemetry-v1.json"


def _event():
    return json.loads(EVENT_PATH.read_text(encoding="utf-8"))


def test_spool_persists_events_and_recovers_after_restart(tmp_path):
    event = _event()
    first = DiskSpool(tmp_path / "spool")
    assert first.append(event) is True
    assert first.append(event) is False

    restarted = DiskSpool(tmp_path / "spool")
    batch = restarted.read_batch()

    assert batch == [event]
    assert restarted.stats()["queued_events"] == 1
    assert restarted.acknowledge([event["event_id"]]) == 1
    assert restarted.read_batch() == []


def test_spool_requires_explicit_ack_before_deleting_events(tmp_path):
    event = _event()
    spool = DiskSpool(tmp_path / "spool")

    spool.append(event)
    first_delivery = spool.read_batch()
    second_delivery = spool.read_batch()

    assert first_delivery == second_delivery == [event]
    assert spool.stats()["queued_events"] == 1


def test_spool_rejects_same_event_id_with_different_content(tmp_path):
    event = _event()
    changed = copy.deepcopy(event)
    changed["flow"]["observed_bytes"] += 1
    spool = DiskSpool(tmp_path / "spool")

    spool.append(event)
    with pytest.raises(DuplicateEventConflict):
        spool.append(changed)


def test_spool_enforces_event_and_byte_capacity_without_dropping(tmp_path):
    event = _event()
    payload_size = len(json.dumps(event, separators=(",", ":"), sort_keys=True).encode())
    spool = DiskSpool(
        tmp_path / "spool",
        max_events=1,
        max_bytes=payload_size * 3,
        max_event_bytes=payload_size * 2,
    )
    spool.append(event)

    changed = copy.deepcopy(event)
    changed["event_id"] = "0192f6a0-3a00-7b00-8000-000000000099"
    with pytest.raises(SpoolFullError, match="event capacity"):
        spool.append(changed)

    byte_limited = DiskSpool(
        tmp_path / "small-spool",
        max_events=10,
        max_bytes=payload_size - 1,
        max_event_bytes=payload_size,
    )
    with pytest.raises(SpoolFullError, match="byte capacity"):
        byte_limited.append(event)


def test_spool_rejects_individually_oversized_event(tmp_path):
    event = _event()
    spool = DiskSpool(
        tmp_path / "spool",
        max_bytes=10000,
        max_event_bytes=100,
    )
    with pytest.raises(SpoolCapacityError, match="max_event_bytes"):
        spool.append(event)


def test_spool_purges_expired_entries_and_reports_empty_queue(tmp_path):
    event = _event()
    spool = DiskSpool(
        tmp_path / "spool",
        max_event_age_seconds=60,
    )
    spool.append(event)
    path = next((tmp_path / "spool").glob("*.json"))
    old = time.time() - 120
    os.utime(path, (old, old))

    assert spool.purge_expired() == 1
    assert spool.read_batch() == []
    assert spool.stats()["queued_events"] == 0


def test_spool_rejects_invalid_telemetry_before_persisting(tmp_path):
    event = _event()
    event.pop("sensor_id")
    spool = DiskSpool(tmp_path / "spool")

    with pytest.raises(SpoolError, match="schema validation"):
        spool.append(event)
    assert spool.stats()["queued_events"] == 0


def test_spool_detects_corrupt_queue_file(tmp_path):
    event = _event()
    spool_dir = tmp_path / "spool"
    spool = DiskSpool(spool_dir)
    filename = hashlib.sha256(event["event_id"].encode()).hexdigest() + ".json"
    (spool_dir / filename).write_text("{broken", encoding="utf-8")

    with pytest.raises(SpoolCorruptionError, match="valid JSON"):
        spool.read_batch()


def test_spool_cleans_orphaned_atomic_write_files_on_restart(tmp_path):
    directory = tmp_path / "spool"
    directory.mkdir()
    orphan = directory / ".netrax-event-interrupted.tmp"
    orphan.write_bytes(b"partial")
    DiskSpool(directory)
    assert not orphan.exists()


def test_spool_rejects_filename_that_does_not_match_event_id(tmp_path):
    event = _event()
    spool = DiskSpool(tmp_path / "spool")
    event_file = spool.directory / "wrong-name.json"
    event_file.write_text(json.dumps(event), encoding="utf-8")

    with pytest.raises(SpoolCorruptionError, match="filename does not match"):
        spool.read_batch()


def test_spool_batch_limits_are_enforced(tmp_path):
    spool = DiskSpool(tmp_path / "spool")
    with pytest.raises(ValueError, match="greater than zero"):
        spool.read_batch(max_events=0)
