import os
import time

import pytest

from netrax_sensor.checkpoint import CheckpointError, ReplayCheckpointStore


IDENTITY = {
    "organization_id": "org-test",
    "site_id": "site-test",
    "sensor_id": "sensor-test",
    "config_sha256": "a" * 64,
    "capture_sha256": "b" * 64,
    "replay_contract": "netrax.flow.observed.v1",
    "replay_implementation": "0.1.0",
}


def test_checkpoint_round_trip_persists_next_index(tmp_path):
    store = ReplayCheckpointStore(tmp_path / "spool")
    store.save(IDENTITY, next_flow_index=7, total_flows=20)

    restarted = ReplayCheckpointStore(tmp_path / "spool")
    assert restarted.load(IDENTITY, expected_total_flows=20) == 7


def test_checkpoint_rejects_changed_total_flow_count(tmp_path):
    store = ReplayCheckpointStore(tmp_path / "spool")
    store.save(IDENTITY, next_flow_index=7, total_flows=20)

    with pytest.raises(CheckpointError, match="flow count changed"):
        store.load(IDENTITY, expected_total_flows=21)


def test_checkpoint_uses_distinct_identity_for_new_replay_version(tmp_path):
    store = ReplayCheckpointStore(tmp_path / "spool")
    store.save(IDENTITY, next_flow_index=7, total_flows=20)

    changed = dict(IDENTITY, replay_implementation="0.2.0")
    assert store.load(changed, expected_total_flows=20) == 0


def test_checkpoint_cleans_orphaned_temp_files_on_restart(tmp_path):
    directory = tmp_path / "spool" / ".checkpoints"
    directory.mkdir(parents=True)
    orphan = directory / ".netrax-checkpoint-interrupted.tmp"
    orphan.write_bytes(b"partial")

    ReplayCheckpointStore(tmp_path / "spool")
    assert not orphan.exists()


def test_checkpoint_purges_expired_progress(tmp_path):
    store = ReplayCheckpointStore(tmp_path / "spool", ttl_seconds=60)
    store.save(IDENTITY, next_flow_index=3, total_flows=20)
    path = store._path(IDENTITY)
    old = time.time() - 120
    os.utime(path, (old, old))

    restarted = ReplayCheckpointStore(tmp_path / "spool", ttl_seconds=60)
    assert restarted.load(IDENTITY, expected_total_flows=20) == 0


def test_checkpoint_capacity_is_bounded(tmp_path):
    store = ReplayCheckpointStore(tmp_path / "spool", max_records=1)
    store.save(IDENTITY, next_flow_index=1, total_flows=2)

    another = dict(IDENTITY, sensor_id="sensor-other")
    with pytest.raises(CheckpointError, match="capacity reached"):
        store.save(another, next_flow_index=1, total_flows=2)


def test_checkpoint_rejects_non_object_json_payload(tmp_path):
    store = ReplayCheckpointStore(tmp_path / "spool")
    path = store._path(IDENTITY)
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(CheckpointError, match="JSON object"):
        store.load(IDENTITY, expected_total_flows=2)


def test_checkpoint_rejects_boolean_indexes_and_invalid_totals(tmp_path):
    store = ReplayCheckpointStore(tmp_path / "spool")
    path = store._path(IDENTITY)
    path.write_text(
        json.dumps({
            "identity": IDENTITY,
            "next_flow_index": True,
            "total_flows": 2,
        }),
        encoding="utf-8",
    )
    with pytest.raises(CheckpointError, match="next_flow_index"):
        store.load(IDENTITY, expected_total_flows=2)

    with pytest.raises(ValueError, match="must be an integer"):
        store.save(IDENTITY, next_flow_index=True, total_flows=2)


def test_checkpoint_rejects_out_of_range_index(tmp_path):
    store = ReplayCheckpointStore(tmp_path / "spool")
    with pytest.raises(ValueError, match="within the capture flow count"):
        store.save(IDENTITY, next_flow_index=3, total_flows=2)
