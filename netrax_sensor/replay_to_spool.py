"""Replay a capture into the durable local sensor spool (no network transport)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from netrax_sensor.checkpoint import CheckpointError, ReplayCheckpointStore
from netrax_sensor.config import SensorConfigError, load_sensor_config
from netrax_sensor.pcap_replay import ReplayError, ReplayLimits, replay_capture
from netrax_sensor.spool import DiskSpool, SpoolError, SpoolFullError


REPLAY_IMPLEMENTATION_VERSION = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Replay an offline capture using a validated sensor config and "
            "enqueue telemetry into a bounded local spool. No network send occurs."
        )
    )
    parser.add_argument("--input", required=True, help="PCAP or single-interface PCAPNG input.")
    parser.add_argument("--config", required=True, help="Sensor config JSON validated against v1.")
    parser.add_argument("--spool-dir", help="Override the spool directory from the sensor config.")
    parser.add_argument("--capture-id")
    parser.add_argument("--max-file-mb", type=int, default=100)
    parser.add_argument("--max-packets", type=int, default=1_000_000)
    parser.add_argument("--max-flows", type=int, default=100_000)
    parser.add_argument("--inactivity-timeout", type=float, default=60.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    enqueued = 0
    duplicates = 0
    skipped_checkpoint = 0
    next_flow_index = 0

    try:
        if args.max_file_mb < 1:
            raise ReplayError("invalid_limit", "--max-file-mb must be at least 1.")
        config = load_sensor_config(args.config)
        values = config.values
        spool_values = values["spool"]
        spool_dir = args.spool_dir or spool_values["directory"]

        spool = DiskSpool(
            spool_dir,
            max_bytes=spool_values["max_bytes"],
            max_events=spool_values["max_events"],
            max_event_age_seconds=spool_values["max_event_age_seconds"],
            max_event_bytes=spool_values["max_event_bytes"],
        )
        limits = ReplayLimits(
            max_file_bytes=args.max_file_mb * 1024 * 1024,
            max_packets=args.max_packets,
            max_flows=args.max_flows,
            inactivity_timeout_seconds=args.inactivity_timeout,
        )
        result = replay_capture(
            args.input,
            organization_id=values["organization_id"],
            site_id=values["site_id"],
            sensor_id=values["sensor_id"],
            capture_id=args.capture_id,
            sensor_version=values["sensor_version"],
            config_version=values["config_version"],
            config_sha256=config.config_sha256,
            limits=limits,
        )

        checkpoint_store = ReplayCheckpointStore(
            spool_dir,
            ttl_seconds=spool_values["max_event_age_seconds"],
        )
        checkpoint_identity = {
            "organization_id": values["organization_id"],
            "site_id": values["site_id"],
            "sensor_id": values["sensor_id"],
            "sensor_version": values["sensor_version"],
            "config_version": values["config_version"],
            "config_sha256": config.config_sha256,
            "capture_id": result.capture_id,
            "capture_sha256": result.capture_sha256,
            "replay_contract": "netrax.flow.observed.v1",
            "replay_implementation": REPLAY_IMPLEMENTATION_VERSION,
        }
        next_flow_index = checkpoint_store.load(
            checkpoint_identity,
            expected_total_flows=result.flow_count,
        )

        try:
            for index, event in enumerate(result.iter_events()):
                if index < next_flow_index:
                    skipped_checkpoint += 1
                    continue

                if spool.append(event):
                    enqueued += 1
                else:
                    duplicates += 1

                # Advance only after the event is durably present in the spool.
                next_flow_index = index + 1
                checkpoint_store.save(
                    checkpoint_identity,
                    next_flow_index=next_flow_index,
                    total_flows=result.flow_count,
                )
        except SpoolFullError as error:
            summary = result.summary()
            summary.update({
                "status": "partial",
                "error_code": "spool_full",
                "message": str(error),
                "events_enqueued": enqueued,
                "duplicate_events": duplicates,
                "flows_skipped_from_checkpoint": skipped_checkpoint,
                "next_flow_index": next_flow_index,
                "spool": spool.stats(),
                "retry_behavior": (
                    "Replay progress is checkpointed after each durable spool "
                    "append. After queued events are acknowledged or expire, "
                    "rerun the same command to continue from next_flow_index."
                ),
            })
            print(json.dumps(summary, indent=2, sort_keys=True), file=sys.stderr)
            return 3

        summary = result.summary()
        summary.update({
            "events_enqueued": enqueued,
            "duplicate_events": duplicates,
            "flows_skipped_from_checkpoint": skipped_checkpoint,
            "checkpoint_complete": next_flow_index == result.flow_count,
            "spool": spool.stats(),
            "network_requests_sent": 0,
        })
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except (ReplayError, SensorConfigError, SpoolError, CheckpointError, OSError, ValueError) as error:
        code = getattr(error, "code", "sensor_replay_failed")
        message = getattr(error, "message", str(error))
        print(
            json.dumps({
                "status": "error",
                "error_code": code,
                "message": message,
                "events_enqueued_before_error": enqueued,
                "duplicate_events_before_error": duplicates,
            }),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
