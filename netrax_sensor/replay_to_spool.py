"""Replay a capture into the durable local sensor spool (no network transport)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from netrax_sensor.config import SensorConfigError, load_sensor_config
from netrax_sensor.pcap_replay import ReplayError, ReplayLimits, replay_capture
from netrax_sensor.spool import DiskSpool, SpoolError, SpoolFullError


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

        try:
            for event in result.iter_events():
                if spool.append(event):
                    enqueued += 1
                else:
                    duplicates += 1
        except SpoolFullError as error:
            summary = result.summary()
            summary.update({
                "status": "partial",
                "error_code": "spool_full",
                "message": str(error),
                "events_enqueued": enqueued,
                "duplicate_events": duplicates,
                "spool": spool.stats(),
                "retry_behavior": (
                    "Event IDs are deterministic for this capture and sensor "
                    "configuration. After queued events are acknowledged or "
                    "expire, rerun the same command to enqueue remaining events."
                ),
            })
            print(json.dumps(summary, indent=2, sort_keys=True), file=sys.stderr)
            return 3

        summary = result.summary()
        summary.update({
            "events_enqueued": enqueued,
            "duplicate_events": duplicates,
            "spool": spool.stats(),
            "network_requests_sent": 0,
        })
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except (ReplayError, SensorConfigError, SpoolError, OSError, ValueError) as error:
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
