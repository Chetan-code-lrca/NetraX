"""Bounded, unprivileged PCAP/PCAPNG replay into NetraX telemetry v1.

This module reads offline captures only. It does not open a live interface,
send packets, or attest that the capture was taken from a one-way mirror.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import struct
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator

import dpkt


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAPNG_BOM_LE = b"\x4d\x3c\x2b\x1a"
PCAPNG_BOM_BE = b"\x1a\x2b\x3c\x4d"
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_PACKET_BLOCK = 0x00000002
PCAPNG_SIMPLE_PACKET_BLOCK = 0x00000003
PCAPNG_ENHANCED_PACKET_BLOCK = 0x00000006

SUPPORTED_LINKTYPE = dpkt.pcap.DLT_EN10MB
DEFAULT_MAX_FILE_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_PACKETS = 1_000_000
DEFAULT_MAX_FLOWS = 100_000
DEFAULT_MAX_PACKET_BYTES = 262_144
DEFAULT_INACTIVITY_TIMEOUT_SECONDS = 60.0


class ReplayError(Exception):
    """Safe, user-facing error raised by the offline replay pipeline."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ReplayLimits:
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_packets: int = DEFAULT_MAX_PACKETS
    max_flows: int = DEFAULT_MAX_FLOWS
    max_packet_bytes: int = DEFAULT_MAX_PACKET_BYTES
    inactivity_timeout_seconds: float = DEFAULT_INACTIVITY_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        for name in ("max_file_bytes", "max_packets", "max_flows", "max_packet_bytes"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be greater than zero.")
        if self.max_packet_bytes > DEFAULT_MAX_PACKET_BYTES:
            raise ValueError(
                f"max_packet_bytes cannot exceed {DEFAULT_MAX_PACKET_BYTES}."
            )
        if self.inactivity_timeout_seconds <= 0:
            raise ValueError("inactivity_timeout_seconds must be greater than zero.")


@dataclass
class FlowAccumulator:
    src: str
    dst: str
    protocol: str
    src_port: int
    dst_port: int
    first_seen: float
    last_seen: float
    min_timestamp: float
    max_timestamp: float
    observed_packets: int = 0
    observed_bytes: int = 0

    def add(self, timestamp: float, frame_bytes: int) -> None:
        self.observed_packets += 1
        self.observed_bytes += frame_bytes
        self.min_timestamp = min(self.min_timestamp, timestamp)
        self.max_timestamp = max(self.max_timestamp, timestamp)
        self.last_seen = max(self.last_seen, timestamp)


@dataclass
class ReplayResult:
    capture_path: str
    capture_sha256: str
    capture_id: str
    file_format: str
    snap_length_bytes: int
    packets_seen: int
    packets_dropped: None
    malformed_packets: int
    unsupported_packets: int
    fragmented_packets: int
    out_of_order_timestamps: int
    flows: list[FlowAccumulator] = field(default_factory=list)
    organization_id: str = ""
    site_id: str = ""
    sensor_id: str = ""
    sensor_version: str = "0.1.0"
    config_version: str = "offline-replay-v1"

    @property
    def flow_count(self) -> int:
        return len(self.flows)

    def summary(self) -> dict:
        return {
            "status": "complete",
            "mode": "offline_replay",
            "capture_id": self.capture_id,
            "capture_sha256": self.capture_sha256,
            "file_format": self.file_format,
            "packets_seen": self.packets_seen,
            "packets_dropped": None,
            "malformed_packets": self.malformed_packets,
            "unsupported_packets": self.unsupported_packets,
            "fragmented_packets": self.fragmented_packets,
            "out_of_order_timestamps": self.out_of_order_timestamps,
            "flows_emitted": self.flow_count,
            "direction_validation": "unverified",
            "packet_payloads_retained": False,
        }

    def iter_events(self) -> Iterator[dict]:
        for index, flow in enumerate(self.flows):
            identity = (
                f"{self.capture_sha256}:{index}:{flow.src}:{flow.src_port}:"
                f"{flow.dst}:{flow.dst_port}:{flow.protocol}:"
                f"{flow.min_timestamp:.9f}:{flow.max_timestamp:.9f}"
            )
            event_id = "replay-" + hashlib.sha256(
                identity.encode("utf-8")
            ).hexdigest()[:40]
            yield {
                "schema_name": "netrax.flow",
                "schema_version": 1,
                "event_id": event_id,
                "event_time": _utc_iso(flow.min_timestamp),
                "organization_id": self.organization_id,
                "site_id": self.site_id,
                "sensor_id": self.sensor_id,
                "sensor_version": self.sensor_version,
                "config_version": self.config_version,
                "capture_id": self.capture_id,
                "capture_sha256": self.capture_sha256,
                "direction_validation": {
                    "status": "unverified",
                    "direction": "unknown",
                    "reason": (
                        "Offline file replay has no trusted sensor/interface "
                        "provenance. File contents alone cannot prove that the "
                        "source capture observed only one network direction."
                    ),
                },
                "capture_health": {
                    "packets_seen": self.packets_seen,
                    "packets_dropped": None,
                    "drop_counter_unavailable_reason": (
                        "Offline PCAP/PCAPNG files do not provide trustworthy "
                        "capture-interface drop counters."
                    ),
                    "clock_source": "pcap_timestamp_unverified",
                    "clock_offset_ms": None,
                    "clock_offset_unavailable_reason": (
                        "Capture clock synchronization metadata is not verified."
                    ),
                    "snap_length_bytes": self.snap_length_bytes,
                    "interface_id": "pcap-file-interface-0",
                    "capture_filter_id": "not-recorded-or-not-verified",
                },
                "feature_schema_id": "netrax.flow.observed.v1",
                "flow": {
                    "src": flow.src,
                    "dst": flow.dst,
                    "protocol": flow.protocol,
                    "src_port": flow.src_port,
                    "dst_port": flow.dst_port,
                    "observed_packets": flow.observed_packets,
                    "observed_bytes": flow.observed_bytes,
                    "observed_duration_ms": max(
                        0.0,
                        (flow.max_timestamp - flow.min_timestamp) * 1000.0,
                    ),
                },
            }


def _utc_iso(timestamp: float) -> str:
    try:
        value = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as error:
        raise ReplayError(
            "invalid_timestamp",
            "Capture contains a timestamp outside the supported UTC range.",
        ) from error
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_single_interface_pcapng(path: Path) -> None:
    """Reject multi-section or multi-interface PCAPNG files.

    dpkt's pcapng reader exposes the first interface's link type and yields
    packet bytes without the per-packet interface ID. Restricting this replay
    implementation to one section and one interface prevents it from silently
    interpreting packets captured with a different link type.
    """
    with path.open("rb") as handle:
        header = handle.read(12)
        if len(header) != 12 or header[:4] != PCAPNG_MAGIC:
            raise ReplayError("invalid_pcapng", "Invalid PCAPNG section header.")

        bom = header[8:12]
        if bom == PCAPNG_BOM_LE:
            endian = "<"
        elif bom == PCAPNG_BOM_BE:
            endian = ">"
        else:
            raise ReplayError("invalid_pcapng", "PCAPNG byte-order marker is invalid.")

        section_count = 1
        interface_count = 0
        first_length = struct.unpack(endian + "I", header[4:8])[0]
        if first_length < 28 or first_length % 4:
            raise ReplayError("invalid_pcapng", "PCAPNG section block length is invalid.")
        remaining = handle.read(first_length - 12)
        if len(remaining) != first_length - 12:
            raise ReplayError("invalid_pcapng", "PCAPNG section header is truncated.")
        if struct.unpack(endian + "I", remaining[-4:])[0] != first_length:
            raise ReplayError("invalid_pcapng", "PCAPNG section block length trailer is invalid.")

        while True:
            block_header = handle.read(8)
            if not block_header:
                break
            if len(block_header) != 8:
                raise ReplayError("invalid_pcapng", "PCAPNG block header is truncated.")

            if block_header[:4] == PCAPNG_MAGIC:
                raise ReplayError(
                    "unsupported_pcapng_layout",
                    "Multi-section PCAPNG files are not supported by this replay version.",
                )
            block_type, block_length = struct.unpack(endian + "II", block_header)
            if block_length < 12 or block_length % 4:
                raise ReplayError("invalid_pcapng", "PCAPNG block length is invalid.")

            block_tail = handle.read(block_length - 8)
            if len(block_tail) != block_length - 8:
                raise ReplayError("invalid_pcapng", "PCAPNG block is truncated.")
            if struct.unpack(endian + "I", block_tail[-4:])[0] != block_length:
                raise ReplayError("invalid_pcapng", "PCAPNG block length trailer is invalid.")

            if block_type == PCAPNG_SHB:
                section_count += 1
                if section_count > 1:
                    raise ReplayError(
                        "unsupported_pcapng_layout",
                        "Multi-section PCAPNG files are not supported by this replay version.",
                    )
            elif block_type == PCAPNG_IDB:
                interface_count += 1
                if interface_count > 1:
                    raise ReplayError(
                        "unsupported_pcapng_layout",
                        "Multi-interface PCAPNG files are not supported by this replay version.",
                    )
            elif block_type in (PCAPNG_PACKET_BLOCK, PCAPNG_ENHANCED_PACKET_BLOCK):
                if interface_count != 1:
                    raise ReplayError(
                        "invalid_pcapng",
                        "PCAPNG packet blocks must follow the single interface description block.",
                    )
                if len(block_header) + len(block_tail) < 12:
                    raise ReplayError("invalid_pcapng", "PCAPNG packet block is truncated.")
                interface_id = struct.unpack(endian + "I", block_tail[:4])[0]
                if interface_id != 0:
                    raise ReplayError(
                        "unsupported_pcapng_layout",
                        "PCAPNG packet references an interface other than interface 0.",
                    )
            elif block_type == PCAPNG_SIMPLE_PACKET_BLOCK:
                # Simple Packet Blocks implicitly belong to interface 0.
                if interface_count != 1:
                    raise ReplayError(
                        "invalid_pcapng",
                        "PCAPNG packet blocks must follow the single interface description block.",
                    )

        if interface_count != 1:
            raise ReplayError(
                "unsupported_pcapng_layout",
                "PCAPNG replay requires exactly one interface description block.",
            )


def _open_capture(path: Path):
    try:
        with path.open("rb") as probe:
            magic = probe.read(4)
        if magic in PCAP_MAGICS:
            handle = path.open("rb")
            try:
                return dpkt.pcap.Reader(handle), handle, "pcap"
            except Exception:
                handle.close()
                raise
        if magic == PCAPNG_MAGIC:
            _validate_single_interface_pcapng(path)
            handle = path.open("rb")
            try:
                return dpkt.pcapng.Reader(handle), handle, "pcapng"
            except Exception:
                handle.close()
                raise
    except ReplayError:
        raise
    except (OSError, dpkt.Error, ValueError, struct.error) as error:
        raise ReplayError("invalid_capture", "Capture file is malformed or unreadable.") from error

    raise ReplayError(
        "unsupported_capture_format",
        "Input is not a supported classic PCAP or single-interface PCAPNG file.",
    )


def _decode_ethernet_packet(raw: bytes):
    """Return a directional flow key and safe packet metadata, or None."""
    try:
        ethernet = dpkt.ethernet.Ethernet(raw)
        network = ethernet.data

        if isinstance(network, dpkt.ip.IP):
            if network.mf or network.offset:
                return "fragment", None
            source = str(ipaddress.ip_address(network.src))
            destination = str(ipaddress.ip_address(network.dst))
            transport = network.data
        elif isinstance(network, dpkt.ip6.IP6):
            source = str(ipaddress.ip_address(network.src))
            destination = str(ipaddress.ip_address(network.dst))
            transport = network.data
        else:
            return "unsupported", None

        if isinstance(transport, dpkt.tcp.TCP):
            protocol = "tcp"
        elif isinstance(transport, dpkt.udp.UDP):
            protocol = "udp"
        else:
            return "unsupported", None

        if not (0 <= int(transport.sport) <= 65535 and 0 <= int(transport.dport) <= 65535):
            return "malformed", None

        key = (
            source,
            int(transport.sport),
            destination,
            int(transport.dport),
            protocol,
        )
        return "ok", key
    except (dpkt.UnpackError, dpkt.NeedData, ValueError, IndexError, struct.error):
        return "malformed", None


def replay_capture(
    input_path: str | Path,
    *,
    organization_id: str,
    site_id: str,
    sensor_id: str,
    capture_id: str | None = None,
    sensor_version: str = "0.1.0",
    config_version: str = "offline-replay-v1",
    limits: ReplayLimits | None = None,
) -> ReplayResult:
    """Read a bounded offline capture and emit directional flow telemetry."""
    path = Path(input_path)
    limits = limits or ReplayLimits()

    for field_name, value in (
        ("organization_id", organization_id),
        ("site_id", site_id),
        ("sensor_id", sensor_id),
        ("sensor_version", sensor_version),
        ("config_version", config_version),
    ):
        if not value or len(value) > 128:
            raise ReplayError("invalid_identity", f"{field_name} must be 1-128 characters.")

    if not path.exists() or not path.is_file():
        raise ReplayError("input_not_found", "Capture input file does not exist.")
    file_size = path.stat().st_size
    if file_size <= 0:
        raise ReplayError("empty_capture", "Capture input file is empty.")
    if file_size > limits.max_file_bytes:
        raise ReplayError(
            "file_too_large",
            f"Capture exceeds the {limits.max_file_bytes}-byte replay limit.",
        )

    capture_hash = _sha256_file(path)
    effective_capture_id = capture_id or f"pcap-{capture_hash[:16]}"

    try:
        reader, handle, file_format = _open_capture(path)
    except ReplayError:
        raise
    except Exception as error:
        raise ReplayError("invalid_capture", "Capture file could not be opened.") from error

    try:
        if reader.datalink() != SUPPORTED_LINKTYPE:
            raise ReplayError(
                "unsupported_linktype",
                "This replay version supports Ethernet (DLT_EN10MB) captures only.",
            )

        snap_length = int(getattr(reader, "snaplen", 0) or 0)
        if snap_length < 1 or snap_length > limits.max_packet_bytes:
            raise ReplayError(
                "unsupported_snaplen",
                "Capture snap length is outside the configured packet-size limit.",
            )

        flows: list[FlowAccumulator] = []
        active: dict[tuple, FlowAccumulator] = {}
        packets_seen = 0
        malformed = 0
        unsupported = 0
        fragmented = 0
        out_of_order = 0

        try:
            for timestamp, raw in reader:
                packets_seen += 1
                if packets_seen > limits.max_packets:
                    raise ReplayError(
                        "packet_limit_exceeded",
                        f"Capture exceeds the {limits.max_packets}-packet replay limit.",
                    )
                if len(raw) > limits.max_packet_bytes:
                    raise ReplayError(
                        "packet_too_large",
                        "Capture contains a packet larger than the configured packet limit.",
                    )
                if not math.isfinite(float(timestamp)):
                    malformed += 1
                    continue

                outcome, key = _decode_ethernet_packet(raw)
                if outcome == "malformed":
                    malformed += 1
                    continue
                if outcome == "unsupported":
                    unsupported += 1
                    continue
                if outcome == "fragment":
                    fragmented += 1
                    continue

                src, src_port, dst, dst_port, protocol = key
                current = active.get(key)
                if current is not None and timestamp < current.last_seen:
                    out_of_order += 1
                if (
                    current is not None
                    and timestamp >= current.last_seen
                    and timestamp - current.last_seen > limits.inactivity_timeout_seconds
                ):
                    current = None

                if current is None:
                    if len(flows) >= limits.max_flows:
                        raise ReplayError(
                            "flow_limit_exceeded",
                            f"Capture exceeds the {limits.max_flows}-flow replay limit.",
                        )
                    current = FlowAccumulator(
                        src=src,
                        dst=dst,
                        protocol=protocol,
                        src_port=src_port,
                        dst_port=dst_port,
                        first_seen=float(timestamp),
                        last_seen=float(timestamp),
                        min_timestamp=float(timestamp),
                        max_timestamp=float(timestamp),
                    )
                    flows.append(current)
                    active[key] = current

                current.add(float(timestamp), len(raw))
        except ReplayError:
            raise
        except (dpkt.Error, OSError, ValueError, struct.error, OverflowError) as error:
            raise ReplayError(
                "capture_read_failed",
                "Capture ended unexpectedly or contains a malformed packet record.",
            ) from error

        if packets_seen == 0:
            raise ReplayError("empty_capture", "Capture contains no packet records.")

        return ReplayResult(
            capture_path=path.name,
            capture_sha256=capture_hash,
            capture_id=effective_capture_id,
            file_format=file_format,
            snap_length_bytes=snap_length,
            packets_seen=packets_seen,
            packets_dropped=None,
            malformed_packets=malformed,
            unsupported_packets=unsupported,
            fragmented_packets=fragmented,
            out_of_order_timestamps=out_of_order,
            flows=flows,
            organization_id=organization_id,
            site_id=site_id,
            sensor_id=sensor_id,
            sensor_version=sensor_version,
            config_version=config_version,
        )
    finally:
        handle.close()


def write_events_jsonl(events: Iterator[dict], output_path: str | Path, *, overwrite: bool = False) -> int:
    """Atomically write validated telemetry events as newline-delimited JSON."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not overwrite:
        raise ReplayError(
            "output_exists",
            f"Output already exists: {output}. Pass --overwrite to replace it.",
        )

    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "telemetry-v1.schema.json"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReplayError("schema_unavailable", "Telemetry v1 schema is unavailable.") from error

    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as error:
        raise ReplayError("schema_validator_unavailable", "Install the NetraX requirements to validate telemetry.") from error

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    temp_path = None
    written = 0
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            for event in events:
                errors = list(validator.iter_errors(event))
                if errors:
                    first = errors[0]
                    raise ReplayError(
                        "telemetry_schema_validation_failed",
                        f"Generated telemetry event failed schema validation at {list(first.absolute_path)}: {first.message}",
                    )
                handle.write(json.dumps(event, separators=(",", ":"), sort_keys=True))
                handle.write("\n")
                written += 1
            handle.flush()
            os.fsync(handle.fileno())

        if output.exists() and not overwrite:
            raise ReplayError(
                "output_exists",
                f"Output already exists: {output}. Pass --overwrite to replace it.",
            )
        os.replace(temp_path, output)
        temp_path = None
        return written
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Replay an authorized offline PCAP/PCAPNG into bounded, "
            "direction-unverified NetraX telemetry v1."
        )
    )
    parser.add_argument("--input", required=True, help="PCAP or single-interface PCAPNG input.")
    parser.add_argument("--output", required=True, help="Output NDJSON path.")
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument("--capture-id")
    parser.add_argument("--sensor-version", default="0.1.0")
    parser.add_argument("--config-version", default="offline-replay-v1")
    parser.add_argument("--max-file-mb", type=int, default=100)
    parser.add_argument("--max-packets", type=int, default=DEFAULT_MAX_PACKETS)
    parser.add_argument("--max-flows", type=int, default=DEFAULT_MAX_FLOWS)
    parser.add_argument("--inactivity-timeout", type=float, default=DEFAULT_INACTIVITY_TIMEOUT_SECONDS)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.max_file_mb < 1:
            raise ReplayError("invalid_limit", "--max-file-mb must be at least 1.")
        input_path = Path(args.input).resolve()
        output_path = Path(args.output).resolve()
        if input_path == output_path:
            raise ReplayError(
                "input_output_collision",
                "Output path must differ from the input capture path.",
            )

        limits = ReplayLimits(
            max_file_bytes=args.max_file_mb * 1024 * 1024,
            max_packets=args.max_packets,
            max_flows=args.max_flows,
            inactivity_timeout_seconds=args.inactivity_timeout,
        )
        result = replay_capture(
            args.input,
            organization_id=args.organization_id,
            site_id=args.site_id,
            sensor_id=args.sensor_id,
            capture_id=args.capture_id,
            sensor_version=args.sensor_version,
            config_version=args.config_version,
            limits=limits,
        )
        count = write_events_jsonl(
            result.iter_events(),
            args.output,
            overwrite=args.overwrite,
        )
        summary = result.summary()
        summary["events_written"] = count
        summary["output"] = str(Path(args.output))
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except (ReplayError, OSError, ValueError) as error:
        code = getattr(error, "code", "replay_failed")
        message = getattr(error, "message", str(error))
        print(json.dumps({"status": "error", "error_code": code, "message": message}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
