import json
from pathlib import Path

import dpkt
import pytest
from jsonschema import Draft202012Validator, FormatChecker

from netrax_sensor.pcap_replay import (
    ReplayError,
    ReplayLimits,
    replay_capture,
    write_events_jsonl,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (ROOT / "schemas" / "telemetry-v1.schema.json").read_text(encoding="utf-8")
)
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


def _ethernet_ipv4_tcp(src, dst, sport, dport, payload=b"x"):
    tcp = dpkt.tcp.TCP(
        sport=sport,
        dport=dport,
        seq=1,
        flags=dpkt.tcp.TH_ACK,
        data=payload,
    )
    ip = dpkt.ip.IP(
        src=bytes(map(int, src.split("."))),
        dst=bytes(map(int, dst.split("."))),
        p=dpkt.ip.IP_PROTO_TCP,
        ttl=64,
        data=tcp,
    )
    ip.len = len(ip)
    ethernet = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\x66\x77\x88\x99\xaa\xbb",
        type=dpkt.ethernet.ETH_TYPE_IP,
    )
    return bytes(ethernet) + bytes(ip)


def _write_pcap(path, packets, *, snaplen=65535, linktype=dpkt.pcap.DLT_EN10MB):
    with path.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle, snaplen=snaplen, linktype=linktype)
        for timestamp, packet in packets:
            writer.writepkt(packet, ts=timestamp)
        # Writer.close() closes its file handle. The surrounding context is
        # intentionally not reused after this point.
        writer.close()


def _write_pcapng(path, packets, *, interfaces=None):
    with path.open("wb") as handle:
        writer = dpkt.pcapng.Writer(
            handle,
            snaplen=65535,
            idb=interfaces,
        )
        for timestamp, packet in packets:
            writer.writepkt(packet, ts=timestamp)
        writer.close()


def _replay(path, **overrides):
    args = {
        "organization_id": "org_test",
        "site_id": "site_lab",
        "sensor_id": "sensor_replay",
    }
    args.update(overrides)
    return replay_capture(path, **args)


def test_replay_emits_valid_telemetry_and_never_claims_one_way_verification(tmp_path):
    capture = tmp_path / "basic.pcap"
    packet = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    _write_pcap(capture, [(1000.0, packet), (1000.5, packet)])

    result = _replay(capture)
    events = list(result.iter_events())

    assert result.file_format == "pcap"
    assert result.packets_seen == 2
    assert result.flow_count == 1
    assert events[0]["direction_validation"]["status"] == "unverified"
    assert events[0]["flow"]["observed_packets"] == 2
    assert events[0]["flow"]["observed_duration_ms"] == pytest.approx(500.0)
    assert events[0]["flow"]["observed_bytes"] == len(packet) * 2
    assert events[0]["capture_health"]["packets_dropped"] is None
    assert len(events[0]["capture_sha256"]) == 64
    assert not list(VALIDATOR.iter_errors(events[0]))


def test_reverse_direction_is_kept_in_a_separate_flow(tmp_path):
    capture = tmp_path / "reverse.pcap"
    forward = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    reverse = _ethernet_ipv4_tcp("198.51.100.20", "192.0.2.10", 443, 50000)
    _write_pcap(capture, [(1000.0, forward), (1000.1, reverse)])

    events = list(_replay(capture).iter_events())

    assert len(events) == 2
    pairs = {(event["flow"]["src"], event["flow"]["dst"]) for event in events}
    assert pairs == {
        ("192.0.2.10", "198.51.100.20"),
        ("198.51.100.20", "192.0.2.10"),
    }
    assert all(event["direction_validation"]["status"] == "unverified" for event in events)


def test_same_direction_flow_is_split_after_inactivity_timeout(tmp_path):
    capture = tmp_path / "idle.pcap"
    packet = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    _write_pcap(capture, [(1000.0, packet), (1061.0, packet)])

    result = _replay(capture)
    assert result.flow_count == 2


def test_out_of_order_timestamp_is_counted_without_negative_duration(tmp_path):
    capture = tmp_path / "out-of-order.pcap"
    packet = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    _write_pcap(capture, [(1001.0, packet), (1000.0, packet)])

    result = _replay(capture)
    event = next(result.iter_events())

    assert result.out_of_order_timestamps == 1
    assert event["flow"]["observed_duration_ms"] == pytest.approx(1000.0)


def test_single_interface_pcapng_is_supported(tmp_path):
    capture = tmp_path / "basic.pcapng"
    packet = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    _write_pcapng(capture, [(1000.0, packet)])

    result = _replay(capture)
    assert result.file_format == "pcapng"
    assert result.flow_count == 1


def test_multi_interface_pcapng_is_rejected_explicitly(tmp_path):
    capture = tmp_path / "multi.pcapng"
    packet = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    interfaces = [
        dpkt.pcapng.InterfaceDescriptionBlockLE(),
        dpkt.pcapng.InterfaceDescriptionBlockLE(),
    ]
    _write_pcapng(capture, [(1000.0, packet)], interfaces=interfaces)

    with pytest.raises(ReplayError, match="Multi-interface"):
        _replay(capture)


def test_non_ethernet_linktype_is_rejected(tmp_path):
    capture = tmp_path / "raw-ip.pcap"
    packet = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    _write_pcap(capture, [(1000.0, packet)], linktype=dpkt.pcap.DLT_RAW)

    with pytest.raises(ReplayError, match="Ethernet"):
        _replay(capture)


def test_packet_and_flow_limits_are_enforced(tmp_path):
    capture = tmp_path / "limits.pcap"
    packet = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    _write_pcap(capture, [(1000.0, packet), (1001.0, packet)])

    with pytest.raises(ReplayError) as packet_error:
        _replay(capture, limits=ReplayLimits(max_packets=1))
    assert packet_error.value.code == "packet_limit_exceeded"

    packet_a = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    packet_b = _ethernet_ipv4_tcp("192.0.2.11", "198.51.100.20", 50001, 443)
    _write_pcap(capture, [(1000.0, packet_a), (1001.0, packet_b)])
    with pytest.raises(ReplayError) as flow_error:
        _replay(capture, limits=ReplayLimits(max_flows=1))
    assert flow_error.value.code == "flow_limit_exceeded"


def test_file_size_limit_is_enforced_before_parsing(tmp_path):
    capture = tmp_path / "large.pcap"
    packet = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    _write_pcap(capture, [(1000.0, packet)])

    with pytest.raises(ReplayError) as error:
        _replay(capture, limits=ReplayLimits(max_file_bytes=1))
    assert error.value.code == "file_too_large"


def test_invalid_magic_and_empty_files_are_rejected(tmp_path):
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    with pytest.raises(ReplayError) as empty_error:
        _replay(empty)
    assert empty_error.value.code == "empty_capture"

    invalid = tmp_path / "invalid.pcap"
    invalid.write_bytes(b"not a capture")
    with pytest.raises(ReplayError) as invalid_error:
        _replay(invalid)
    assert invalid_error.value.code == "unsupported_capture_format"


def test_jsonl_writer_validates_schema_and_refuses_accidental_overwrite(tmp_path):
    capture = tmp_path / "sample.pcap"
    packet = _ethernet_ipv4_tcp("192.0.2.10", "198.51.100.20", 50000, 443)
    _write_pcap(capture, [(1000.0, packet)])
    result = _replay(capture)
    output = tmp_path / "events.ndjson"

    count = write_events_jsonl(result.iter_events(), output)
    assert count == 1
    assert len(output.read_text(encoding="utf-8").splitlines()) == 1

    with pytest.raises(ReplayError) as error:
        write_events_jsonl(result.iter_events(), output)
    assert error.value.code == "output_exists"


def test_empty_or_unsupported_network_capture_is_reported_without_fake_flows(tmp_path):
    capture = tmp_path / "arp-only.pcap"
    arp = bytes(dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\x66\x77\x88\x99\xaa\xbb",
        type=dpkt.ethernet.ETH_TYPE_ARP,
        data=b"\x00" * 28,
    ))
    _write_pcap(capture, [(1000.0, arp)])

    result = _replay(capture)
    assert result.packets_seen == 1
    assert result.flow_count == 0
    assert result.unsupported_packets == 1
