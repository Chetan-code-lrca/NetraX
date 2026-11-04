# NetraX offline sensor replay

**Component:** `netrax_sensor.pcap_replay`  
**Status:** Engineering preview; offline replay only.  
**No live capture:** This command does not open a network interface, require root/CAP_NET_RAW, send packets, or forward traffic.

## Purpose

Replay an authorized packet capture through a bounded packet-to-flow path and emit NetraX telemetry v1 as newline-delimited JSON (NDJSON). This provides a deterministic, non-privileged input path for sensor and ingestion development before live capture is introduced.

## Supported input

- Classic libpcap PCAP files.
- PCAPNG files with exactly one section, one interface description block, Ethernet (DLT_EN10MB) link type, and timestamped Enhanced/Packet Block records.
- Ethernet II, including VLAN decapsulation supported by dpkt.
- IPv4 and IPv6 packets carrying directly decoded TCP or UDP.

Explicit limitations:
- Multi-interface and multi-section PCAPNG files are rejected.
- PCAPNG Simple Packet Blocks are rejected because they do not carry per-packet timestamps; the replay pipeline will not silently skip those records. The current dpkt reader API does not preserve each packet's interface ID in its yielded packet tuple; accepting these files without additional validation could misinterpret link types.
- Non-Ethernet link types are rejected.
- IP fragments are counted and skipped rather than partially interpreted.
- ARP, ICMP, unsupported IP protocols and IPv6 packets whose transport is not directly decoded as TCP/UDP are counted as unsupported and do not produce flows.
- This component does not calculate the trained CICFlowMeter model feature vector. Its `netrax.flow.observed.v1` schema is basic directional flow telemetry, not `netrax.flow.forward.v1`.
- Packet capture drop counters, capture filter, physical interface, clock synchronization and mirror topology cannot be proven from an arbitrary file. Their unavailable/unverified state is represented explicitly.

## Installation

Install the repository requirements into your Python 3.12+ environment:

```bash
python -m pip install -r requirements.txt
```

## Run a replay

Use a capture you are authorized to analyze:

```bash
python -m netrax_sensor.pcap_replay \
  --input ./captures/lab-one-direction.pcap \
  --output ./out/flows.ndjson \
  --organization-id org-lab \
  --site-id site-lab \
  --sensor-id sensor-replay-lab
```

By default:
- Maximum input size: 100 MiB.
- Maximum packets: 1,000,000.
- Maximum directional flow records: 100,000.
- Maximum snap length / packet size: 262,144 bytes.
- Inactivity timeout: 60 seconds for a repeated directional 5-tuple.

Limits can be reduced or raised within the supported packet-size ceiling:

```bash
python -m netrax_sensor.pcap_replay --help
```

An existing output file is not overwritten unless `--overwrite` is explicitly supplied. Output is written to a temporary file, each event is validated against `schemas/telemetry-v1.schema.json`, and the file is atomically replaced only after all events validate.

## Direction and grouping semantics

A flow key is directional:

`(src IP, src port, dst IP, dst port, transport protocol)`

Reverse-direction packets use the reversed key and are accumulated separately. A directional key is split into a new observation record when the inactivity timeout is exceeded.

The output status is **always**:

```json
{
  "status": "unverified",
  "direction": "unknown"
}
```

This is intentional. Splitting packets into directional 5-tuples does not prove that the original capture came from a one-direction SPAN/TAP source. The output cannot be promoted to `verified_unidirectional` by CLI arguments, a filename, or operator self-attestation. A future trusted sensor must bind an approved monitoring-point/interface configuration to its authenticated identity and attach verifiable provenance.

## Output semantics

- `observed_packets`: packet records decoded into this directional flow and inactivity window.
- `observed_bytes`: sum of captured Ethernet frame lengths, including Ethernet headers.
- `observed_duration_ms`: maximum minus minimum packet timestamp for that directional flow window; it is not classic bidirectional CICFlowMeter `Flow Duration`.
- `capture_sha256`: SHA-256 of the exact input file.
- `event_id`: deterministic for the same capture digest and flow ordering, supporting reproducible replay.
- `packets_dropped`: null, with an explanation that an offline file does not provide trustworthy interface drop counters.
- `clock_offset_ms`: null, with an explanation that capture clock synchronization is unverified.
- Packet payloads are not copied into NDJSON output.

Organization/site/sensor values supplied to this offline command are labels for local replay events, not authenticated identities. A future ingestion service must authenticate a sensor certificate, look up its registered organization/site/sensor scope, and verify payload claims against that registry. Do not treat these JSON fields as authorization.

## Regression tests

The test suite covers:
- PCAP and single-interface PCAPNG parsing;
- multi-interface PCAPNG and non-Ethernet rejection;
- reverse-direction separation and inactivity splitting;
- out-of-order timestamps;
- file, packet and flow limits;
- unsupported packet handling;
- schema validation and safe output overwrite behavior.

Run:

```bash
python -m pytest -q netrax_sensor/test_pcap_replay.py
```

Passing these tests validates the replay implementation and schema wiring. It does not validate detector accuracy, real sensor packet-loss performance, or one-way capture provenance.

## Next live-sensor gates

Before adding live capture:
1. Validate actual interface and mirror topology in an isolated lab.
2. Threat-model the minimal capture privilege and process boundary.
3. Verify kernel/NIC drop counters and timestamp semantics.
4. Test backpressure, disk-full, restart, disconnect and burst traffic.
5. Bind capture direction to an approved monitoring-point configuration.
6. Add mTLS enrollment, rotation and revocation before remote ingestion.
