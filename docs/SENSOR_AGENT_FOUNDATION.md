# NetraX local sensor foundation

This note covers the current non-privileged sensor foundation. It is not a live capture agent and does not send network telemetry to a remote service.

## Components

| Component | Implemented behavior |
|---|---|
| Sensor config v1 | Strict JSON schema, explicit interface allowlist, BPF filter, passive-mode invariant and bounded spool settings |
| Config loader | Validates configuration and computes a canonical SHA-256 digest |
| PCAP replay | Bounded offline PCAP / single-interface Ethernet PCAPNG parsing |
| Telemetry v1 | Each directional observation is schema-validated; arbitrary files remain direction-unverified |
| Local outbox | Atomic per-event files, bounded by bytes/count/TTL, explicit acknowledgements and restart recovery |
| Replay-to-spool CLI | Replays a capture using sensor identity/config labels and enqueues events locally; sends no network requests |

## Run the end-to-end local flow

Install the project requirements:

```bash
python -m pip install -r requirements.txt
```

Replay a lab capture into a local spool directory:

```bash
python -m netrax_sensor.replay_to_spool \
  --input ./captures/lab.pcap \
  --config schemas/examples/sensor-config-v1.json \
  --spool-dir /tmp/netrax-spool
```

The command:
1. Validates the sensor config against `schemas/sensor-config-v1.schema.json`.
2. Computes its canonical config digest.
3. Reads the authorized offline capture within the configured replay limits.
4. Creates directional 5-tuple flow events; reverse packets are never combined.
5. Sets direction validation to `unverified`.
6. Validates each telemetry event against `schemas/telemetry-v1.schema.json`.
7. Atomically appends each event to the spool.
8. Prints counts and spool usage. It sends **zero network requests**.

The configured interface list, BPF filter, expected direction and monitoring-point ID are not applied to an offline file. They are configuration for a future live sensor; their presence does not verify the file's capture source.

## Local outbox semantics

- **At-least-once delivery:** `read_batch()` does not delete or mark events sent. Re-reading the same batch is expected.
- **Explicit acknowledgement:** call `acknowledge(event_ids)` only after a future ingest service confirms durable acceptance. Never acknowledge on a timeout or ambiguous network response.
- **Idempotent retry:** event IDs are deterministic for the same capture, organization/site/sensor and config version/digest. Rerunning the exact same replay is a duplicate no-op.
- **Resumable backpressure:** a separate bounded checkpoint records the next flow index only after the event is durably present in the spool. When the spool fills, the command exits with a partial result. After queued events are acknowledged or expire, rerunning the same capture/config resumes from the first not-yet-enqueued flow.
- **Changed config:** the config digest/version contributes to both event and checkpoint identity; replaying the same capture under a changed config creates a separate replay stream.
- **Bounded storage:** maximum spool bytes, event count, individual event size and local enqueue age are enforced. A full spool raises an explicit error; it does not silently drop a new event.
- **Crash recovery:** committed events are atomic JSON files. Interrupted temporary writes are cleaned when the single sensor process starts again.
- **Integrity:** event JSON is checked against telemetry v1 on append and read; the filename is checked against its event ID.

The spool and replay checkpoint writer support a single sensor process. A future sender must coordinate with replay/acknowledgement in that process; do not run independent writers against the same spool directory. This is not a shared multi-process queue, distributed broker or durable remote ingest service.

## Security and data handling

Flow telemetry contains internal source/destination addresses and traffic metadata. The local spool stores these records as plaintext JSON. On POSIX systems the spool directory is restricted to mode `0700`, and temporary event files use private permissions; these file permissions are not encryption.

For any real organization pilot, place the spool on an encrypted volume, restrict host access, monitor filesystem capacity, and define secure deletion/retention. Application-level envelope encryption and key rotation remain future work.

Identity fields in the config and event are labels, not authentication. A future ingest service must bind an mTLS client certificate to a registered sensor and derive organization/site/sensor authorization from that registry. The receiver must not trust JSON identity claims by themselves.

The config SHA-256 is a content digest, not a signature. A trusted control plane must compare it with an approved, signed/registered configuration before accepting any direction or capture-coverage claim.

## Not implemented yet

- Live packet capture from a Linux interface.
- Privilege separation and the minimal packet-capture capability boundary.
- Interface state and kernel/NIC drop counter collection.
- Applying the BPF filter to a live interface.
- Sensor heartbeat and remote management.
- mTLS certificate enrollment, rotation or revocation.
- HTTPS telemetry sender, ingest API, durable broker or dead-letter queue.
- Automatic remote acknowledgement and backpressure coordination.
- Encrypted spool files and managed key rotation.

These are deliberately separate gates. The current foundation must not be described as a deployed network sensor.
