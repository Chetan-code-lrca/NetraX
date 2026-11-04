# NetraX sensor configuration v1

**Status:** Strict configuration contract only. No live packet capture is activated by this file or loader.

## Why a separate configuration exists

A sensor must have an explicit and reviewable observation scope. The configuration requires named interfaces, an explicit BPF capture filter, bounded snap length, an inactivity timeout, local spool limits, and a monitoring-point identifier.

Schema: `schemas/sensor-config-v1.schema.json`  
Example: `schemas/examples/sensor-config-v1.json`

## Validate the example

```bash
python - <<'PY'
from netrax_sensor.config import load_sensor_config

validated = load_sensor_config("schemas/examples/sensor-config-v1.json")
print("config SHA-256:", validated.config_sha256)
print("interfaces:", validated.values["capture"]["interfaces"])
PY
```

The loader:
- requires JSON schema v1;
- rejects unknown fields;
- requires at least one explicitly named interface;
- rejects wildcard/pseudo-interface values such as `any`, `all`, and `*`;
- requires an explicit capture filter;
- enforces packet, timeout and spool bounds;
- computes a canonical SHA-256 digest.

## Important trust boundary

The configuration field `expected_direction` is an operator-supplied expectation. The digest identifies the exact configuration content; **it is not a digital signature, certificate, or proof that the physical TAP/SPAN topology is configured correctly**.

Until a trusted control-plane registry and sensor authentication exist:
- do not use this configuration to set telemetry `direction_validation.status` to `verified_unidirectional`;
- do not trust `organization_id`, `site_id`, or `sensor_id` from an unauthenticated event payload;
- keep replay output direction marked `unverified`.

The future ingest boundary must authenticate a sensor certificate, derive its registered organization/site/sensor identity, and verify the approved monitoring-point record and configuration digest before assigning any trusted direction state.

## Operational scope

This contract does not start capture, change interface flags, enable promiscuous mode, install BPF filters, request Linux capabilities, or send network traffic. The live capture service must implement those operations separately, with a dedicated threat model and lab validation.
