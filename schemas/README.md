# NetraX schemas

This directory contains versioned data contracts shared by sensors, ingest,
and detection services.

- `telemetry-v1.schema.json`: draft JSON Schema for flow telemetry envelope v1.

The schema is a contract baseline, not proof that a sensor or receiver has
implemented it. Validate every example and implementation against the schema
in CI before deploying.

The receiver must derive organization, site and sensor identity from the
authenticated certificate and sensor registry. These identifiers are not
accepted from an untrusted payload as authoritative scope.

Unknown schema versions must be rejected or quarantined; never silently coerce
unknown fields into detector features.
