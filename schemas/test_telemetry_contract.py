import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "telemetry-v1.schema.json"
EXAMPLE_PATH = ROOT / "schemas" / "examples" / "telemetry-v1.json"


class TelemetryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(
            cls.schema,
            format_checker=FormatChecker(),
        )

    def test_example_matches_telemetry_v1_schema(self):
        errors = sorted(
            self.validator.iter_errors(self.example),
            key=lambda error: list(error.absolute_path),
        )
        self.assertEqual(
            errors,
            [],
            "; ".join(error.message for error in errors),
        )

    def test_verified_unidirectional_requires_provenance(self):
        event = json.loads(json.dumps(self.example))
        event["direction_validation"] = {
            "status": "verified_unidirectional",
            "direction": "egress",
        }
        self.assertTrue(
            any(
                list(error.absolute_path) == ["direction_validation"]
                for error in self.validator.iter_errors(event)
            )
        )

    def test_unknown_direction_does_not_claim_verification(self):
        event = json.loads(json.dumps(self.example))
        event["direction_validation"] = {"status": "unknown"}
        self.assertEqual(
            list(self.validator.iter_errors(event)),
            [],
        )

    def test_sensor_scope_claims_are_required(self):
        event = json.loads(json.dumps(self.example))
        for field in ("organization_id", "site_id", "sensor_id"):
            event.pop(field)
            self.assertTrue(list(self.validator.iter_errors(event)))
            event[field] = self.example[field]

    def test_unknown_top_level_fields_are_rejected(self):
        event = json.loads(json.dumps(self.example))
        event["unreviewed_field"] = "must not pass silently"
        self.assertTrue(list(self.validator.iter_errors(event)))

    def test_unobserved_flow_counters_cannot_be_negative_or_zero_packets(self):
        event = json.loads(json.dumps(self.example))
        event["flow"]["observed_packets"] = 0
        self.assertTrue(list(self.validator.iter_errors(event)))


if __name__ == "__main__":
    unittest.main()
