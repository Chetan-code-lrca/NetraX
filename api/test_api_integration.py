import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

import joblib
import pandas as pd
from fastapi.testclient import TestClient
from sklearn.ensemble import RandomForestClassifier


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEMO_CSV_PATH = Path("/tmp/netrax_demo.csv")
MODEL_FEATURES = [
    "dst_port",
    "tot_fwd_pkts",
    "fwd_pkts_s",
    "totlen_fwd_pkts",
]


def _build_model(training_rows, labels, model_path):
    frame = pd.DataFrame(
        training_rows,
        columns=MODEL_FEATURES,
    )

    model = RandomForestClassifier(
        n_estimators=50,
        random_state=42,
    )
    model.fit(frame, labels)
    joblib.dump(model, model_path)


def _write_demo_csv():
    rows = []

    for index in range(25):
        rows.append(
            {
                "src_ip": f"10.0.0.{index + 1}",
                "dst_ip": f"192.168.0.{(index % 5) + 1}",
                "dst_port": 1000 + index,
                "tot_fwd_pkts": 3 + (index % 3),
                "fwd_pkts_s": 250 + (index * 5),
                "totlen_fwd_pkts": 300 + (index * 10),
                "Label": "PortScan",
            }
        )

    for index in range(25):
        rows.append(
            {
                "src_ip": f"10.0.1.{index + 1}",
                "dst_ip": f"192.168.1.{(index % 5) + 1}",
                "dst_port": 443,
                "tot_fwd_pkts": 40 + (index % 4),
                "fwd_pkts_s": 5 + (index % 3),
                "totlen_fwd_pkts": 7000 + (index * 40),
                "Label": "BENIGN",
            }
        )

    pd.DataFrame(rows).to_csv(
        DEMO_CSV_PATH,
        index=False,
    )


class AnalyzeApiIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous_model_dir = os.environ.get(
            "NETRAX_MODEL_DIR"
        )
        cls.model_dir = tempfile.TemporaryDirectory(
            prefix="netrax-models-"
        )
        os.environ["NETRAX_MODEL_DIR"] = (
            cls.model_dir.name
        )

        portscan_training_rows = []
        portscan_labels = []

        for index in range(60):
            portscan_training_rows.append(
                [
                    1000 + (index % 30),
                    2 + (index % 4),
                    220 + (index * 4),
                    260 + (index * 12),
                ]
            )
            portscan_labels.append(
                "PortScan"
            )

            portscan_training_rows.append(
                [
                    443,
                    35 + (index % 6),
                    4 + (index % 3),
                    6500 + (index * 25),
                ]
            )
            portscan_labels.append(
                "BENIGN"
            )

        ddos_training_rows = []
        ddos_labels = []

        for index in range(60):
            ddos_training_rows.append(
                [
                    80,
                    1000 + (index * 5),
                    1200 + (index * 10),
                    250000 + (index * 2000),
                ]
            )
            ddos_labels.append(
                "DDoS"
            )

            ddos_training_rows.append(
                [
                    443,
                    35 + (index % 6),
                    4 + (index % 3),
                    6500 + (index * 25),
                ]
            )
            ddos_labels.append(
                "BENIGN"
            )

        _build_model(
            portscan_training_rows,
            portscan_labels,
            Path(cls.model_dir.name)
            / "portscan_model.joblib",
        )
        _build_model(
            ddos_training_rows,
            ddos_labels,
            Path(cls.model_dir.name)
            / "ddos_model.joblib",
        )
        _write_demo_csv()

        from api import main as api_main

        cls.api_main = importlib.reload(
            api_main
        )
        cls.client = TestClient(
            cls.api_main.app
        )

    @classmethod
    def tearDownClass(cls):
        cls.model_dir.cleanup()

        if cls.previous_model_dir is None:
            os.environ.pop(
                "NETRAX_MODEL_DIR",
                None,
            )
        else:
            os.environ["NETRAX_MODEL_DIR"] = (
                cls.previous_model_dir
            )

    def test_health(self):
        response = self.client.get(
            "/api/health"
        )

        self.assertEqual(
            response.status_code,
            200,
        )
        self.assertEqual(
            response.json()["status"],
            "ok",
        )

    def test_analyze_csv(self):
        with DEMO_CSV_PATH.open("rb") as handle:
            response = self.client.post(
                "/api/analyze",
                files={
                    "file": (
                        DEMO_CSV_PATH.name,
                        handle,
                        "text/csv",
                    )
                },
            )

        payload = response.json()

        self.assertEqual(
            response.status_code,
            200,
        )
        self.assertEqual(
            payload["status"],
            "complete",
        )
        self.assertEqual(
            payload["flows_processed"],
            50,
        )
        self.assertTrue(
            20
            <= payload["alerts_generated"]
            <= 30
        )
        self.assertEqual(
            payload["alerts_generated"],
            payload["summary"]["detected"],
        )
        self.assertEqual(
            payload["summary"]["insufficient"],
            50
            - payload["summary"]["detected"],
        )
        self.assertTrue(
            all(
                alert["status"]
                == "DETECTED"
                for alert in payload["alerts"]
            )
        )
        self.assertTrue(
            all(
                alert["threat_class"]
                == "PortScan"
                for alert in payload["alerts"]
            )
        )


if __name__ == "__main__":
    unittest.main()
