import importlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import joblib
import pandas as pd
from fastapi.testclient import TestClient
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from features.encrypted.encrypted_features import (
    extract_encrypted_features,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

FLOW_MODEL_FEATURES = [
    " Destination Port",
    " Total Fwd Packets",
    "Fwd Packets/s",
    "Total Length of Fwd Packets",
]


def _build_flow_model(training_rows, labels, model_path):
    frame = pd.DataFrame(
        training_rows,
        columns=FLOW_MODEL_FEATURES,
    )
    model = RandomForestClassifier(
        n_estimators=50,
        random_state=42,
    )
    model.fit(frame, labels)
    joblib.dump(model, model_path)


def _build_encrypted_model(model_path):
    rows = []
    labels = []

    for index in range(40):
        rows.append(
            {
                "bs": 300000 + (index * 5000),
                "ps": 2200 + index,
                "td": 20 + (index % 5),
                "dp": 443,
                "tls.cver": "771",
                "tls.sver": "771",
                "tls.sext": "['server_name','alpn']",
                "tls.csg": "['TLS_AES_128_GCM_SHA256']",
                "tls.ccs": "[]",
                "tls.cext": "['supported_groups']",
                "tls.alpn": "['h2']",
                "tls.sni": "malicious.example",
                "tls.ja3": "ja3hash",
                "tls.ja4": "ja4hash",
            }
        )
        labels.append(1)

        rows.append(
            {
                "bs": 4000 + (index * 100),
                "ps": 80 + (index % 10),
                "td": 90 + (index % 7),
                "dp": 443,
                "tls.cver": "771",
                "tls.sver": "771",
                "tls.sext": "['server_name']",
                "tls.csg": "['TLS_AES_128_GCM_SHA256']",
                "tls.ccs": "[]",
                "tls.cext": "['supported_groups']",
                "tls.alpn": "['h2']",
                "tls.sni": "cdn.example",
                "tls.ja3": "ja3hash",
                "tls.ja4": "",
            }
        )
        labels.append(0)

    features = pd.DataFrame(
        [
            extract_encrypted_features(row)
            for row in rows
        ]
    )
    model = RandomForestClassifier(
        n_estimators=80,
        random_state=42,
    )
    model.fit(features, labels)
    joblib.dump(model, model_path)


def _build_dns_artifacts(vectorizer_path, model_path):
    domains = []
    labels = []

    benign = [
        "google.com",
        "microsoft.com",
        "github.com",
        "wikipedia.org",
        "python.org",
    ]
    dga = [
        "ajd92jd9kq.com",
        "x8qvz9m2n.net",
        "m1n2b3v4c5.biz",
        "qwx92mz81.info",
        "z9x8c7v6b5.top",
    ]
    tunnel = [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa111111111111.example.com",
        "xn3k9z2a8b7c6d5e4f3g2h1i0j.example.net",
        "123451234512345123451234512345.abc.org",
        "a1b2c3d4e5f6g7h8i9j0k1l2m3n4.longdomain.io",
        "p9q8r7s6t5u4v3w2x1y0z9a8b7c6.data.xyz",
    ]

    for value in benign:
        domains.append(value)
        labels.append(0)
    for value in dga:
        domains.append(value)
        labels.append(1)
    for value in tunnel:
        domains.append(value)
        labels.append(2)

    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 4),
        min_df=1,
    )
    X = vectorizer.fit_transform(domains)
    model = LogisticRegression(
        max_iter=200,
    )
    model.fit(X, labels)

    joblib.dump(vectorizer, vectorizer_path)
    joblib.dump(model, model_path)


class AnalyzeApiIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous_model_dir = os.environ.get(
            "NETRAX_MODEL_DIR"
        )
        cls.model_dir = tempfile.TemporaryDirectory(
            prefix="netrax-models-"
        )
        cls.fixtures_dir = tempfile.TemporaryDirectory(
            prefix="netrax-fixtures-"
        )
        os.environ["NETRAX_MODEL_DIR"] = cls.model_dir.name

        _build_flow_model(
            training_rows=[
                [8080, 300, 1400, 280000],
                [3306, 400, 1700, 350000],
                [443, 20, 8, 4000],
                [53, 15, 5, 2200],
            ],
            labels=[
                "PortScan",
                "PortScan",
                "BENIGN",
                "BENIGN",
            ],
            model_path=Path(cls.model_dir.name)
            / "portscan_model.joblib",
        )

        _build_flow_model(
            training_rows=[
                [80, 2000, 2400, 900000],
                [8080, 1500, 1800, 700000],
                [443, 30, 6, 5000],
                [53, 20, 4, 2500],
            ],
            labels=[
                "DDoS",
                "DDoS",
                "BENIGN",
                "BENIGN",
            ],
            model_path=Path(cls.model_dir.name)
            / "ddos_model.joblib",
        )

        _build_encrypted_model(
            Path(cls.model_dir.name)
            / "encrypted_malware_model.joblib"
        )
        _build_dns_artifacts(
            Path(cls.model_dir.name)
            / "dns_char_vectorizer.joblib",
            Path(cls.model_dir.name)
            / "dns_ngram_model.joblib",
        )

        cls.flow_csv = (
            Path(cls.fixtures_dir.name)
            / "flow_fixture.csv"
        )
        pd.DataFrame(
            [
                {
                    "src_ip": "10.1.1.10",
                    "dst_ip": "192.168.10.10",
                    "dst_port": 8080,
                    "tot_fwd_pkts": 300,
                    "fwd_pkts_s": 1500,
                    "totlen_fwd_pkts": 300000,
                    "tot_bwd_pkts": 10,
                },
                {
                    "src_ip": "10.1.1.11",
                    "dst_ip": "192.168.10.11",
                    "dst_port": 80,
                    "tot_fwd_pkts": 2400,
                    "fwd_pkts_s": 2800,
                    "totlen_fwd_pkts": 1_800_000,
                    "tot_bwd_pkts": 30,
                }
            ]
        ).to_csv(
            cls.flow_csv,
            index=False,
        )

        cls.c2_csv = (
            Path(cls.fixtures_dir.name)
            / "c2_fixture.csv"
        )
        pd.DataFrame(
            [
                {
                    "src": "10.2.2.2",
                    "window": "2026-01-01T00:00:00",
                    "flows_per_window": 240,
                    "unique_destinations": 70,
                    "unique_ports": 30,
                    "repeated_pairs": 10,
                    "periodic_pairs_cv1": 8,
                    "periodic_pairs_cv05": 4,
                }
            ]
        ).to_csv(
            cls.c2_csv,
            index=False,
        )

        cls.dns_csv = (
            Path(cls.fixtures_dir.name)
            / "dns_fixture.csv"
        )
        pd.DataFrame(
            [
                {
                    "domain": (
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa111111111111."
                        "example.com"
                    )
                }
            ]
        ).to_csv(
            cls.dns_csv,
            index=False,
        )

        cls.encrypted_csv = (
            Path(cls.fixtures_dir.name)
            / "encrypted_fixture.csv"
        )
        pd.DataFrame(
            [
                {
                    "src": "10.3.3.3",
                    "dst": "203.0.113.10",
                    "hostname": "malicious.example",
                    "bs": 380000,
                    "ps": 2400,
                    "td": 19,
                    "dp": 443,
                    "tls.cver": "771",
                    "tls.sver": "771",
                    "tls.sext": "['server_name','alpn']",
                    "tls.csg": "['TLS_AES_128_GCM_SHA256']",
                    "tls.ccs": "[]",
                    "tls.cext": "['supported_groups']",
                    "tls.alpn": "['h2']",
                    "tls.sni": "malicious.example",
                    "tls.ja3": "ja3hash",
                    "tls.ja4": "ja4hash",
                }
            ]
        ).to_csv(
            cls.encrypted_csv,
            index=False,
        )

        cls.mixed_flow_dns_csv = (
            Path(cls.fixtures_dir.name)
            / "mixed_flow_dns_fixture.csv"
        )
        pd.DataFrame(
            [
                {
                    "domain": "google.com",
                    "src_ip": "10.5.5.5",
                    "dst_ip": "192.168.55.5",
                    "dst_port": 80,
                    "tot_fwd_pkts": 1800,
                    "fwd_pkts_s": 2300,
                    "totlen_fwd_pkts": 850000,
                    "tot_bwd_pkts": 18,
                }
            ]
        ).to_csv(
            cls.mixed_flow_dns_csv,
            index=False,
        )

        cls.pcap_file = (
            Path(cls.fixtures_dir.name)
            / "capture_fixture.pcap"
        )
        cls.pcap_file.write_bytes(
            b"pcap-fixture"
        )

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
        cls.fixtures_dir.cleanup()

        if cls.previous_model_dir is None:
            os.environ.pop(
                "NETRAX_MODEL_DIR",
                None,
            )
        else:
            os.environ["NETRAX_MODEL_DIR"] = (
                cls.previous_model_dir
            )

    def _post_csv(self, path):
        with path.open("rb") as handle:
            return self.client.post(
                "/api/analyze",
                files={
                    "file": (
                        path.name,
                        handle,
                        "text/csv",
                    )
                },
            )

    def _assert_required_analysis_fields(self, payload):
        required = {
            "analysis_id",
            "filename",
            "file_type",
            "flows_processed",
            "packets_processed",
            "alerts_generated",
            "alerts_returned",
            "alerts_truncated",
            "summary",
            "alerts",
        }
        self.assertTrue(
            required.issubset(payload.keys())
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

    def test_flow_detectors_reachable(self):
        response = self._post_csv(self.flow_csv)
        payload = response.json()

        self.assertEqual(
            response.status_code,
            200,
        )
        self._assert_required_analysis_fields(payload)
        self.assertEqual(
            payload["file_type"],
            "csv",
        )
        self.assertEqual(
            payload["flows_processed"],
            2,
        )
        self.assertIsInstance(
            payload["packets_processed"],
            int,
        )

        threat_classes = {
            alert["threat_class"]
            for alert in payload["alerts"]
        }
        self.assertTrue(
            {
                "PortScan",
                "DDoS",
                "Data_Exfiltration",
            }.issubset(threat_classes)
        )

    def test_c2_detector_reachable(self):
        response = self._post_csv(self.c2_csv)
        payload = response.json()

        self.assertEqual(
            response.status_code,
            200,
        )
        self._assert_required_analysis_fields(payload)
        self.assertEqual(
            payload["packets_processed"],
            None,
        )
        self.assertTrue(
            any(
                alert["threat_class"]
                == "C2_Beaconing"
                for alert in payload["alerts"]
            )
        )

    def test_dns_detector_reachable(self):
        response = self._post_csv(self.dns_csv)
        payload = response.json()

        self.assertEqual(
            response.status_code,
            200,
        )
        self._assert_required_analysis_fields(payload)
        self.assertTrue(
            any(
                alert["threat_class"]
                == "DGA_DNS_Tunneling"
                for alert in payload["alerts"]
            )
        )

    def test_encrypted_detector_reachable(self):
        response = self._post_csv(self.encrypted_csv)
        payload = response.json()

        self.assertEqual(
            response.status_code,
            200,
        )
        self._assert_required_analysis_fields(payload)
        self.assertTrue(
            any(
                alert["threat_class"]
                == "Encrypted_Malware"
                for alert in payload["alerts"]
            )
        )
        self.assertFalse(
            any(
                alert["threat_class"]
                == "DGA_DNS_Tunneling"
                for alert in payload["alerts"]
            )
        )

    def test_pcap_conversion_branch_reachable(self):
        def fake_cicflow_run(
            command,
            capture_output,
            text,
            timeout,
        ):
            csv_output = Path(
                command[
                    command.index("-c")
                    + 1
                ]
            )
            pd.DataFrame(
                [
                    {
                        "src_ip": "10.9.9.9",
                        "dst_ip": "192.168.99.9",
                        "dst_port": 80,
                        "tot_fwd_pkts": 2000,
                        "fwd_pkts_s": 2500,
                        "totlen_fwd_pkts": 900000,
                        "tot_bwd_pkts": 20,
                    }
                ]
            ).to_csv(
                csv_output,
                index=False,
            )
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout="ok",
                stderr="",
            )

        with mock.patch(
            "detection.inference.subprocess.run",
            side_effect=fake_cicflow_run,
        ):
            with self.pcap_file.open("rb") as handle:
                response = self.client.post(
                    "/api/analyze",
                    files={
                        "file": (
                            self.pcap_file.name,
                            handle,
                            "application/vnd.tcpdump.pcap",
                        )
                    },
                )

        payload = response.json()
        self.assertEqual(
            response.status_code,
            200,
        )
        self._assert_required_analysis_fields(payload)
        self.assertEqual(
            payload["file_type"],
            "pcap",
        )

    def test_flow_contract_precedence_over_dns_column(self):
        response = self._post_csv(
            self.mixed_flow_dns_csv
        )
        payload = response.json()

        self.assertEqual(
            response.status_code,
            200,
        )
        self._assert_required_analysis_fields(payload)

        threat_classes = {
            alert["threat_class"]
            for alert in payload["alerts"]
        }

        self.assertTrue(
            {"PortScan", "DDoS"}.issubset(
                threat_classes
            )
        )
        self.assertNotIn(
            "DGA_DNS_Tunneling",
            threat_classes,
        )

    def test_pcap_timeout_maps_to_504(self):
        with mock.patch(
            "detection.inference.subprocess.run",
            side_effect=subprocess.TimeoutExpired(
                cmd=["cicflowmeter"],
                timeout=120,
            ),
        ):
            with self.pcap_file.open("rb") as handle:
                response = self.client.post(
                    "/api/analyze",
                    files={
                        "file": (
                            self.pcap_file.name,
                            handle,
                            "application/vnd.tcpdump.pcap",
                        )
                    },
                )

        payload = response.json()
        self.assertEqual(
            response.status_code,
            504,
        )
        self.assertEqual(
            payload["error_code"],
            "cicflow_timeout",
        )

    def test_pcap_cicflow_failure_maps_to_500(self):
        with mock.patch(
            "detection.inference.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["cicflowmeter"],
                returncode=1,
                stdout="",
                stderr="failed",
            ),
        ):
            with self.pcap_file.open("rb") as handle:
                response = self.client.post(
                    "/api/analyze",
                    files={
                        "file": (
                            self.pcap_file.name,
                            handle,
                            "application/vnd.tcpdump.pcap",
                        )
                    },
                )

        payload = response.json()
        self.assertEqual(
            response.status_code,
            500,
        )
        self.assertEqual(
            payload["error_code"],
            "cicflow_failed",
        )

    def test_pcap_missing_output_maps_to_500(self):
        with mock.patch(
            "detection.inference.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["cicflowmeter"],
                returncode=0,
                stdout="ok",
                stderr="",
            ),
        ):
            with self.pcap_file.open("rb") as handle:
                response = self.client.post(
                    "/api/analyze",
                    files={
                        "file": (
                            self.pcap_file.name,
                            handle,
                            "application/vnd.tcpdump.pcap",
                        )
                    },
                )

        payload = response.json()
        self.assertEqual(
            response.status_code,
            500,
        )
        self.assertEqual(
            payload["error_code"],
            "cicflow_missing_output",
        )


if __name__ == "__main__":
    unittest.main()
