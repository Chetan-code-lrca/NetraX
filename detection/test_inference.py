"""
NetraX unified inference integration tests.

These are smoke/integration tests, not model-quality benchmarks.
"""

from detection.inference import (
    SUPPORTED_THREATS,
    predict,
    validate_alert,
)


def assert_standard_alert(alert, expected_threat):
    validate_alert(alert)

    assert alert["threat_class"] == expected_threat
    assert alert["status"] in {
        "DETECTED",
        "AMBIGUOUS",
        "INSUFFICIENT",
    }

    assert 0.0 <= float(alert["confidence"]) <= 1.0
    assert 0.0 <= float(alert["evidence_coverage"]) <= 1.0
    assert isinstance(alert["evidence"], list)
    assert isinstance(alert["available_evidence"], list)
    assert isinstance(alert["missing_evidence"], list)


def main():
    print("=== NETRAX UNIFIED INFERENCE TEST ===")

    # ---------------------------------------------------------
    # PortScan
    # ---------------------------------------------------------

    portscan_features = {
        " Destination Port": 80,
        " Flow Duration": 1000,
        " Total Fwd Packets": 20,
        "Total Length of Fwd Packets": 2000,
        " Fwd Packet Length Max": 100,
        " Fwd Packet Length Min": 20,
        " Fwd Packet Length Mean": 60,
        " Fwd IAT Mean": 50,
        " Fwd IAT Std": 10,
        " Fwd IAT Max": 100,
        " Fwd IAT Min": 1,
        "Fwd PSH Flags": 0,
        " Fwd URG Flags": 0,
        " Fwd Header Length": 200,
        "Fwd Packets/s": 20,
        " SYN Flag Count": 1,
        " RST Flag Count": 0,
        " PSH Flag Count": 0,
        " ACK Flag Count": 0,
        " URG Flag Count": 0,
        " CWE Flag Count": 0,
        " ECE Flag Count": 0,
        " Avg Fwd Segment Size": 60,
        " Fwd Avg Packets/Bulk": 0,
        " Fwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": 20,
        "Init_Win_bytes_forward": 8192,
        " act_data_pkt_fwd": 20,
        " min_seg_size_forward": 20,
    }

    alert = predict(
        "PortScan",
        portscan_features,
        "test-portscan",
    )

    assert_standard_alert(alert, "PortScan")
    print("✓ PortScan")

    # ---------------------------------------------------------
    # DDoS
    # ---------------------------------------------------------

    ddos_features = dict(portscan_features)
    ddos_features.update({
        " Total Fwd Packets": 5000,
        "Fwd Packets/s": 500,
        " Fwd Packet Length Mean": 100,
        " Fwd Packet Length Max": 1200,
    })

    alert = predict(
        "DDoS",
        ddos_features,
        "test-ddos",
    )

    assert_standard_alert(alert, "DDoS")
    print("✓ DDoS")

    # ---------------------------------------------------------
    # C2
    # ---------------------------------------------------------

    c2_features = {
        "flows_per_window": 250,
        "unique_destinations": 3,
        "unique_ports": 2,
        "repeated_pairs": 10,
        "periodic_pairs_cv1": 6,
        "periodic_pairs_cv05": 3,
    }

    alert = predict(
        "C2_Beaconing",
        c2_features,
        "test-c2",
    )

    assert_standard_alert(
        alert,
        "C2_Beaconing",
    )
    print("✓ C2")

    # ---------------------------------------------------------
    # DNS / DGA / Tunnelling
    # ---------------------------------------------------------

    dns_domain = (
        "3eabapdnggydixon2aaaedrlp55zvgcamdmoehp2zp313hh4j5cibdeylkmqih"
        ".yddcaeir2gls.securitytesting.online"
    )

    alert = predict(
        "DGA_DNS_Tunneling",
        dns_domain,
        "test-dns",
    )

    assert_standard_alert(
        alert,
        "DGA_DNS_Tunneling",
    )
    print("✓ DNS/DGA/Tunnelling")

    # ---------------------------------------------------------
    # Encrypted Malware
    # ---------------------------------------------------------
    #
    # Build a Series because the existing encrypted detector
    # expects row-like input.

    import pandas as pd

    encrypted_row = pd.Series({
        "bytes_sent": 1_000_000,
        "packets_sent": 2_000,
        "flow_duration": 10.0,
        "bytes_per_second": 100_000,
        "packets_per_second": 200,
        "bytes_per_packet": 500,
        "destination_port": 443,
        "tls_client_version_present": 1,
        "tls_server_version_present": 1,
        "tls_extensions_count": 10,
        "tls_cipher_suites_count": 5,
        "tls_compression_count": 0,
        "tls_client_extensions_count": 8,
        "tls_alpn_count": 1,
        "sni_present": 1,
        "ja3_present": 1,
        "ja4_present": 1,
    })

    alert = predict(
        "Encrypted_Malware",
        encrypted_row,
        "test-encrypted",
    )

    assert_standard_alert(
        alert,
        "Encrypted_Malware",
    )
    print("✓ Encrypted Malware")

    # ---------------------------------------------------------
    # Data Exfiltration
    # ---------------------------------------------------------

    exfil_features = {
        " Total Fwd Packets": 5000,
        "Total Length of Fwd Packets": 8_000_000,
        " Fwd Packet Length Mean": 1100,
        " Fwd Packet Length Max": 1460,
        "Fwd Packets/s": 180,
        " Fwd IAT Mean": 50_000,
        " Fwd IAT Std": 1_500_000,
    }

    alert = predict(
        "Data_Exfiltration",
        exfil_features,
        "test-exfil",
    )

    assert_standard_alert(
        alert,
        "Data_Exfiltration",
    )
    print("✓ Data Exfiltration")

    # ---------------------------------------------------------
    # Supported threat list
    # ---------------------------------------------------------

    assert len(SUPPORTED_THREATS) == 6

    print("\nSupported threats:")
    for threat in SUPPORTED_THREATS:
        print(f"  {threat}")

    print("\nALL UNIFIED INFERENCE TESTS PASSED")


if __name__ == "__main__":
    main()
