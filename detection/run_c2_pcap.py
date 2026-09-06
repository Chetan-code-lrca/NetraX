from streaming.flow_builder import (
    prepare_packets,
    build_one_way_flows,
)
from features.c2.pcap_behavioral_features import (
    extract_pcap_c2_features,
)
from detection.c2.c2_detector import c2_score
from detection.pipeline import build_alert


PACKET_FILE = "data/raw/ctu13_neris/packets.tsv"
FLOW_FILE = "data/processed/neris_one_way_flows.csv"
SOURCE_IP = "147.32.84.165"


def main():
    # Rebuild flows from packets so the complete path remains reproducible.
    packets = prepare_packets(PACKET_FILE)

    flows = build_one_way_flows(
        packets,
        inactivity_timeout=60.0,
    )

    # Persist the intermediate flow representation.
    flows.to_csv(FLOW_FILE, index=False)

    # Analyze only the suspected source for this C2 experiment.
    features = extract_pcap_c2_features(
        flows,
        source_ip=SOURCE_IP,
    )

    alerts = []

    for _, row in features.iterrows():
        score, status, evidence = c2_score(row)

        alert = build_alert(
            threat_class="C2_Beaconing",
            confidence=score,
            status=status,
            evidence=evidence,
            flow_id=(
                f"PCAP-C2-{row['src']}-"
                f"{row['window']}"
            ),
        )

        alerts.append(alert)

    detected = [
        alert
        for alert in alerts
        if alert["status"] == "DETECTED"
    ]

    print("=== NETRAX PCAP C2 ANALYSIS ===")
    print("Packets:", len(packets))
    print("One-way flows:", len(flows))
    print("Behavioral windows:", len(features))
    print("Detected windows:", len(detected))

    if detected:
        print("\nTop detections:")

        for alert in sorted(
            detected,
            key=lambda x: x["confidence"],
            reverse=True,
        )[:10]:
            print(
                f"{alert['flow_id']} | "
                f"confidence={alert['confidence']:.3f} | "
                f"coverage={alert['evidence_coverage']:.2f}"
            )


if __name__ == "__main__":
    main()
