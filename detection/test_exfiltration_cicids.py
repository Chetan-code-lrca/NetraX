import pandas as pd

from detection.exfiltration_detector import score_exfiltration


DATA = (
    "data/raw/MachineLearningCVE/"
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
)


def main():
    df = pd.read_csv(DATA)

    # Only use the two classes present in this file.
    infiltration = df[
        df[" Label"] == "Infiltration"
    ]

    benign = df[
        df[" Label"] == "BENIGN"
    ].sample(
        n=len(infiltration),
        random_state=42,
    )

    sample = pd.concat(
        [infiltration, benign],
        ignore_index=True,
    )

    results = []

    for _, row in sample.iterrows():

        features = {
            " Total Fwd Packets":
                row.get(" Total Fwd Packets", 0),

            "Total Length of Fwd Packets":
                row.get("Total Length of Fwd Packets", 0),

            " Fwd Packet Length Mean":
                row.get(" Fwd Packet Length Mean", 0),

            " Fwd Packet Length Max":
                row.get(" Fwd Packet Length Max", 0),

            "Fwd Packets/s":
                row.get("Fwd Packets/s", 0),

            " Fwd IAT Mean":
                row.get(" Fwd IAT Mean", 0),

            " Fwd IAT Std":
                row.get(" Fwd IAT Std", 0),
        }

        result = score_exfiltration(
            features
        )

        results.append({
            "ground_truth":
                row[" Label"],

            "score":
                result["score"],

            "status":
                result["status"],
        })

    result_df = pd.DataFrame(results)

    print("\n=== EXFILTRATION PROXY TEST ===")
    print(
        result_df.groupby(
            "ground_truth"
        )["score"].describe()
    )

    print("\n=== STATUS BY GROUND TRUTH ===")
    print(
        pd.crosstab(
            result_df["ground_truth"],
            result_df["status"],
        )
    )


if __name__ == "__main__":
    main()
