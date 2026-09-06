import numpy as np
import pandas as pd


def extract_c2_behavioral_features(df):
    """
    Extract source-side C2 behavioral features.

    Expected columns:
        StartTime
        SrcAddr
        DstAddr
        Dport
        Dir
    """

    df = df.copy()

    df["Dir"] = df["Dir"].str.strip()
    df = df[df["Dir"] == "->"].copy()

    df["StartTime"] = pd.to_datetime(df["StartTime"])
    df["Dport"] = pd.to_numeric(df["Dport"], errors="coerce")

    df["window"] = df["StartTime"].dt.floor("5min")

    rows = []

    for (src, window), g in df.groupby(["SrcAddr", "window"]):

        pair_cvs = []

        for (_, _), x in g.groupby(["DstAddr", "Dport"]):

            if len(x) < 5:
                continue

            timestamps = (
                x["StartTime"]
                .astype("int64")
                .to_numpy()
                / 1e9
            )

            iat = np.diff(np.sort(timestamps))

            if len(iat) == 0:
                continue

            median_iat = np.median(iat)
            std_iat = np.std(iat)

            if median_iat > 0:
                cv = std_iat / median_iat
                pair_cvs.append(cv)

        rows.append({
            "src": src,
            "window": window,
            "flows_per_window": len(g),
            "unique_destinations": g["DstAddr"].nunique(),
            "unique_ports": g["Dport"].nunique(),
            "repeated_pairs": len(pair_cvs),
            "periodic_pairs_cv1": sum(cv < 1 for cv in pair_cvs),
            "periodic_pairs_cv05": sum(cv < 0.5 for cv in pair_cvs),
        })

    return pd.DataFrame(rows)
