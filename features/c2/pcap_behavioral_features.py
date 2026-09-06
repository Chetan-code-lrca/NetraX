import pandas as pd


def extract_pcap_c2_features(
    flows,
    window="5min",
    source_ip=None
):
    """
    Create C2 behavioral features from one-way PCAP-derived flows.

    Only source-side observations are used.

    Output:
        src
        window
        flows_per_window
        unique_destinations
        unique_ports
        repeated_pairs
        periodic_pairs_cv1
        periodic_pairs_cv05
    """

    df = flows.copy()

    if source_ip is not None:
        df = df[df["src"] == source_ip].copy()

    if df.empty:
        return pd.DataFrame(
            columns=[
                "src",
                "window",
                "flows_per_window",
                "unique_destinations",
                "unique_ports",
                "repeated_pairs",
                "periodic_pairs_cv1",
                "periodic_pairs_cv05",
            ]
        )

    df["window"] = df["start"].dt.floor(window)

    rows = []

    for (src, win), group in df.groupby(
        ["src", "window"],
        sort=True
    ):
        pair_counts = (
            group.groupby(
                ["dst", "dst_port"]
            )
            .size()
        )

        repeated_pairs = int(
            (pair_counts >= 2).sum()
        )

        # Number of distinct destination/port pairs
        # that repeat regularly within the window.
        cv1 = 0
        cv05 = 0

        for (dst, port), pair in group.groupby(
            ["dst", "dst_port"]
        ):
            if len(pair) < 3:
                continue

            times = (
                pair["start"]
                .sort_values()
                .astype("int64")
                / 1e9
            )

            iat = times.diff().dropna()

            if len(iat) < 2 or iat.mean() <= 0:
                continue

            cv = iat.std() / iat.mean()

            if cv <= 1.0:
                cv1 += 1

            if cv <= 0.5:
                cv05 += 1

        rows.append({
            "src": src,
            "window": win,
            "flows_per_window": len(group),
            "unique_destinations": group["dst"].nunique(),
            "unique_ports": group["dst_port"].nunique(),
            "repeated_pairs": repeated_pairs,
            "periodic_pairs_cv1": cv1,
            "periodic_pairs_cv05": cv05,
        })

    return pd.DataFrame(rows)
