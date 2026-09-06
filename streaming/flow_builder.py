import pandas as pd


FLOW_KEY = [
    "ip.src",
    "tcp.srcport",
    "udp.srcport",
    "ip.dst",
    "tcp.dstport",
    "udp.dstport",
    "ip.proto",
]


def prepare_packets(path):
    """
    Load packet observations and normalize TCP/UDP ports.
    """

    df = pd.read_csv(path, sep="\t")

    df["src_port"] = df["tcp.srcport"].fillna(df["udp.srcport"])
    df["dst_port"] = df["tcp.dstport"].fillna(df["udp.dstport"])

    df["time"] = pd.to_datetime(
        df["frame.time_epoch"],
        unit="s"
    )

    return df[
        [
            "time",
            "ip.src",
            "ip.dst",
            "ip.proto",
            "src_port",
            "dst_port",
            "frame.len",
        ]
    ]


def build_one_way_flows(df, inactivity_timeout=60.0):
    """
    Aggregate packets into time-bounded originator-side flows.

    A new flow is created when:
      1. the 5-tuple changes, or
      2. the gap between consecutive packets exceeds inactivity_timeout.

    Only packets in the observed direction are included.
    """

    work = df.copy()

    work = work.sort_values("time")

    work["flow_key"] = list(
        zip(
            work["ip.src"],
            work["src_port"],
            work["ip.dst"],
            work["dst_port"],
            work["ip.proto"],
        )
    )

    flows = []

    for flow_key, group in work.groupby("flow_key", sort=False):
        group = group.sort_values("time").reset_index(drop=True)

        # Split the same 5-tuple whenever there is a long idle period.
        gaps = group["time"].diff().dt.total_seconds()

        segment_id = (gaps > inactivity_timeout).cumsum()

        for _, segment in group.groupby(segment_id, sort=False):
            segment = segment.sort_values("time")

            timestamps = (
                segment["time"].astype("int64") / 1e9
            )

            lengths = segment["frame.len"].astype(float)

            duration = (
                timestamps.iloc[-1] - timestamps.iloc[0]
            )

            iat = timestamps.diff().dropna()

            flows.append({
                "src": flow_key[0],
                "src_port": flow_key[1],
                "dst": flow_key[2],
                "dst_port": flow_key[3],
                "proto": flow_key[4],

                "start": segment["time"].iloc[0],
                "end": segment["time"].iloc[-1],

                "duration": duration,
                "packet_count": len(segment),
                "total_bytes": lengths.sum(),

                "packet_mean": lengths.mean(),
                "packet_min": lengths.min(),
                "packet_max": lengths.max(),

                "iat_mean": (
                    iat.mean()
                    if len(iat)
                    else 0.0
                ),

                "iat_std": (
                    iat.std()
                    if len(iat) > 1
                    else 0.0
                ),

                "iat_min": (
                    iat.min()
                    if len(iat)
                    else 0.0
                ),

                "iat_max": (
                    iat.max()
                    if len(iat)
                    else 0.0
                ),
            })

    return pd.DataFrame(flows)