"""Versioned feature contract for strictly one-direction CIC flow models.

The v1 list is deliberately limited to features classified as observable in the
master feature mapping for PortScan, DDoS, and Data_Exfiltration. It does not
include bidirectional flow duration or aggregate TCP flag counters.
"""

ONE_WAY_FEATURE_SCHEMA_ID = "netrax.flow.forward.v1"

ORIGINATOR_ONLY = [
    " Destination Port",
    " Total Fwd Packets",
    "Total Length of Fwd Packets",
    " Fwd Packet Length Max",
    " Fwd Packet Length Min",
    " Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    " Fwd IAT Total",
    " Fwd IAT Mean",
    " Fwd IAT Std",
    " Fwd IAT Max",
    " Fwd IAT Min",
    "Fwd PSH Flags",
    " Fwd URG Flags",
    " Fwd Header Length",
    "Fwd Packets/s",
    " Avg Fwd Segment Size",
    "Fwd Header Length.1",
    " Fwd Avg Bytes/Bulk",
    " Fwd Avg Packets/Bulk",
    " Fwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Init_Win_bytes_forward",
    " act_data_pkt_fwd",
    " min_seg_size_forward",
]

ONE_WAY_FEATURES = tuple(ORIGINATOR_ONLY)

# These legacy fields were previously included in ORIGINATOR_ONLY but the
# master mapping classifies them as responder-dependent. They are retained
# here only to provide actionable diagnostics for incompatible old artifacts.
RESPONDER_DEPENDENT_LEGACY_FEATURES = (
    " Flow Duration",
    " FIN Flag Count",
    " SYN Flag Count",
    " RST Flag Count",
    " PSH Flag Count",
    " ACK Flag Count",
    " URG Flag Count",
    " CWE Flag Count",
    " ECE Flag Count",
)


def get_one_way_features(columns):
    """Return v1 features present in columns, preserving contract order."""
    available = set(columns)
    return [column for column in ONE_WAY_FEATURES if column in available]


def unsupported_one_way_features(feature_names):
    """Return model features that are not approved by the v1 contract."""
    approved = set(ONE_WAY_FEATURES)
    return [
        str(name)
        for name in feature_names
        if name not in approved
    ]


def validate_one_way_feature_names(feature_names):
    """Validate a model's named input features against the v1 contract."""
    names = list(feature_names)
    if not names:
        raise ValueError(
            "Model has no named input features; retrain it using a pandas "
            "DataFrame and the NetraX feature contract."
        )

    unsupported = unsupported_one_way_features(names)
    if unsupported:
        raise ValueError(
            "Model uses features outside "
            f"{ONE_WAY_FEATURE_SCHEMA_ID}: {unsupported}. "
            "Retrain the model with the approved one-way feature set."
        )
    return names
