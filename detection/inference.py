import subprocess
from pathlib import Path

import pandas as pd

from detection.c2.c2_detector import FEATURES as C2_FEATURES
from detection.c2.c2_detector import c2_score
from detection.dns_detector import detect_dns, load_dns_model
from detection.encrypted_malware_detector import (
    detect_encrypted_malware,
    load_model as load_encrypted_model,
)
from detection.exfiltration_detector import detect_exfiltration
from detection.model_detector import detect_model, load_model
from detection.pipeline import build_alert
from features.cicflow_adapter import adapt_cicflow_row


CICFLOWMETER_TIMEOUT_SECONDS = 120
DEFAULT_CICFLOWMETER_PATH = ".venv-cicflow/bin/cicflowmeter"
MAX_DASHBOARD_ALERTS = 500

FLOW_THREATS = (
    "PortScan",
    "DDoS",
)

DNS_COLUMNS = (
    "domain",
    "query",
    "dns_query",
    "qname",
    "hostname",
)

ENCRYPTED_REQUIRED = {
    "bs",
    "ps",
    "td",
}

CICFLOW_REQUIRED = {
    "dst_port",
    "tot_fwd_pkts",
    "fwd_pkts_s",
    "totlen_fwd_pkts",
}

SOURCE_FIELDS = (
    "src_ip",
    "Src IP",
    "Source IP",
    " Source IP",
    "src",
    "SrcAddr",
)

DESTINATION_FIELDS = (
    "dst_ip",
    "Dst IP",
    "Destination IP",
    " Destination IP",
    "dst",
    "DstAddr",
)


def get_optional_value(row, names):
    for name in names:
        if name not in row:
            continue
        value = row.get(name)
        if pd.isna(value):
            continue
        return value
    return None


def estimate_packet_count(df):
    candidate_pairs = [
        (
            "tot_fwd_pkts",
            "tot_bwd_pkts",
        ),
        (
            "Total Fwd Packets",
            " Total Backward Packets",
        ),
        (
            " Total Fwd Packets",
            " Total Backward Packets",
        ),
    ]

    for forward_col, backward_col in candidate_pairs:
        if forward_col in df.columns and backward_col in df.columns:
            forward = pd.to_numeric(
                df[forward_col],
                errors="coerce",
            ).fillna(0)
            backward = pd.to_numeric(
                df[backward_col],
                errors="coerce",
            ).fillna(0)
            return int((forward + backward).sum())

    return None


def load_observations(
    input_path,
    suffix,
    workspace,
    cicflowmeter_path=DEFAULT_CICFLOWMETER_PATH,
    timeout_seconds=CICFLOWMETER_TIMEOUT_SECONDS,
):
    if suffix == ".csv":
        return pd.read_csv(input_path), "csv"

    flow_csv = workspace / "flows.csv"

    command = [
        cicflowmeter_path,
        "-f",
        str(input_path),
        "-c",
        str(flow_csv),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError(
            "CICFlowMeter timed out."
        ) from error

    if result.returncode != 0:
        raise RuntimeError(
            "CICFlowMeter failed.\n"
            + result.stderr[-3000:]
        )

    if not flow_csv.exists():
        raise RuntimeError(
            "CICFlowMeter completed but did not produce a flow CSV."
        )

    return pd.read_csv(flow_csv), suffix.lstrip(".")


def detect_input_contract(df, flow_models):
    columns = set(df.columns)

    if set(C2_FEATURES).issubset(columns):
        return "c2_behavioral"

    if ENCRYPTED_REQUIRED.issubset(columns):
        return "encrypted_flow"

    if any(name in columns for name in DNS_COLUMNS):
        return "dns_query"

    if CICFLOW_REQUIRED.issubset(columns):
        return "flow_features"

    for model in flow_models.values():
        feature_names = set(model.feature_names_in_)
        if feature_names.issubset(columns):
            return "flow_features"

    raise ValueError(
        "Unsupported CSV schema for NetraX detectors."
    )


def normalize_alert(alert, row, alert_id):
    normalized = alert.copy()
    normalized["alert_id"] = alert_id
    normalized["source"] = get_optional_value(row, SOURCE_FIELDS)
    normalized["destination"] = get_optional_value(
        row,
        DESTINATION_FIELDS,
    )
    return normalized


def _prepare_model_features(row, model):
    feature_names = list(model.feature_names_in_)

    if all(name in row for name in feature_names):
        return {
            name: row[name]
            for name in feature_names
        }

    return adapt_cicflow_row(
        row,
        feature_names,
    )


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _run_flow_detectors(df, flow_models):
    alerts = []

    for index, series in df.iterrows():
        row = series.to_dict()
        flow_id = f"flow-{index}"

        for threat_class in FLOW_THREATS:
            model = flow_models[threat_class]
            features = _prepare_model_features(row, model)
            alert = detect_model(
                threat_class=threat_class,
                features=features,
                flow_id=flow_id,
                model=model,
            )
            alerts.append(
                normalize_alert(
                    alert,
                    row,
                    f"{threat_class.lower()}-{index}",
                )
            )

        exfiltration_alert = detect_exfiltration(
            _prepare_exfiltration_features(row),
            flow_id=flow_id,
        )
        alerts.append(
            normalize_alert(
                exfiltration_alert,
                row,
                f"data_exfiltration-{index}",
            )
        )

    return alerts


def _prepare_exfiltration_features(row):
    features = dict(row)

    if "tot_fwd_pkts" in row:
        features["Total Fwd Packets"] = row["tot_fwd_pkts"]

    if "totlen_fwd_pkts" in row:
        features["Total Length of Fwd Packets"] = row[
            "totlen_fwd_pkts"
        ]

    if "fwd_pkt_len_mean" in row:
        features["Fwd Packet Length Mean"] = row[
            "fwd_pkt_len_mean"
        ]

    if "fwd_pkt_len_max" in row:
        features["Fwd Packet Length Max"] = row[
            "fwd_pkt_len_max"
        ]

    if "fwd_pkts_s" in row:
        features["Fwd Packets/s"] = row["fwd_pkts_s"]

    if "fwd_iat_mean" in row:
        features["Fwd IAT Mean"] = row["fwd_iat_mean"]

    if "fwd_iat_std" in row:
        features["Fwd IAT Std"] = row["fwd_iat_std"]

    return features


def _run_c2_detector(df):
    alerts = []

    for index, series in df.iterrows():
        row = series.to_dict()
        features = {
            name: _safe_float(row.get(name, 0.0))
            for name in C2_FEATURES
        }
        score, status, evidence = c2_score(features)
        alert = build_alert(
            threat_class="C2_Beaconing",
            confidence=score,
            status=status,
            evidence=evidence,
            flow_id=f"c2-{index}",
        )
        alerts.append(
            normalize_alert(
                alert,
                row,
                f"c2_beaconing-{index}",
            )
        )

    return alerts


def _run_dns_detector(df, vectorizer, model):
    alerts = []
    domain_column = next(
        column
        for column in DNS_COLUMNS
        if column in df.columns
    )

    for index, series in df.iterrows():
        row = series.to_dict()
        domain = str(row.get(domain_column, "")).strip()
        if not domain:
            continue

        result = detect_dns(
            domain,
            vectorizer=vectorizer,
            model=model,
        )

        evidence = list(result["tunnelling_evidence"])

        if result["classification"] in (1, 2):
            evidence.append("N-gram model anomaly")

        if (
            result["tunnelling_status"] == "DETECTED"
            or result["classification"] in (1, 2)
        ):
            status = "DETECTED"
        elif result["tunnelling_status"] == "AMBIGUOUS":
            status = "AMBIGUOUS"
        else:
            status = "INSUFFICIENT"

        confidence = max(
            float(result["classification_confidence"]),
            float(result["tunnelling_score"]),
        )

        alert = build_alert(
            threat_class="DGA_DNS_Tunneling",
            confidence=confidence,
            status=status,
            evidence=list(dict.fromkeys(evidence)),
            flow_id=f"dns-{index}",
        )
        alerts.append(
            normalize_alert(
                alert,
                row,
                f"dga_dns_tunneling-{index}",
            )
        )

    return alerts


def _run_encrypted_detector(df, model):
    alerts = []

    for index, series in df.iterrows():
        row = series.to_dict()
        alert = detect_encrypted_malware(
            row,
            flow_id=f"encrypted-{index}",
            model=model,
        )
        alerts.append(
            normalize_alert(
                alert,
                row,
                f"encrypted_malware-{index}",
            )
        )

    return alerts


def run_unified_inference(df):
    contract = None
    columns = set(df.columns)

    if set(C2_FEATURES).issubset(columns):
        contract = "c2_behavioral"
    elif ENCRYPTED_REQUIRED.issubset(columns):
        contract = "encrypted_flow"
    elif any(name in columns for name in DNS_COLUMNS):
        contract = "dns_query"

    flow_models = {}
    if contract is None:
        flow_models = {
            threat_class: load_model(threat_class)
            for threat_class in FLOW_THREATS
        }
        contract = detect_input_contract(
            df,
            flow_models=flow_models,
        )

    if contract == "flow_features":
        alerts = _run_flow_detectors(
            df,
            flow_models=flow_models,
        )
    elif contract == "c2_behavioral":
        alerts = _run_c2_detector(df)
    elif contract == "dns_query":
        dns_vectorizer, dns_model = load_dns_model()
        alerts = _run_dns_detector(
            df,
            dns_vectorizer,
            dns_model,
        )
    elif contract == "encrypted_flow":
        encrypted_model = load_encrypted_model()
        alerts = _run_encrypted_detector(
            df,
            encrypted_model,
        )
    else:
        alerts = []

    alerts.sort(
        key=lambda item: (
            _safe_float(
                item.get("confidence")
            )
        ),
        reverse=True,
    )

    positive_alerts = [
        alert
        for alert in alerts
        if alert["status"] in ("DETECTED", "AMBIGUOUS")
    ]

    dashboard_alerts = positive_alerts[:MAX_DASHBOARD_ALERTS]

    detected_count = sum(
        alert["status"] == "DETECTED"
        for alert in alerts
    )
    ambiguous_count = sum(
        alert["status"] == "AMBIGUOUS"
        for alert in alerts
    )
    insufficient_count = sum(
        alert["status"] == "INSUFFICIENT"
        for alert in alerts
    )

    return {
        "contract": contract,
        "alerts": dashboard_alerts,
        "alerts_generated": int(len(positive_alerts)),
        "alerts_returned": int(len(dashboard_alerts)),
        "alerts_truncated": (
            len(positive_alerts) > MAX_DASHBOARD_ALERTS
        ),
        "summary": {
            "detected": int(detected_count),
            "ambiguous": int(ambiguous_count),
            "insufficient": int(insufficient_count),
        },
        "packets_processed": estimate_packet_count(df),
    }
