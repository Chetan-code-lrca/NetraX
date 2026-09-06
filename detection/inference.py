import os
import shutil
import subprocess
from pathlib import Path

import pandas as pd

from detection.c2.c2_detector import FEATURES as C2_FEATURES
from detection.c2.c2_detector import c2_score
from detection.dns_detector import detect_dns, load_dns_model
from detection.encrypted_malware_detector import (
    detect_encrypted_malware_batch,
    load_model as load_encrypted_model,
)
from detection.exfiltration_detector import detect_exfiltration
from detection.model_detector import (
    detect_model_batch,
    load_model,
)
from detection.pipeline import build_alert
from features.cicflow_adapter import adapt_cicflow_row


CICFLOWMETER_TIMEOUT_SECONDS = 120
DEFAULT_CICFLOWMETER_PATH = ".venv-cicflow/bin/cicflowmeter"
CICFLOWMETER_PATH_ENV_VAR = "NETRAX_CICFLOWMETER_PATH"
MAX_DASHBOARD_ALERTS = 500

FLOW_THREATS = (
    "PortScan",
    "DDoS",
)

SUPPORTED_THREATS = (
    "PortScan",
    "DDoS",
    "C2_Beaconing",
    "DGA_DNS_Tunneling",
    "Encrypted_Malware",
    "Data_Exfiltration",
)

EXFILTRATION_HINTS = {
    " Total Fwd Packets",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    " Fwd Packet Length Mean",
    "Fwd Packet Length Mean",
    " Fwd Packet Length Max",
    "Fwd Packet Length Max",
    "Fwd Packets/s",
    " Fwd Packets/s",
    " Fwd IAT Mean",
    "Fwd IAT Mean",
    " Fwd IAT Std",
    "Fwd IAT Std",
}

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

FLOW_MODEL_HINT_COLUMNS = {
    " Destination Port",
    " Total Fwd Packets",
    "Fwd Packets/s",
    "Total Length of Fwd Packets",
}


class FlowExtractionError(Exception):
    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


class ModelUnavailableError(FlowExtractionError):
    """Raised when a detector's trained model artifact is missing."""


def _load_model_or_raise(threat_class):
    try:
        return load_model(threat_class)
    except FileNotFoundError as error:
        raise ModelUnavailableError(
            "model_unavailable",
            (
                f"Trained model for '{threat_class}' is not "
                "available on this server."
            ),
            details=str(error),
        ) from error


def _load_dns_model_or_raise():
    try:
        return load_dns_model()
    except FileNotFoundError as error:
        raise ModelUnavailableError(
            "model_unavailable",
            "Trained DNS model is not available on this server.",
            details=str(error),
        ) from error


def _load_encrypted_model_or_raise():
    try:
        return load_encrypted_model()
    except FileNotFoundError as error:
        raise ModelUnavailableError(
            "model_unavailable",
            (
                "Trained encrypted-malware model is not "
                "available on this server."
            ),
            details=str(error),
        ) from error


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


def resolve_cicflowmeter_path(
    cicflowmeter_path=DEFAULT_CICFLOWMETER_PATH,
):
    env_path = os.environ.get(CICFLOWMETER_PATH_ENV_VAR)
    if env_path:
        return env_path

    if Path(cicflowmeter_path).exists():
        return cicflowmeter_path

    found_on_path = shutil.which("cicflowmeter")
    if found_on_path:
        return found_on_path

    return cicflowmeter_path


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
    resolved_cicflowmeter_path = resolve_cicflowmeter_path(
        cicflowmeter_path,
    )

    command = [
        resolved_cicflowmeter_path,
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
        raise FlowExtractionError(
            "cicflow_timeout",
            "CICFlowMeter timed out.",
        ) from error
    except (FileNotFoundError, PermissionError) as error:
        raise FlowExtractionError(
            "cicflow_not_found",
            (
                "CICFlowMeter executable was not found "
                f"at '{resolved_cicflowmeter_path}'. Install it "
                "(pip install cicflowmeter) or set the "
                f"{CICFLOWMETER_PATH_ENV_VAR} environment "
                "variable to its path."
            ),
        ) from error

    if result.returncode != 0:
        details = (result.stderr or "").strip()
        raise FlowExtractionError(
            "cicflow_failed",
            "CICFlowMeter failed during flow extraction.",
            details=details[-2000:] if details else None,
        )

    if not flow_csv.exists():
        raise FlowExtractionError(
            "cicflow_missing_output",
            "CICFlowMeter completed but did not produce a flow CSV."
        )

    return pd.read_csv(flow_csv), suffix.lstrip(".")


def detect_input_contract(df, flow_models):
    columns = set(df.columns)

    if CICFLOW_REQUIRED.issubset(columns):
        return "flow_features"

    for model in flow_models.values():
        feature_names = set(model.feature_names_in_)
        if feature_names.issubset(columns):
            return "flow_features"

    if set(C2_FEATURES).issubset(columns):
        return "c2_behavioral"

    if ENCRYPTED_REQUIRED.issubset(columns):
        return "encrypted_flow"

    if any(name in columns for name in DNS_COLUMNS):
        return "dns_query"

    if EXFILTRATION_HINTS.intersection(columns):
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
    counts = {
        "detected": 0,
        "ambiguous": 0,
        "insufficient": 0,
    }

    rows = [
        series.to_dict()
        for _, series in df.iterrows()
    ]

    flow_ids = [
        f"flow-{index}"
        for index in df.index
    ]

    prepared_features = [
        {
            threat_class: _prepare_model_features(
                row,
                flow_models[threat_class],
            )
            for threat_class in FLOW_THREATS
        }
        for row in rows
    ]

    for threat_class in FLOW_THREATS:
        model = flow_models[threat_class]

        feature_rows = [
            item[threat_class]
            for item in prepared_features
        ]

        detector_alerts = detect_model_batch(
            threat_class=threat_class,
            feature_rows=feature_rows,
            flow_ids=flow_ids,
            model=model,
        )

        for index, alert in enumerate(detector_alerts):
            status = alert["status"]

            if status == "DETECTED":
                counts["detected"] += 1
            elif status == "AMBIGUOUS":
                counts["ambiguous"] += 1
            else:
                counts["insufficient"] += 1

            if status in ("DETECTED", "AMBIGUOUS"):
                alerts.append(
                    normalize_alert(
                        alert,
                        rows[index],
                        f"{threat_class.lower()}-{df.index[index]}",
                    )
                )

    exfiltration_alerts = []

    for index, row in zip(df.index, rows):
        exfiltration_alert = detect_exfiltration(
            _prepare_exfiltration_features(row),
            flow_id=f"flow-{index}",
        )

        status = exfiltration_alert["status"]

        if status == "DETECTED":
            counts["detected"] += 1
        elif status == "AMBIGUOUS":
            counts["ambiguous"] += 1
        else:
            counts["insufficient"] += 1

        if status in ("DETECTED", "AMBIGUOUS"):
            exfiltration_alerts.append(
                normalize_alert(
                    exfiltration_alert,
                    row,
                    f"data_exfiltration-{index}",
                )
            )

    alerts.extend(exfiltration_alerts)

    return alerts, counts

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
    counts = {
        "detected": 0,
        "ambiguous": 0,
        "insufficient": 0,
    }

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
        if status == "DETECTED":
            counts["detected"] += 1
        elif status == "AMBIGUOUS":
            counts["ambiguous"] += 1
        else:
            counts["insufficient"] += 1

        if status in ("DETECTED", "AMBIGUOUS"):
            alerts.append(
                normalize_alert(
                    alert,
                    row,
                    f"c2_beaconing-{index}",
                )
            )

    return alerts, counts


def _run_dns_detector(df, vectorizer, model):
    alerts = []
    counts = {
        "detected": 0,
        "ambiguous": 0,
        "insufficient": 0,
    }
    domain_column = next(
        column
        for column in DNS_COLUMNS
        if column in df.columns
    )

    for index, series in df.iterrows():
        row = series.to_dict()
        raw_domain = row.get(domain_column)
        if pd.isna(raw_domain):
            continue

        domain = str(raw_domain).strip()
        if not domain:
            continue

        result = detect_dns(domain)

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
        if status == "DETECTED":
            counts["detected"] += 1
        elif status == "AMBIGUOUS":
            counts["ambiguous"] += 1
        else:
            counts["insufficient"] += 1

        if status in ("DETECTED", "AMBIGUOUS"):
            alerts.append(
                normalize_alert(
                    alert,
                    row,
                    f"dga_dns_tunneling-{index}",
                )
            )

    return alerts, counts

def _run_encrypted_detector(df, model):
    alerts = []
    counts = {
        "detected": 0,
        "ambiguous": 0,
        "insufficient": 0,
    }

    rows = [
        series.to_dict()
        for _, series in df.iterrows()
    ]

    flow_ids = [
        f"encrypted-{index}"
        for index in df.index
    ]

    detector_alerts = detect_encrypted_malware_batch(
        rows=rows,
        flow_ids=flow_ids,
        model=model,
    )

    for index, alert in enumerate(detector_alerts):
        status = alert["status"]

        if status == "DETECTED":
            counts["detected"] += 1
        elif status == "AMBIGUOUS":
            counts["ambiguous"] += 1
        else:
            counts["insufficient"] += 1

        if status in ("DETECTED", "AMBIGUOUS"):
            alerts.append(
                normalize_alert(
                    alert,
                    rows[index],
                    f"encrypted_malware-{df.index[index]}",
                )
            )

    return alerts, counts

def validate_alert(alert):
    """
    Validate the standardized NetraX alert contract.

    Returns True when the alert satisfies the required schema.
    Raises ValueError when the alert is invalid.
    """

    required_fields = {
        "timestamp",
        "flow_id",
        "threat_class",
        "confidence",
        "status",
        "evidence",
        "observability",
        "observability_status",
        "available_evidence",
        "missing_evidence",
        "evidence_coverage",
    }

    missing = required_fields.difference(alert)

    if missing:
        raise ValueError(
            f"Alert missing required fields: "
            f"{sorted(missing)}"
        )

    if alert["threat_class"] not in SUPPORTED_THREATS:
        raise ValueError(
            f"Unsupported threat class: "
            f"{alert['threat_class']!r}"
        )

    if alert["status"] not in {
        "DETECTED",
        "AMBIGUOUS",
        "INSUFFICIENT",
    }:
        raise ValueError(
            f"Invalid alert status: "
            f"{alert['status']!r}"
        )

    try:
        confidence = float(
            alert["confidence"]
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Alert confidence must be numeric."
        ) from exc

    if not 0.0 <= confidence <= 1.0:
        raise ValueError(
            f"Alert confidence must be in [0, 1], "
            f"got {confidence}"
        )

    try:
        coverage = float(
            alert["evidence_coverage"]
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Alert evidence_coverage must be numeric."
        ) from exc

    if not 0.0 <= coverage <= 1.0:
        raise ValueError(
            f"Alert evidence_coverage must be in [0, 1], "
            f"got {coverage}"
        )

    if not isinstance(
        alert["evidence"],
        list,
    ):
        raise ValueError(
            "Alert evidence must be a list."
        )

    if not isinstance(
        alert["available_evidence"],
        list,
    ):
        raise ValueError(
            "Alert available_evidence must be a list."
        )

    if not isinstance(
        alert["missing_evidence"],
        list,
    ):
        raise ValueError(
            "Alert missing_evidence must be a list."
        )

    return True


def predict(
    threat_class,
    features,
    flow_id="unknown",
):
    """
    Public single-observation NetraX inference interface.

    Each threat is routed to its existing detector implementation.
    The detector result is passed through the existing alert pipeline,
    including separability enrichment, and then validated.
    """

    if threat_class not in SUPPORTED_THREATS:
        raise ValueError(
            f"Unsupported threat class: {threat_class!r}"
        )

    # =====================================================
    # 1. PortScan / DDoS
    # =====================================================

    if threat_class in FLOW_THREATS:
        alert = detect_model(
            threat_class=threat_class,
            features=features,
            flow_id=flow_id,
        )

        validate_alert(alert)
        return alert

    # =====================================================
    # 2. C2 Beaconing
    # =====================================================

    if threat_class == "C2_Beaconing":
        numeric_features = {
            name: _safe_float(
                features.get(name, 0.0)
            )
            for name in C2_FEATURES
        }

        score, status, evidence = c2_score(
            numeric_features
        )

        alert = build_alert(
            threat_class="C2_Beaconing",
            confidence=float(score),
            status=status,
            evidence=evidence,
            flow_id=flow_id,
        )

        validate_alert(alert)
        return alert

    # =====================================================
    # 3. DNS / DGA / DNS Tunnelling
    # =====================================================

    if threat_class == "DGA_DNS_Tunneling":
        domain = str(features).strip()

        if not domain:
            raise ValueError(
                "DNS prediction requires a non-empty domain."
            )

        # detect_dns() loads its own vectorizer/model.
        result = detect_dns(domain)

        evidence = list(
            result.get("tunnelling_evidence", [])
        )

        if result.get("classification") in (1, 2):
            evidence.append("N-gram model anomaly")

        if (
            result.get("tunnelling_status") == "DETECTED"
            or result.get("classification") in (1, 2)
        ):
            status = "DETECTED"
        elif result.get("tunnelling_status") == "AMBIGUOUS":
            status = "AMBIGUOUS"
        else:
            status = "INSUFFICIENT"

        confidence = max(
            float(
                result.get(
                    "classification_confidence",
                    0.0,
                )
            ),
            float(
                result.get(
                    "tunnelling_score",
                    0.0,
                )
            ),
        )

        alert = build_alert(
            threat_class="DGA_DNS_Tunneling",
            confidence=confidence,
            status=status,
            evidence=list(
                dict.fromkeys(evidence)
            ),
            flow_id=flow_id,
        )

        validate_alert(alert)
        return alert

    # =====================================================
    # 4. Encrypted Malware
    # =====================================================

    if threat_class == "Encrypted_Malware":
        if not isinstance(features, pd.Series):
            features = pd.Series(features)

        # detect_encrypted_malware() uses its own model-loading
        # path, so do not pass model= here.
        alert = detect_encrypted_malware(
            features,
            flow_id=flow_id,
        )

        validate_alert(alert)
        return alert

    # =====================================================
    # 5. Data Exfiltration
    # =====================================================

    if threat_class == "Data_Exfiltration":
        alert = detect_exfiltration(
            features,
            flow_id=flow_id,
        )

        validate_alert(alert)
        return alert

    raise ValueError(
        f"No prediction route implemented for {threat_class!r}"
    )

def run_unified_inference(df):
    flow_models = {}
    columns = set(df.columns)
    if (
        _looks_like_flow_model_schema(columns)
        and not CICFLOW_REQUIRED.issubset(columns)
    ):
        flow_models = {
            threat_class: _load_model_or_raise(threat_class)
            for threat_class in FLOW_THREATS
        }

    try:
        contract = detect_input_contract(
            df,
            flow_models=flow_models,
        )
    except ValueError:
        if flow_models:
            raise

        flow_models = {
            threat_class: _load_model_or_raise(threat_class)
            for threat_class in FLOW_THREATS
        }
        contract = detect_input_contract(
            df,
            flow_models=flow_models,
        )

    if contract == "flow_features":
        if not flow_models:
            flow_models = {
                threat_class: _load_model_or_raise(threat_class)
                for threat_class in FLOW_THREATS
            }
        alerts, counts = _run_flow_detectors(
            df,
            flow_models=flow_models,
        )
    elif contract == "c2_behavioral":
        alerts, counts = _run_c2_detector(df)
    elif contract == "dns_query":
        dns_vectorizer, dns_model = _load_dns_model_or_raise()
        alerts, counts = _run_dns_detector(
            df,
            dns_vectorizer,
            dns_model,
        )
    elif contract == "encrypted_flow":
        encrypted_model = _load_encrypted_model_or_raise()
        alerts, counts = _run_encrypted_detector(
            df,
            encrypted_model,
        )
    else:
        alerts = []
        counts = {
            "detected": 0,
            "ambiguous": 0,
            "insufficient": 0,
        }

    alerts.sort(
        key=lambda item: (
            _safe_float(
                item.get("confidence")
            )
        ),
        reverse=True,
    )

    dashboard_alerts = alerts[:MAX_DASHBOARD_ALERTS]

    return {
        "contract": contract,
        "alerts": dashboard_alerts,
        "alerts_generated": int(len(alerts)),
        "alerts_returned": int(len(dashboard_alerts)),
        "alerts_truncated": (
            len(alerts) > MAX_DASHBOARD_ALERTS
        ),
        "summary": {
            "detected": int(counts["detected"]),
            "ambiguous": int(counts["ambiguous"]),
            "insufficient": int(counts["insufficient"]),
        },
        "packets_processed": estimate_packet_count(df),
    }


def _looks_like_flow_model_schema(columns):
    return bool(
        FLOW_MODEL_HINT_COLUMNS.intersection(
            set(columns)
        )
    ) or CICFLOW_REQUIRED.issubset(set(columns))
