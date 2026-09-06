from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess

import joblib
import pandas as pd
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from detection.pipeline import build_alert
from features.cicflow_adapter import adapt_cicflow_row


APP_VERSION = "0.3.0"

CICFLOWMETER_PATH = (
    ".venv-cicflow/bin/cicflowmeter"
)

MODEL_PATHS = {
    "PortScan": "detection/portscan_model.joblib",
    "DDoS": "detection/ddos_model.joblib",
}

ALLOWED_SUFFIXES = {
    ".pcap",
    ".pcapng",
    ".csv",
}

# Protect the browser from receiving enormous responses.
MAX_DASHBOARD_ALERTS = 500


app = FastAPI(
    title="NetraX API",
    version=APP_VERSION,
    description=(
        "Passive one-way cyber threat analysis API"
    ),
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# MODEL HELPERS
# =========================================================

def load_model(threat_class):
    """
    Load one of the trained NetraX models.
    """

    if threat_class not in MODEL_PATHS:
        raise ValueError(
            f"Unsupported threat class: {threat_class}"
        )

    path = Path(
        MODEL_PATHS[threat_class]
    )

    if not path.exists():
        raise FileNotFoundError(
            f"Model not found: {path}"
        )

    return joblib.load(path)


def get_model_features(model):
    """
    Return the exact feature order used when training.
    """

    if not hasattr(
        model,
        "feature_names_in_",
    ):
        raise ValueError(
            "Model does not contain feature_names_in_."
        )

    return list(
        model.feature_names_in_
    )


# =========================================================
# FEATURE PREPARATION
# =========================================================

def prepare_model_input(df, model):
    """
    Accept either:

    1. NetraX 29-feature format
    2. CICFlowMeter normalized 82-feature format
    3. Original CICFlowMeter-style names supported by
       features.cicflow_adapter
    """

    feature_names = get_model_features(model)

    # -----------------------------------------------------
    # Already in exact model format
    # -----------------------------------------------------

    if all(
        name in df.columns
        for name in feature_names
    ):
        X = df[
            feature_names
        ].copy()

    # -----------------------------------------------------
    # CICFlowMeter format
    # -----------------------------------------------------

    else:
        rows = []

        for _, row in df.iterrows():

            features = adapt_cicflow_row(
                row,
                feature_names,
            )

            rows.append(
                [
                    features[name]
                    for name in feature_names
                ]
            )

        X = pd.DataFrame(
            rows,
            columns=feature_names,
            index=df.index,
        )

    # -----------------------------------------------------
    # Clean numeric values
    # -----------------------------------------------------

    X = X.replace(
        [
            float("inf"),
            float("-inf"),
        ],
        pd.NA,
    )

    X = X.apply(
        pd.to_numeric,
        errors="coerce",
    )

    return X


# =========================================================
# EVIDENCE
# =========================================================

def build_evidence(
    row,
    threat_class,
):
    """
    Build evidence using only source-side / forward-side
    observable traffic features.
    """

    evidence = []

    if threat_class == "PortScan":

        try:
            if float(
                row.get("dst_port", 0)
            ) > 0:
                evidence.append(
                    "Destination-port activity"
                )
        except (TypeError, ValueError):
            pass

        try:
            if float(
                row.get("tot_fwd_pkts", 0)
            ) > 0:
                evidence.append(
                    "Source-side packet behavior"
                )
        except (TypeError, ValueError):
            pass

        try:
            if float(
                row.get("fwd_pkts_s", 0)
            ) > 0:
                evidence.append(
                    "Forward packet rate"
                )
        except (TypeError, ValueError):
            pass

        evidence.append(
            "Flow timing"
        )

    elif threat_class == "DDoS":

        try:
            if float(
                row.get("fwd_pkts_s", 0)
            ) > 0:
                evidence.append(
                    "Packet/flow rate"
                )
        except (TypeError, ValueError):
            pass

        try:
            if float(
                row.get("tot_fwd_pkts", 0)
            ) > 0:
                evidence.append(
                    "Source-side packet volume"
                )
        except (TypeError, ValueError):
            pass

        try:
            if float(
                row.get("totlen_fwd_pkts", 0)
            ) > 0:
                evidence.append(
                    "Packet-size characteristics"
                )
        except (TypeError, ValueError):
            pass

    return list(
        dict.fromkeys(evidence)
    )


# =========================================================
# ALERT GENERATION
# =========================================================

def build_model_alerts(
    df,
    threat_class,
    model,
):
    """
    Run one model in batch.

    IMPORTANT:
    Only flows positively classified as the requested
    threat are returned as alerts.

    Normal flows are not returned as alerts.
    """

    X = prepare_model_input(
        df,
        model,
    )

    valid_mask = (
        ~X.isna().any(axis=1)
    )

    X_valid = X.loc[
        valid_mask
    ]

    if X_valid.empty:
        return []

    # -----------------------------------------------------
    # Batch prediction
    # -----------------------------------------------------

    predictions = model.predict(
        X_valid
    )

    probabilities = model.predict_proba(
        X_valid
    )

    classes = list(
        model.classes_
    )

    class_to_index = {
        value: index
        for index, value
        in enumerate(classes)
    }

    alerts = []

    # -----------------------------------------------------
    # Positive detections only
    # -----------------------------------------------------

    for local_index, prediction in enumerate(
        predictions
    ):

        if str(prediction) != threat_class:
            continue

        original_index = X_valid.index[
            local_index
        ]

        row = df.loc[
            original_index
        ]

        confidence = float(
            probabilities[
                local_index,
                class_to_index[prediction],
            ]
        )

        evidence = build_evidence(
            row,
            threat_class,
        )

        source = row.get(
            "src_ip"
        )

        destination = row.get(
            "dst_ip"
        )

        if pd.isna(source):
            source = None

        if pd.isna(destination):
            destination = None

        alert = build_alert(
            threat_class=threat_class,
            confidence=confidence,
            status="DETECTED",
            evidence=evidence,
            flow_id=(
                f"flow-{original_index}"
            ),
        )

        alert["source"] = source
        alert["destination"] = destination

        # Helpful frontend metadata.
        alert["input_row"] = int(
            original_index
        )

        alerts.append(
            alert
        )

    return alerts


# =========================================================
# FLOW ANALYSIS
# =========================================================

def run_cicflow_analysis(
    csv_path,
):
    """
    Run the currently trained CICFlowMeter-based
    threat models.

    Current supported ML models:
      - PortScan
      - DDoS
    """

    df = pd.read_csv(
        csv_path
    )

    all_alerts = []

    for threat_class in (
        "PortScan",
        "DDoS",
    ):

        model = load_model(
            threat_class
        )

        alerts = build_model_alerts(
            df=df,
            threat_class=threat_class,
            model=model,
        )

        all_alerts.extend(
            alerts
        )

    return df, all_alerts


# =========================================================
# PACKET COUNT
# =========================================================

def estimate_packet_count(df):
    """
    Estimate packet count from CICFlowMeter forward +
    backward packet counts when available.
    """

    candidate_pairs = [
        (
            "tot_fwd_pkts",
            "tot_bwd_pkts",
        ),
        (
            "Total Fwd Packets",
            " Total Backward Packets",
        ),
    ]

    for forward_col, backward_col in candidate_pairs:

        if (
            forward_col in df.columns
            and backward_col in df.columns
        ):

            forward = pd.to_numeric(
                df[forward_col],
                errors="coerce",
            ).fillna(0)

            backward = pd.to_numeric(
                df[backward_col],
                errors="coerce",
            ).fillna(0)

            return int(
                (
                    forward
                    + backward
                ).sum()
            )

    return None


# =========================================================
# HEALTH
# =========================================================

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "netrax-api",
        "version": APP_VERSION,
    }


# =========================================================
# ANALYZE
# =========================================================

@app.post("/api/analyze")
async def analyze(
    file: UploadFile = File(...),
):
    """
    Analyze an uploaded PCAP / PCAPNG / CSV file.

    Current real model path:

        PCAP
          ↓
        CICFlowMeter
          ↓
        Flow CSV
          ↓
        PortScan + DDoS
          ↓
        NetraX Alert Schema
          ↓
        JSON
    """

    filename = (
        file.filename
        or "uploaded_traffic"
    )

    suffix = Path(
        filename
    ).suffix.lower()

    # -----------------------------------------------------
    # Validate extension
    # -----------------------------------------------------

    if suffix not in ALLOWED_SUFFIXES:

        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "message": (
                    "Unsupported file type. "
                    "Use PCAP, PCAPNG or CSV."
                ),
            },
        )

    try:

        contents = await file.read()

        # -------------------------------------------------
        # Temporary workspace
        # -------------------------------------------------

        with TemporaryDirectory(
            prefix="netrax_"
        ) as temp_dir:

            temp_dir = Path(
                temp_dir
            )

            input_path = (
                temp_dir / filename
            )

            input_path.write_bytes(
                contents
            )

            # =============================================
            # CSV
            # =============================================

            if suffix == ".csv":

                flow_csv = input_path

                df = pd.read_csv(
                    flow_csv
                )

                input_type = "csv"

            # =============================================
            # PCAP / PCAPNG
            # =============================================

            else:

                flow_csv = (
                    temp_dir
                    / "flows.csv"
                )

                command = [
                    CICFLOWMETER_PATH,
                    "-f",
                    str(input_path),
                    "-c",
                    str(flow_csv),
                ]

                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                )

                if result.returncode != 0:

                    return JSONResponse(
                        status_code=500,
                        content={
                            "status": "error",
                            "message": (
                                "CICFlowMeter "
                                "failed."
                            ),
                            "details": (
                                result.stderr[-3000:]
                            ),
                        },
                    )

                if not flow_csv.exists():

                    return JSONResponse(
                        status_code=500,
                        content={
                            "status": "error",
                            "message": (
                                "CICFlowMeter "
                                "completed but did not "
                                "produce a flow CSV."
                            ),
                        },
                    )

                df = pd.read_csv(
                    flow_csv
                )

                input_type = (
                    suffix.lstrip(".")
                )

            # =============================================
            # REAL MODEL ANALYSIS
            # =============================================

            df, alerts = (
                run_cicflow_analysis(
                    flow_csv
                )
            )

            # -------------------------------------------------
            # Unique detected flows
            # -------------------------------------------------

            detected_flow_ids = {
                alert["flow_id"]
                for alert in alerts
            }

            detected_flow_count = len(
                detected_flow_ids
            )

            insufficient_flow_count = max(
                len(df)
                - detected_flow_count,
                0,
            )

            # -------------------------------------------------
            # Keep dashboard response bounded
            # -------------------------------------------------

            alerts.sort(
                key=lambda item: (
                    item.get(
                        "confidence",
                        0.0,
                    )
                    or 0.0
                ),
                reverse=True,
            )

            dashboard_alerts = alerts[
                :MAX_DASHBOARD_ALERTS
            ]

            # -------------------------------------------------
            # Summary
            # -------------------------------------------------

            packets_processed = (
                estimate_packet_count(
                    df
                )
            )

            return {
                "status": "complete",

                "analysis_id": (
                    f"analysis-"
                    f"{abs(hash(filename))}"
                ),

                "filename": filename,

                "file_type": input_type,

                "flows_processed": int(
                    len(df)
                ),

                "packets_processed": (
                    packets_processed
                ),

                # True number of positive findings.
                "alerts_generated": int(
                    len(alerts)
                ),

                # Number actually returned to browser.
                "alerts_returned": int(
                    len(dashboard_alerts)
                ),

                "alerts_truncated": (
                    len(alerts)
                    > MAX_DASHBOARD_ALERTS
                ),

                "current_stage": (
                    "complete"
                ),

                "alerts": dashboard_alerts,

                "summary": {
                    "detected": int(
                        detected_flow_count
                    ),
                    "insufficient": int(
                        insufficient_flow_count
                    ),
                },
            }

    except Exception as exc:

        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": str(exc),
            },
        )