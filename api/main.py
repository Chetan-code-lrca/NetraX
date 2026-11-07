import hashlib
import logging
import os
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from detection.inference import (
    FlowExtractionError,
    load_observations,
    run_unified_inference,
    resolve_cicflowmeter_path,
)

from detection.input_limits import MAX_FLOW_ROWS
from detection.model_paths import get_model_artifact_status


APP_VERSION = "0.5.0"
logger = logging.getLogger(__name__)

ALLOWED_SUFFIXES = {
    ".pcap",
    ".pcapng",
    ".csv",
}

MAX_UPLOAD_BYTES = 100 * 1024 * 1024

EXTRA_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("NETRAX_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]


app = FastAPI(
    title="NetraX API",
    version=APP_VERSION,
    description="Passive one-way cyber threat analysis API",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://netra-x-three.vercel.app",
        *EXTRA_ALLOWED_ORIGINS,
    ],
    # Preview/staging origins must be explicitly added through
    # NETRAX_ALLOWED_ORIGINS; do not trust every *.vercel.app deployment.
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


def build_analysis_id(digest):
    return f"analysis-{digest.hexdigest()[:16]}"


def _analyze_file(input_path, suffix, workspace):
    df, input_type = load_observations(
        input_path=input_path,
        suffix=suffix,
        workspace=workspace,
    )

    inference = run_unified_inference(df)

    return df, input_type, inference


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "netrax-api",
        "version": APP_VERSION,
    }


@app.get("/api/readiness")
def readiness():
    """Report optional runtime dependencies without loading model files."""
    artifacts = get_model_artifact_status()
    # Readiness is public operational metadata; do not disclose server paths.
    artifacts.pop("directory", None)
    converter = resolve_cicflowmeter_path()
    converter_path = shutil.which(converter) or converter
    converter_ready = (
        Path(converter_path).is_file()
        and os.access(converter_path, os.X_OK)
    )

    return {
        "status": (
            "ready"
            if artifacts["ready"] and converter_ready
            else "degraded"
        ),
        "model_artifacts": artifacts,
        "pcap_conversion": {
            "ready": converter_ready,
            "hint": (
                None
                if converter_ready
                else (
                    "Install CICFlowMeter with 'python -m pip install cicflowmeter' "
                    "or set NETRAX_CICFLOWMETER_PATH to its executable."
                )
            ),
        },
        "limits": {
            "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
            "max_flow_rows": MAX_FLOW_ROWS,
        },
    }


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    supplied_filename = file.filename or "uploaded_traffic"
    # Treat both POSIX and Windows separators as path separators. The uploaded
    # filename is untrusted metadata and must never be used as a filesystem path.
    filename = Path(supplied_filename.replace("\\", "/")).name or "uploaded_traffic"
    suffix = Path(filename).suffix.lower()

    if suffix not in ALLOWED_SUFFIXES:
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "message": "Unsupported file type. Use PCAP, PCAPNG or CSV.",
            },
        )

    try:
        with TemporaryDirectory(prefix="netrax_") as temp_dir:
            temp_dir_path = Path(temp_dir)
            # Use a server-generated path; preserve only the already-validated suffix.
            input_path = temp_dir_path / f"upload{suffix}"

            analysis_digest = hashlib.sha256()
            analysis_digest.update(filename.encode("utf-8"))

            bytes_written = 0

            with input_path.open("wb") as handle:
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break

                    bytes_written += len(chunk)
                    if bytes_written > MAX_UPLOAD_BYTES:
                        return JSONResponse(
                            status_code=413,
                            content={
                                "status": "error",
                                "message": "Uploaded file is too large.",
                            },
                        )

                    analysis_digest.update(chunk)
                    handle.write(chunk)

            try:
                df, input_type, inference = await run_in_threadpool(
                    _analyze_file,
                    input_path,
                    suffix,
                    temp_dir_path,
                )
            except FlowExtractionError as error:
                logger.warning(
                    "Flow extraction failed for %s: %s",
                    filename,
                    error.message,
                )
                content = {
                    "status": "error",
                    "message": error.message,
                    "error_code": error.code,
                }
                if error.details:
                    content["details"] = error.details

                if error.code == "too_many_flows":
                    status_code = 413
                elif error.code == "cicflow_timeout":
                    status_code = 504
                elif error.code in (
                    "cicflow_not_found",
                    "model_unavailable",
                ):
                    status_code = 503
                else:
                    status_code = 500

                return JSONResponse(
                    status_code=status_code,
                    content=content,
                )

            return {
                "status": "complete",
                "analysis_id": build_analysis_id(analysis_digest),
                "filename": filename,
                "file_type": input_type,
                "flows_processed": int(len(df)),
                "packets_processed": inference["packets_processed"],
                "alerts_generated": inference["alerts_generated"],
                "alerts_returned": inference["alerts_returned"],
                "alerts_truncated": inference["alerts_truncated"],
                "summary": inference["summary"],
                "alerts": inference["alerts"],
            }

    except Exception:
        logger.exception("Traffic analysis failed for %s", filename)
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": "Traffic analysis failed inside the analysis service.",
            },
        )
