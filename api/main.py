import hashlib
import logging
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from detection.inference import (
    FlowExtractionError,
    load_observations,
    run_unified_inference,
)


APP_VERSION = "0.4.0"
logger = logging.getLogger(__name__)

ALLOWED_SUFFIXES = {
    ".pcap",
    ".pcapng",
    ".csv",
}

MAX_UPLOAD_BYTES = 100 * 1024 * 1024


app = FastAPI(
    title="NetraX API",
    version=APP_VERSION,
    description=(
        "Passive one-way cyber threat analysis API"
    ),
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_origin_regex=(
        r"https?://"
        r"(localhost|127\.0\.0\.1)"
        r"(:\d+)?$"
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def build_analysis_id(digest):
    return (
        "analysis-"
        f"{digest.hexdigest()[:16]}"
    )


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "netrax-api",
        "version": APP_VERSION,
    }


@app.post("/api/analyze")
async def analyze(
    file: UploadFile = File(...),
):
    filename = (
        file.filename
        or "uploaded_traffic"
    )
    suffix = Path(filename).suffix.lower()

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
        with TemporaryDirectory(
            prefix="netrax_"
        ) as temp_dir:
            temp_dir_path = Path(temp_dir)
            input_path = temp_dir_path / filename

            analysis_digest = hashlib.sha256()
            analysis_digest.update(
                filename.encode("utf-8")
            )

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
                                "message": (
                                    "Uploaded file is too large."
                                ),
                            },
                        )

                    analysis_digest.update(chunk)
                    handle.write(chunk)

            try:
                df, input_type = load_observations(
                    input_path=input_path,
                    suffix=suffix,
                    workspace=temp_dir_path,
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
                return JSONResponse(
                    status_code=(
                        504
                        if error.code == "cicflow_timeout"
                        else 500
                    ),
                    content=content,
                )

            inference = run_unified_inference(df)

            return {
                "status": "complete",
                "analysis_id": build_analysis_id(
                    analysis_digest
                ),
                "filename": filename,
                "file_type": input_type,
                "flows_processed": int(len(df)),
                "packets_processed": inference[
                    "packets_processed"
                ],
                "alerts_generated": inference[
                    "alerts_generated"
                ],
                "alerts_returned": inference[
                    "alerts_returned"
                ],
                "alerts_truncated": inference[
                    "alerts_truncated"
                ],
                "summary": inference["summary"],
                "alerts": inference["alerts"],
            }

    except Exception:
        logger.exception(
            "Traffic analysis failed for %s",
            filename,
        )
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": (
                    "Traffic analysis failed "
                    "inside the analysis service."
                ),
            },
        )
