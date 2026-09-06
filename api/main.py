from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


app = FastAPI(
    title="NetraX API",
    version="0.1.0",
    description="Passive one-way cyber threat analysis API",
)


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# Health
# ---------------------------------------------------------

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "netrax-api",
        "version": "0.1.0",
    }


# ---------------------------------------------------------
# Analysis placeholder
# ---------------------------------------------------------

@app.post("/api/analyze")
async def analyze(
    file: UploadFile = File(...),
):
    """
    Temporary upload endpoint.

    This confirms that the dashboard/backend file-transfer path works.
    Real NetraX analysis will be connected next.
    """

    suffix = Path(
        file.filename or ""
    ).suffix.lower()

    allowed = {
        ".pcap",
        ".pcapng",
        ".csv",
    }

    if suffix not in allowed:
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

    data = await file.read()

    # Temporary storage only for upload validation.
    with NamedTemporaryFile(
        delete=True,
        suffix=suffix,
    ) as tmp:

        tmp.write(data)
        tmp.flush()

        size = len(data)

        return {
            "status": "received",
            "filename": file.filename,
            "file_type": suffix.lstrip("."),
            "file_size": size,
            "message": (
                "Traffic file received successfully. "
                "Model analysis is not connected yet."
            ),
        }
