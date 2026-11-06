from fastapi.testclient import TestClient

from api import main
from detection.inference import FlowExtractionError


def test_analysis_error_does_not_expose_internal_diagnostics(monkeypatch):
    internal_path = "/srv/netrax/private-models/portscan_model.joblib"

    def fail_analysis(*_args, **_kwargs):
        raise FlowExtractionError(
            "model_unavailable",
            "A required analysis model is not available.",
            details=f"FileNotFoundError: {internal_path}",
        )

    monkeypatch.setattr(main, "_analyze_file", fail_analysis)

    response = TestClient(main.app).post(
        "/api/analyze",
        files={"file": ("capture.csv", b"src,dst\n10.0.0.1,10.0.0.2\n", "text/csv")},
    )

    assert response.status_code == 503
    payload = response.json()
    assert payload["error_code"] == "model_unavailable"
    assert "details" not in payload
    assert internal_path not in response.text
