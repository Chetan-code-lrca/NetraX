from detection.alert_schema import create_alert
from separability.engine import enrich_alert


def build_alert(
    threat_class,
    confidence,
    status,
    evidence,
    flow_id="unknown"
):
    """
    Build a complete NetraX alert.

    Pipeline:
        Detector
          ↓
        Standard Alert
          ↓
        One-Way Separability Engine
          ↓
        Enriched Alert
    """

    alert = create_alert(
        threat_class=threat_class,
        confidence=confidence,
        status=status,
        evidence=evidence,
        flow_id=flow_id
    )

    return enrich_alert(alert)
