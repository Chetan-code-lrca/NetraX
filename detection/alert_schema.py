from datetime import datetime


def create_alert(
    threat_class,
    confidence,
    status,
    evidence,
    flow_id="unknown"
):
    """
    Create the standardized NetraX alert schema.
    """

    return {
        "timestamp": datetime.now().isoformat(),
        "flow_id": flow_id,
        "threat_class": threat_class,
        "confidence": round(float(confidence), 3),
        "status": status,
        "evidence": evidence,
    }
