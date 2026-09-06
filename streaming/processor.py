from detection.model_detector import detect_model
from detection.pipeline import build_alert
from detection.c2.c2_detector import c2_score
from detection.alert_logger import save_alert

class NetraXProcessor:
    """
    Core NetraX streaming processor.

    Receives already-extracted observations and routes them
    to the appropriate threat detector.
    """

    def process_model_event(self, threat_class, features, flow_id):
        """
        Process a PortScan or DDoS feature event.
        """

        if threat_class not in ["PortScan", "DDoS"]:
            raise ValueError(
                f"Unsupported ML threat class: {threat_class}"
            )

        return detect_model(
            threat_class=threat_class,
            features=features,
            flow_id=flow_id
        )

    def process_c2_event(self, features, flow_id):
        """
        Process a C2 behavioral feature event.
        """

        score, status, evidence = c2_score(features)

        return build_alert(
            threat_class="C2_Beaconing",
            confidence=score,
            status=status,
            evidence=evidence,
            flow_id=flow_id
        )

    def process(self, event):
        """
    Route one incoming observation to the correct detector
    and persist the resulting alert.
    """

        event_type = event.get("type")
        flow_id = event.get("flow_id", "unknown")

        if event_type == "model":
            alert = self.process_model_event(
                event["threat_class"],
                event["features"],
                flow_id
            )

        elif event_type == "c2":
            alert = self.process_c2_event(
                event["features"],
                flow_id
            )

        else:
             raise ValueError(
                f"Unknown event type: {event_type}"
            )

        save_alert(alert)

        return alert
