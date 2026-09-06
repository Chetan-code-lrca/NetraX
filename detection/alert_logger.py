import json
from pathlib import Path


ALERT_LOG = Path("results/alerts.jsonl")


def save_alert(alert):
    """
    Append one NetraX alert to the persistent JSONL log.
    """

    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)

    with ALERT_LOG.open("a") as f:
        f.write(json.dumps(alert) + "\n")


def load_alerts():
    """
    Load all previously saved alerts.
    """

    if not ALERT_LOG.exists():
        return []

    alerts = []

    with ALERT_LOG.open("r") as f:
        for line in f:
            line = line.strip()

            if line:
                alerts.append(json.loads(line))

    return alerts

