"""
Minimal outbound alert notification sender for Shadow AI Hunter.

Sends a compact JSON payload to a configured webhook URL (ALERT_WEBHOOK_URL)
when a high or critical alert is created. Fail-safe: delivery errors are logged
but never block or break the detection pipeline.
"""

import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime

logger = logging.getLogger(__name__)

# Severity levels that trigger outbound notifications
_NOTIFY_SEVERITIES = {"high", "critical"}


def should_notify(severity: str) -> bool:
    return severity.lower() in _NOTIFY_SEVERITIES


def send_alert_webhook(alert: dict) -> bool:
    """
    POST a compact alert payload to ALERT_WEBHOOK_URL.
    Returns True if delivered successfully, False otherwise.
    Does not raise exceptions — all failures are logged and swallowed.
    """
    webhook_url = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return False

    payload = {
        "title": alert.get("title", ""),
        "severity": alert.get("severity", ""),
        "source_project": alert.get("source_project"),
        "project_id": alert.get("project_id"),
        "detection_id": alert.get("detection_id"),
        "created_at": (
            alert.get("created_at").isoformat()
            if isinstance(alert.get("created_at"), datetime)
            else str(alert.get("created_at", ""))
        ),
    }

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            logger.info(
                f"[notification] Alert webhook delivered for '{alert.get('_id')}' "
                f"(severity={alert.get('severity')}) — HTTP {status}"
            )
            return True
    except urllib.error.HTTPError as e:
        logger.warning(
            f"[notification] Alert webhook HTTP error for '{alert.get('_id')}': "
            f"HTTP {e.code} — not retrying"
        )
    except urllib.error.URLError as e:
        logger.warning(
            f"[notification] Alert webhook URL error for '{alert.get('_id')}': "
            f"{e.reason} — not retrying"
        )
    except Exception as e:
        logger.warning(
            f"[notification] Alert webhook unexpected error for '{alert.get('_id')}': "
            f"{type(e).__name__}: {e} — not retrying"
        )

    return False


def notify_if_high_severity(alert: dict) -> None:
    """
    Send a webhook notification if the alert severity is high or critical.
    Safe to call fire-and-forget style — all errors are caught and logged.
    """
    if not should_notify(alert.get("severity", "")):
        return
    send_alert_webhook(alert)

