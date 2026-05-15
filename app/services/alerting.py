from __future__ import annotations

from typing import Any, Dict, List
import os
import requests


def build_alerts(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts = []
    summary = context.get("summary", {})
    score = int(summary.get("overall_risk_score", 0) or 0)
    if score >= 80:
        alerts.append({"severity": "Critical", "title": "Critical case risk", "message": f"Overall risk score is {score}. Immediate triage recommended."})
    elif score >= 60:
        alerts.append({"severity": "High", "title": "High case risk", "message": f"Overall risk score is {score}. Analyst review required."})
    if int(summary.get("credential_exposures", 0) or 0) > 0:
        alerts.append({"severity": "High", "title": "Credential exposure detected", "message": "Plaintext credential artifacts were found. Rotate exposed accounts."})
    if int(summary.get("ti_confirmed_iocs", 0) or 0) > 0:
        alerts.append({"severity": "High", "title": "Threat intelligence match", "message": "One or more IOCs matched external reputation intelligence."})
    return alerts[:20]


def send_webhook_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    url = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    if not url:
        return {"status": "disabled", "message": "ALERT_WEBHOOK_URL is not configured."}
    try:
        r = requests.post(url, json=alert, timeout=8)
        r.raise_for_status()
        return {"status": "sent", "code": r.status_code}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
