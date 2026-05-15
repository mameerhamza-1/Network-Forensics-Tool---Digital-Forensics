from __future__ import annotations

from typing import Any, Dict, List

_MITRE = {
    "Port Scan": {"tactic": "Discovery", "technique_id": "T1046", "technique": "Network Service Discovery", "recommendation": "Limit exposed services and investigate scanning source."},
    "Brute Force Login": {"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force", "recommendation": "Enable lockout/MFA and review authentication logs."},
    "SYN Flood": {"tactic": "Impact", "technique_id": "T1498", "technique": "Network Denial of Service", "recommendation": "Apply rate limiting and upstream DDoS filtering."},
    "Traffic Spike": {"tactic": "Impact", "technique_id": "T1498", "technique": "Network Denial of Service", "recommendation": "Validate traffic baseline and apply throttling."},
    "Plaintext Credential Exposure": {"tactic": "Credential Access", "technique_id": "T1552", "technique": "Unsecured Credentials", "recommendation": "Disable plaintext protocols and rotate exposed credentials."},
    "Web Application Attack": {"tactic": "Initial Access", "technique_id": "T1190", "technique": "Exploit Public-Facing Application", "recommendation": "Patch web app, add WAF rules, and review affected endpoint."},
    "Large Payload Anomaly": {"tactic": "Command and Control", "technique_id": "T1105", "technique": "Ingress Tool Transfer", "recommendation": "Inspect payloads and block suspicious transfer paths."},
}

_KEYWORDS = [
    ("credential", "Plaintext Credential Exposure"),
    ("password", "Plaintext Credential Exposure"),
    ("brute", "Brute Force Login"),
    ("scan", "Port Scan"),
    ("syn", "SYN Flood"),
    ("web", "Web Application Attack"),
    ("payload", "Large Payload Anomaly"),
    ("spike", "Traffic Spike"),
]


def map_attacks_to_mitre(attacks: List[Dict[str, Any]], threat_intel: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen = set()
    for attack in attacks or []:
        name = str(attack.get("attack_type") or attack.get("event") or "Unknown")
        key = name
        if key not in _MITRE:
            low = name.lower()
            for kw, mapped in _KEYWORDS:
                if kw in low:
                    key = mapped
                    break
        item = _MITRE.get(key)
        if not item:
            item = {"tactic": "Defense Evasion", "technique_id": "T1027", "technique": "Obfuscated/Compressed Files and Information", "recommendation": "Collect more evidence and validate suspicious artifacts."}
        dedupe = (item["technique_id"], str(attack.get("src_ip", "")))
        if dedupe in seen:
            continue
        seen.add(dedupe)
        rows.append({
            "attack_type": name,
            "src_ip": attack.get("src_ip", "N/A"),
            "dst_ip": attack.get("dst_ip", "N/A"),
            "tactic": item["tactic"],
            "technique_id": item["technique_id"],
            "technique": item["technique"],
            "recommendation": item["recommendation"],
            "risk_score": int(attack.get("risk_score", 0) or 0),
        })
    # Add TI confirmed malware behavior mapping when provider score is high.
    for ioc in (threat_intel or {}).get("correlated_iocs", []) or []:
        if int(ioc.get("score", 0) or 0) >= 60:
            rows.append({
                "attack_type": "Threat Intelligence Confirmed IOC",
                "src_ip": ioc.get("indicator", "N/A"),
                "dst_ip": "N/A",
                "tactic": "Command and Control",
                "technique_id": "T1071",
                "technique": "Application Layer Protocol",
                "recommendation": "Block IOC, search logs for historical contact, and isolate affected host.",
                "risk_score": int(ioc.get("score", 0) or 0),
            })
    return rows[:50]
