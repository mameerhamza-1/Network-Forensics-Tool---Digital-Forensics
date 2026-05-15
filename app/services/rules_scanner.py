from __future__ import annotations

from typing import Any, Dict, List
import re

_RULES = [
    {"name": "YARA-like Credential Pattern", "type": "YARA", "severity": "High", "pattern": r"(?i)(password|passwd|pwd|username|login)=", "description": "Payload contains credential-style key/value strings."},
    {"name": "YARA-like Web Shell Keyword", "type": "YARA", "severity": "High", "pattern": r"(?i)(cmd=|shell=|exec\(|system\(|passthru\()", "description": "Payload contains command execution keywords."},
    {"name": "Sigma-like Path Traversal", "type": "Sigma", "severity": "High", "pattern": r"(?i)(\.\./|%2e%2e%2f|/etc/passwd|boot\.ini)", "description": "Network log contains path traversal artifacts."},
    {"name": "Sigma-like SQL Injection", "type": "Sigma", "severity": "High", "pattern": r"(?i)(union\s+select|or\s+1=1|drop\s+table|information_schema)", "description": "Network log contains SQL injection indicators."},
    {"name": "Sigma-like Suspicious PowerShell", "type": "Sigma", "severity": "Medium", "pattern": r"(?i)(powershell|encodedcommand|frombase64string)", "description": "Payload contains PowerShell execution indicators."},
]


def scan_payload_rules(events_df) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if "payload" not in events_df.columns:
        return findings
    for idx, row in events_df.iterrows():
        payload = str(row.get("payload", "") or "")
        if not payload:
            continue
        for rule in _RULES:
            if re.search(rule["pattern"], payload):
                findings.append({
                    "rule_name": rule["name"], "rule_type": rule["type"], "severity": rule["severity"],
                    "src_ip": str(row.get("src_ip", "N/A")), "dst_ip": str(row.get("dst_ip", "N/A")),
                    "timestamp": str(row.get("timestamp", "N/A")), "description": rule["description"],
                    "evidence": payload[:160]
                })
    # Deduplicate near-identical rows
    seen = set(); out = []
    for f in findings:
        key = (f["rule_name"], f["src_ip"], f["dst_ip"], f["evidence"][:60])
        if key not in seen:
            seen.add(key); out.append(f)
    return out[:80]
