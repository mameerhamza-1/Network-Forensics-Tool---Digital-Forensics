from __future__ import annotations

from typing import Any, Dict, List


def severity(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def _provider_rows(vt_results: dict, ha_results: dict) -> List[dict]:
    rows: List[dict] = []
    for group in ["ips", "domains", "urls", "hashes"]:
        for item in vt_results.get(group, []) or []:
            if item.get("status") == "ok" and (int(item.get("score", 0) or 0) > 0 or int(item.get("malicious", 0) or 0) > 0 or int(item.get("suspicious", 0) or 0) > 0):
                rows.append({**item, "source_group": group})
    for item in ha_results.get("hashes", []) or []:
        if item.get("status") == "ok" and int(item.get("score", 0) or 0) > 0:
            rows.append({**item, "source_group": "hashes"})
    return rows


def correlate_threats(
    iocs: Dict[str, Any],
    local_attacks: List[Dict[str, Any]],
    risk_records: List[Dict[str, Any]],
    vt_results: Dict[str, Any] | None = None,
    ha_results: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    vt_results = vt_results or {}
    ha_results = ha_results or {}
    provider_rows = _provider_rows(vt_results, ha_results)

    indicator_map: Dict[str, dict] = {}
    for row in provider_rows:
        indicator = row.get("indicator")
        if not indicator:
            continue
        current = indicator_map.setdefault(indicator, {
            "indicator": indicator,
            "type": row.get("type", row.get("source_group", "ioc")),
            "providers": [],
            "score": 0,
            "malicious": 0,
            "suspicious": 0,
            "details": [],
        })
        current["providers"].append(row.get("provider", "Unknown"))
        current["score"] = max(int(current.get("score", 0)), int(row.get("score", 0) or 0))
        current["malicious"] += int(row.get("malicious", 0) or 0)
        current["suspicious"] += int(row.get("suspicious", 0) or 0)
        if row.get("detection_ratio"):
            current["details"].append(f"VT ratio {row['detection_ratio']}")
        if row.get("verdict"):
            current["details"].append(f"HA verdict {row['verdict']}")
        if row.get("malware_family") and row.get("malware_family") != "unknown":
            current["details"].append(f"Family {row['malware_family']}")

    correlated = []
    for item in indicator_map.values():
        item["providers"] = sorted(set(item["providers"]))
        item["severity"] = severity(int(item["score"]))
        item["details"] = "; ".join(dict.fromkeys(item["details"])) or "No malicious vendor consensus found."
        correlated.append(item)
    correlated.sort(key=lambda x: x.get("score", 0), reverse=True)

    local_max = max([int(a.get("risk_score", 0) or 0) for a in local_attacks] + [0])
    risk_max = max([int(r.get("risk_score", 0) or 0) for r in risk_records] + [0])
    ti_max = max([int(c.get("score", 0) or 0) for c in correlated] + [0])
    suspicious_payload_score = min(30, int(iocs.get("summary", {}).get("suspicious_payload_count", 0)) * 5)
    overall = min(100, int(max(local_max, risk_max) * 0.55 + ti_max * 0.35 + suspicious_payload_score))

    confidence = "High" if provider_rows and ti_max >= 60 else "Medium" if local_attacks or provider_rows else "Low"
    sophistication = "Advanced" if ti_max >= 80 and len(correlated) >= 3 else "Moderate" if local_attacks or ti_max >= 35 else "Low"

    return {
        "ioc_summary": iocs.get("summary", {}),
        "correlated_iocs": correlated[:100],
        "virustotal": vt_results,
        "hybrid_analysis": ha_results,
        "overall_threat_score": overall,
        "overall_severity": severity(overall),
        "confidence_level": confidence,
        "sophistication_level": sophistication,
        "provider_status": {
            "virustotal_enabled": any((vt_results.get(k) for k in ["ips", "domains", "urls", "hashes"])),
            "hybrid_analysis_enabled": bool(ha_results.get("hashes")),
        },
    }
