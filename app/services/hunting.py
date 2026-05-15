from __future__ import annotations

from typing import Any, Dict, List


def hunt_context(context: Dict[str, Any], query: str) -> Dict[str, Any]:
    q = (query or "").strip().lower()
    results: List[Dict[str, Any]] = []
    if not q:
        return {"query": query, "count": 0, "results": []}
    groups = {
        "attacks": context.get("attacks", []),
        "timeline": context.get("timeline", []),
        "iocs": context.get("threat_intel", {}).get("correlated_iocs", []),
        "vt": context.get("virustotal_rows", []),
        "ha": context.get("hybrid_analysis_rows", []),
        "mitre": context.get("mitre_mappings", []),
        "rules": context.get("rule_findings", []),
        "anomalies": context.get("anomaly_findings", []),
    }
    for source, rows in groups.items():
        for row in rows:
            text = " ".join(str(v) for v in row.values()).lower() if isinstance(row, dict) else str(row).lower()
            if q in text:
                results.append({"source": source, "record": row})
    return {"query": query, "count": len(results), "results": results[:100]}
