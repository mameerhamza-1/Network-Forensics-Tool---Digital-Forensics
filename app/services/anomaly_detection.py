from __future__ import annotations

from typing import Any, Dict, List
import pandas as pd


def detect_behavior_anomalies(events_df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Lightweight ML-style anomaly layer using robust statistics; no training required."""
    findings: List[Dict[str, Any]] = []
    if events_df.empty:
        return findings
    df = events_df.copy()
    if "length" not in df.columns:
        df["length"] = 0
    grouped = df.groupby("src_ip").agg(
        packet_count=("src_ip", "count"),
        unique_dsts=("dst_ip", "nunique"),
        unique_ports=("dst_port", "nunique"),
        total_bytes=("length", "sum"),
        avg_bytes=("length", "mean"),
    ).reset_index()
    for col in ["packet_count", "unique_dsts", "unique_ports", "total_bytes", "avg_bytes"]:
        median = float(grouped[col].median() or 0)
        mad = float((grouped[col] - median).abs().median() or 1)
        grouped[col + "_rz"] = (grouped[col] - median).abs() / (1.4826 * mad)
    for _, row in grouped.iterrows():
        score = int(min(100, max(row.get(c, 0) for c in grouped.columns if c.endswith("_rz")) * 18))
        reasons = []
        if row["packet_count_rz"] >= 3: reasons.append("abnormally high packet count")
        if row["unique_ports_rz"] >= 3: reasons.append("abnormally broad port activity")
        if row["unique_dsts_rz"] >= 3: reasons.append("abnormally broad destination spread")
        if row["total_bytes_rz"] >= 3: reasons.append("abnormally high data volume")
        if reasons:
            findings.append({
                "src_ip": str(row["src_ip"]),
                "score": max(35, score),
                "severity": "Critical" if score >= 80 else "High" if score >= 60 else "Medium",
                "reason": ", ".join(reasons),
                "packet_count": int(row["packet_count"]),
                "unique_dsts": int(row["unique_dsts"]),
                "unique_ports": int(row["unique_ports"]),
                "total_bytes": int(row["total_bytes"]),
            })
    return sorted(findings, key=lambda x: x["score"], reverse=True)[:30]
