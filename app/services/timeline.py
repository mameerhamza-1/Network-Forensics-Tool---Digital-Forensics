
from __future__ import annotations

from typing import Any, Dict, List
import pandas as pd

def build_timeline(events_df: pd.DataFrame, attack_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    timeline: List[Dict[str, Any]] = []
    for _, row in events_df.iterrows():
        timeline.append({
            "timestamp": row["timestamp"],
            "event": row["event_type"],
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "details": f"{row['protocol']} {row['src_port']}->{row['dst_port']}",
        })
    for attack in attack_results:
        timeline.append({
            "timestamp": attack.get("timestamp"),
            "event": attack.get("attack_type"),
            "src_ip": attack.get("src_ip"),
            "dst_ip": attack.get("dst_ip"),
            "details": attack.get("details"),
        })
    def _sort_key(item):
        ts = pd.to_datetime(item.get("timestamp"), errors="coerce")
        return (pd.isna(ts), ts if pd.notna(ts) else pd.Timestamp.max)
    timeline.sort(key=_sort_key)
    return timeline
