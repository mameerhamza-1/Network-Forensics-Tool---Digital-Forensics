
from __future__ import annotations

from typing import Dict, List
import pandas as pd

def reconstruct_sessions(events_df: pd.DataFrame) -> List[Dict[str, object]]:
    sessions: List[Dict[str, object]] = []
    grouped = events_df.groupby(["src_ip", "dst_ip", "src_port", "dst_port", "protocol"], dropna=False)
    for (src_ip, dst_ip, src_port, dst_port, protocol), group in grouped:
        first_seen = group["timestamp"].min()
        last_seen = group["timestamp"].max()
        duration = None
        if pd.notna(first_seen) and pd.notna(last_seen):
            duration = max((last_seen - first_seen).total_seconds(), 0.0)
        payload_sample = " ".join(group["payload"].astype(str).head(2).tolist())[:200]
        sessions.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": protocol,
            "packet_count": int(len(group)),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "duration_seconds": duration,
            "payload_sample": payload_sample,
        })
    sessions.sort(key=lambda x: x["packet_count"], reverse=True)
    return sessions
