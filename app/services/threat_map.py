from __future__ import annotations

from typing import Any, Dict, List
import ipaddress
import hashlib

# Offline-safe pseudo geolocation for dashboard visualization. It avoids external API dependency.
_REGIONS = [
    ("United States", 37.0902, -95.7129), ("United Kingdom", 55.3781, -3.4360),
    ("Germany", 51.1657, 10.4515), ("Netherlands", 52.1326, 5.2913),
    ("Russia", 61.5240, 105.3188), ("China", 35.8617, 104.1954),
    ("Singapore", 1.3521, 103.8198), ("Pakistan", 30.3753, 69.3451),
    ("Brazil", -14.2350, -51.9253), ("Australia", -25.2744, 133.7751),
]


def _is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_multicast or obj.is_reserved or obj.is_link_local)
    except Exception:
        return False


def build_threat_map(events_df, suspicious_ranking: List[Dict[str, Any]], correlated_iocs: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    risk = {str(x.get("src_ip")): int(x.get("risk_score", 0) or 0) for x in suspicious_ranking or []}
    ti = {str(x.get("indicator")): int(x.get("score", 0) or 0) for x in correlated_iocs or []}
    ips = set()
    for col in ["src_ip", "dst_ip"]:
        if col in events_df.columns:
            ips.update(str(x) for x in events_df[col].dropna().unique())
    points = []
    for ip in sorted(ips):
        if not _is_public_ip(ip):
            continue
        idx = int(hashlib.sha256(ip.encode()).hexdigest(), 16) % len(_REGIONS)
        country, lat, lon = _REGIONS[idx]
        score = max(risk.get(ip, 0), ti.get(ip, 0))
        points.append({"ip": ip, "country": country, "lat": lat, "lon": lon, "score": score, "severity": "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 35 else "Low"})
    return {"points": points[:80], "total_public_ips": len(points), "note": "Offline-safe map approximation. Add GeoIP/MaxMind for exact geolocation."}
