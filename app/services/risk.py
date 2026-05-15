"""
Unified Risk Scoring + Attacker Profile System

Key fixes vs prior version:
  - Removed Tor ports (9001/9030/9050/9150) from SUSPICIOUS_PORTS list to
    prevent double-counting with Tor detection score.
  - Raised VOLUME_THRESHOLD from 200 to 1000 so normal browsing traffic
    does not inflate risk scores.
  - Capped Tor score contribution more conservatively.
  - Suspicious port score now requires >=2 distinct suspicious ports
    before contributing (single hit may be coincidental).
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List

import pandas as pd

W_ATTACK_RISK_MAX = 40
W_TOR             = 35
W_TLS_SUSPICIOUS  = 20
W_SUSPICIOUS_PORT = 10
W_VOLUME          = 15
W_ATTACK_BASE     = 30

# Tor-specific ports removed from this list -- they are scored separately
# through the dedicated Tor detection module to avoid double-counting.
SUSPICIOUS_PORTS = {
    4444, 1337, 31337, 6666, 6667,
    23, 2323, 5900, 5901, 3389,
}

# Minimum distinct suspicious ports before adding to score (prevents 1-hit FP)
SUSPICIOUS_PORT_MIN_COUNT = 2

# Raised from 200 -- normal browsing easily generates >200 events
VOLUME_THRESHOLD = 1000


def _risk_label(score: int) -> str:
    if score >= 80: return "Critical"
    if score >= 60: return "High"
    if score >= 40: return "Medium"
    if score >= 20: return "Low"
    return "Minimal"


def compute_risk_scores(
    events_df: pd.DataFrame,
    attack_results: List[Dict[str, Any]],
    tor_findings: List[Dict[str, Any]],
    tls_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    event_counts: Dict[str, int] = defaultdict(int)
    port_hits:    Dict[str, set] = defaultdict(set)
    for _, row in events_df.iterrows():
        src   = str(row["src_ip"])
        dport = int(row["dst_port"])
        event_counts[src] += 1
        if dport in SUSPICIOUS_PORTS:
            port_hits[src].add(dport)

    attack_scores: Dict[str, int]  = defaultdict(int)
    attack_types:  Dict[str, set]  = defaultdict(set)
    for hit in attack_results:
        src = str(hit["src_ip"])
        attack_scores[src] += int(hit.get("risk_score", 50))
        attack_types[src].add(hit["attack_type"])

    tor_scores:  Dict[str, int]        = defaultdict(int)
    tor_reasons: Dict[str, List[str]]  = defaultdict(list)
    for f in tor_findings:
        src = str(f["src_ip"])
        tor_scores[src] += int(f.get("confidence", 80))
        tor_reasons[src].append(f["reason"])

    tls_scores:  Dict[str, int]        = defaultdict(int)
    tls_reasons: Dict[str, List[str]]  = defaultdict(list)
    for fp in tls_findings:
        src = str(fp["src_ip"])
        cls = fp.get("classification", "Normal")
        if cls != "Normal":
            tls_scores[src] += W_TLS_SUSPICIOUS
            tls_reasons[src].append(f"TLS: {cls}")

    all_ips = set(event_counts) | set(attack_scores) | set(tor_scores) | set(tls_scores)
    records = []
    for ip in all_ips:
        reasons = []
        score = 0

        # Attack contribution
        a_raw = min(attack_scores[ip], 200)
        score += int((a_raw / 200) * W_ATTACK_RISK_MAX)
        if attack_types[ip]:
            score += min(len(attack_types[ip]) * W_ATTACK_BASE, W_ATTACK_BASE * 3)
            reasons.extend(sorted(attack_types[ip]))

        # Tor contribution (capped more conservatively)
        t_raw = min(tor_scores[ip], 200)
        score += int((t_raw / 200) * W_TOR * 2)
        if tor_reasons[ip]:
            reasons.append("Tor-like behaviour detected")

        # TLS contribution
        score += min(tls_scores[ip], W_TLS_SUSPICIOUS * 3)
        if tls_reasons[ip]:
            reasons.extend(tls_reasons[ip][:2])

        # Suspicious port contribution -- require >=2 distinct hits
        sp_count = len(port_hits[ip])
        if sp_count >= SUSPICIOUS_PORT_MIN_COUNT:
            score += min(sp_count * W_SUSPICIOUS_PORT, W_SUSPICIOUS_PORT * 4)
            reasons.append(f"Suspicious ports used: {list(port_hits[ip])[:5]}")

        # Volume contribution -- only above raised threshold
        events = event_counts[ip]
        if events > VOLUME_THRESHOLD:
            vol = min(int(((events - VOLUME_THRESHOLD) / 2000) * W_VOLUME), W_VOLUME)
            score += vol
            if vol >= 5:
                reasons.append(f"High traffic volume ({events} events)")

        score = min(score, 100)
        records.append({
            "src_ip":       ip,
            "risk_score":   score,
            "risk_label":   _risk_label(score),
            "event_count":  event_counts[ip],
            "attack_types": list(attack_types[ip]),
            "tor_detected": tor_scores[ip] > 0,
            "tls_anomaly":  tls_scores[ip] > 0,
            "reasons":      list(dict.fromkeys(reasons)),
        })
    records.sort(key=lambda x: x["risk_score"], reverse=True)
    return records


def build_attacker_profiles(
    events_df: pd.DataFrame,
    attack_results: List[Dict[str, Any]],
    sessions: List[Dict[str, Any]],
    risk_records: List[Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    profile_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "src_ip": "", "event_count": 0, "session_count": 0,
        "attack_count": 0, "risk_score": 0,
        "primary_behaviors": set(), "top_targets": set(),
    })
    for _, row in events_df.iterrows():
        ip = str(row["src_ip"])
        profile_map[ip]["src_ip"] = ip
        profile_map[ip]["event_count"] += 1
        profile_map[ip]["top_targets"].add(str(row["dst_ip"]))
    for sess in sessions:
        ip = str(sess["src_ip"])
        profile_map[ip]["src_ip"] = ip
        profile_map[ip]["session_count"] += 1
        profile_map[ip]["primary_behaviors"].add(str(sess["protocol"]))
    for attack in attack_results:
        ip = str(attack["src_ip"])
        profile_map[ip]["src_ip"] = ip
        profile_map[ip]["attack_count"] += 1
        profile_map[ip]["risk_score"] += int(attack.get("risk_score", 0))
        profile_map[ip]["primary_behaviors"].add(attack["attack_type"])

    risk_by_ip = {r["src_ip"]: r for r in (risk_records or [])}
    profiles = []
    for ip, item in profile_map.items():
        if ip in risk_by_ip:
            item["risk_score"]   = risk_by_ip[ip]["risk_score"]
            item["risk_label"]   = risk_by_ip[ip]["risk_label"]
            item["tor_detected"] = risk_by_ip[ip].get("tor_detected", False)
        else:
            item["risk_score"] = min(
                item["risk_score"] + item["event_count"] // 5 + item["session_count"] * 2, 100)
            item["risk_label"]   = _risk_label(item["risk_score"])
            item["tor_detected"] = False

        item["primary_behaviors"] = (
            ", ".join(sorted(str(b) for b in item["primary_behaviors"])) or "General Activity"
        )
        item["top_targets"] = ", ".join(sorted(str(t) for t in list(item["top_targets"])[:5]))
        profiles.append(item)
    profiles.sort(key=lambda x: x["risk_score"], reverse=True)
    return profiles


def rank_suspicious_ips(attacker_profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(attacker_profiles, key=lambda x: x.get("risk_score", 0), reverse=True)
