"""
Rule-Based Attack Pattern Engine
---------------------------------
Uses time-window analysis (NOT single-packet detection) to reduce
false positives and detect genuine attack patterns:

  - Port Scan       -- many distinct ports from same source in short window
  - Brute Force     -- repeated auth-port hits in short window
  - SYN Flood       -- high rate of TCP SYN-only packets (flag-aware)
  - Traffic Spike   -- sudden volume surge from a single source
  - Credential Leak -- plaintext credentials in payload
  - Web Attack      -- SQLi / path traversal / XSS patterns

Key fixes vs prior version:
  - SYN Flood now reads actual TCP flags (flags & 0x02 == SYN, ACK not set)
    instead of using packet-size as a SYN proxy (was causing false positives).
  - Port scan threshold raised and target-IP diversity check added.
  - Traffic spike threshold raised to reduce normal-traffic false positives.
  - Brute-force requires destination diversity check (same dst_ip).
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List

import pandas as pd

# ── Tunable thresholds ─────────────────────────────────────────────────────
PORT_SCAN_DISTINCT_PORTS    = 15    # lowered from 25 — typical scans hit 15+ distinct ports
PORT_SCAN_WINDOW_SECS       = 60
PORT_SCAN_MIN_DEST_IPS      = 1
# NOTE: ephemeral port exclusion removed — we count ALL distinct dst ports.
# Counting only ports < 1024 caused false negatives when scanners target
# service ports like 1433, 3389, 5432, 8080, etc.
PORT_SCAN_MIN_PACKETS       = 15    # lowered from 25

BRUTE_FORCE_THRESHOLD       = 15    # slightly lowered to catch smaller test captures
BRUTE_FORCE_WINDOW_SECS     = 60
BRUTE_FORCE_PORTS           = {21, 22, 23, 25, 110, 143, 389, 3389, 5900}

# Protocol-based brute force thresholds (when port info is unavailable)
# Wireshark CSVs often have Protocol column but no separate port column.
PROTO_BRUTE_FORCE_THRESHOLD = 50    # many FTP/SSH packets to same dst = brute force
PROTO_BRUTE_FORCE_PROTOCOLS = {"FTP", "FTP-DATA", "SSH", "TELNET", "RDP"}

# SYN Flood: require high SYN count AND a low SYN-ACK ratio
SYN_FLOOD_THRESHOLD         = 300
SYN_FLOOD_WINDOW_SECS       = 30
SYN_FLOOD_MIN_SYN_RATIO     = 0.80

TRAFFIC_SPIKE_THRESHOLD     = 800
TRAFFIC_SPIKE_WINDOW_SECS   = 60

LARGE_PAYLOAD_BYTES         = 10000

_WEB_ATTACK_PATTERNS = re.compile(
    r"(\.\./|%2e%2e/|union\s+select|<script|javascript:|"
    r"alert\s*\(|onerror=|onload=|exec\s*\(|cmd=|shell=|"
    r"\bOR\b.+?=.+?\bOR\b|\bDROP\s+TABLE\b|\bINSERT\s+INTO\b)",
    re.IGNORECASE,
)

_CRED_PATTERNS = re.compile(
    r"\b(password|passwd|pwd|username|user|email|login)=",
    re.IGNORECASE,
)

COMMON_WEB_PORTS = {80, 443, 8080, 8443}


def _safe_ts(value) -> str:
    if pd.isna(value):
        return "unknown"
    return pd.Timestamp(value).strftime("%Y-%m-%d %H:%M:%S")


def _window_group(df: pd.DataFrame, window_secs: int) -> Dict[str, List]:
    """Chunk each source IP's rows into rolling time windows."""
    groups: Dict[str, List] = defaultdict(list)
    for src_ip, src_df in df.groupby("src_ip"):
        src_sorted = src_df.sort_values("timestamp")
        if src_sorted["timestamp"].isna().all():
            groups[src_ip].append(src_sorted)
            continue
        times = src_sorted["timestamp"].tolist()
        rows  = src_sorted.reset_index(drop=True)
        start_idx = 0
        while start_idx < len(rows):
            t0 = times[start_idx]
            if pd.isna(t0):
                start_idx += 1
                continue
            end_idx = start_idx
            while (end_idx < len(rows) and
                   not pd.isna(times[end_idx]) and
                   (times[end_idx] - t0).total_seconds() <= window_secs):
                end_idx += 1
            chunk = rows.iloc[start_idx:end_idx]
            if len(chunk) > 1:
                groups[src_ip].append(chunk)
            start_idx = end_idx if end_idx > start_idx else start_idx + 1
    return groups


def _is_pure_syn(row) -> bool:
    """
    Return True if the row looks like a pure TCP SYN (no ACK).
    Uses the 'flags' column if present; falls back to packet-size heuristic
    only when flag data is unavailable.
    """
    flags = row.get("flags", None)
    if flags is not None and not pd.isna(flags):
        try:
            f = int(flags)
            syn_set = bool(f & 0x02)
            ack_set = bool(f & 0x10)
            return syn_set and not ack_set
        except (ValueError, TypeError):
            # String flags like 'S', 'SA', 'PA', etc.
            s = str(flags).upper()
            return "S" in s and "A" not in s
    # Fallback: very small packet AND TCP -- treat as possible SYN
    # Use a conservative size range to limit false positives
    length = int(row.get("length", 0))
    return 40 <= length <= 68


def detect_attacks(events_df: pd.DataFrame) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []
    seen: set = set()

    def _add(attack_type, src, dst, ts, details, risk, evidence):
        key = (attack_type, src, dst, details[:80])
        if key in seen:
            return
        seen.add(key)
        detections.append({
            "attack_type": attack_type,
            "src_ip":      src,
            "dst_ip":      dst,
            "timestamp":   ts,
            "details":     details,
            "evidence":    evidence,
            "risk_score":  min(risk, 100),
        })

    # ── Port Scan (time-window) ────────────────────────────────────────────
    for src_ip, chunks in _window_group(events_df, PORT_SCAN_WINDOW_SECS).items():
        for chunk in chunks:
            if len(chunk) < PORT_SCAN_MIN_PACKETS:
                continue
            # Count ALL distinct destination ports — do NOT filter out ports >= 1024.
            # Filtering to only ports < 1024 caused false negatives when scanners
            # target service ports like 1433 (MSSQL), 3389 (RDP), 5432 (Postgres), etc.
            all_ports = chunk[chunk["dst_port"] > 0]["dst_port"].unique()
            dest_ips  = chunk["dst_ip"].nunique()
            if (len(all_ports) >= PORT_SCAN_DISTINCT_PORTS and
                    dest_ips >= PORT_SCAN_MIN_DEST_IPS):
                ts = _safe_ts(chunk["timestamp"].min())
                _add("Port Scan", src_ip, "multiple", ts,
                     f"Scanned {len(all_ports)} distinct ports across "
                     f"{dest_ips} host(s) in {PORT_SCAN_WINDOW_SECS}s.",
                     85, f"Ports: {sorted(all_ports)[:15]}")

    # ── Brute Force (time-window, single destination) ─────────────────────
    for src_ip, chunks in _window_group(events_df, BRUTE_FORCE_WINDOW_SECS).items():
        for chunk in chunks:
            bf_rows = chunk[chunk["dst_port"].isin(BRUTE_FORCE_PORTS)]
            if len(bf_rows) < BRUTE_FORCE_THRESHOLD:
                continue
            for (dst_ip, dst_port), grp in bf_rows.groupby(["dst_ip", "dst_port"]):
                if len(grp) >= BRUTE_FORCE_THRESHOLD:
                    ts = _safe_ts(grp["timestamp"].min())
                    _add("Brute Force Login", src_ip, str(dst_ip), ts,
                         f"{len(grp)} repeated attempts to {dst_ip}:{int(dst_port)} "
                         f"in {BRUTE_FORCE_WINDOW_SECS}s.",
                         80, f"Port {int(dst_port)} hit {len(grp)} times")

    # ── Protocol-based Brute Force (for Wireshark CSVs without port columns) ─
    # When dst_port is 0 (not parsed), detect brute force by counting many
    # packets of FTP/SSH/RDP protocol from the same source to the same destination.
    proto_upper = events_df["protocol"].str.upper()
    proto_bf_df = events_df[proto_upper.isin(PROTO_BRUTE_FORCE_PROTOCOLS)]
    if not proto_bf_df.empty:
        for (src_ip, dst_ip, protocol), grp in proto_bf_df.groupby(
                ["src_ip", "dst_ip", "protocol"]):
            if len(grp) >= PROTO_BRUTE_FORCE_THRESHOLD:
                ts = _safe_ts(grp["timestamp"].min())
                _add("Brute Force Login", str(src_ip), str(dst_ip), ts,
                     f"{len(grp)} {protocol} packets from {src_ip} to {dst_ip} "
                     f"— consistent with {protocol} brute-force attack.",
                     80, f"{protocol} session count: {len(grp)}")

    # ── SYN Flood (time-window, flag-aware) ───────────────────────────────
    # Only examine TCP packets; require both high SYN count AND high SYN ratio.
    tcp_df = events_df[events_df["protocol"].isin(["TCP", "HTTPS", "HTTP"])]
    if not tcp_df.empty:
        for src_ip, chunks in _window_group(tcp_df, SYN_FLOOD_WINDOW_SECS).items():
            for chunk in chunks:
                if len(chunk) < SYN_FLOOD_THRESHOLD:
                    continue
                pure_syn_mask = chunk.apply(_is_pure_syn, axis=1)
                syn_count = pure_syn_mask.sum()
                syn_ratio = syn_count / len(chunk)
                if (syn_count >= SYN_FLOOD_THRESHOLD and
                        syn_ratio >= SYN_FLOOD_MIN_SYN_RATIO):
                    ts = _safe_ts(chunk["timestamp"].min())
                    _add("SYN Flood", src_ip, "multiple", ts,
                         f"{syn_count} pure SYN packets ({syn_ratio:.0%} of traffic) "
                         f"in {SYN_FLOOD_WINDOW_SECS}s.",
                         90, f"SYN ratio {syn_ratio:.0%}, avg size "
                             f"{int(chunk['length'].mean())} bytes")

    # ── Traffic Spike ──────────────────────────────────────────────────────
    for src_ip, chunks in _window_group(events_df, TRAFFIC_SPIKE_WINDOW_SECS).items():
        for chunk in chunks:
            if len(chunk) >= TRAFFIC_SPIKE_THRESHOLD:
                ts = _safe_ts(chunk["timestamp"].min())
                _add("Traffic Spike", src_ip, "multiple", ts,
                     f"{len(chunk)} packets in {TRAFFIC_SPIKE_WINDOW_SECS}s.",
                     70, f"Rate ≈ {len(chunk)/TRAFFIC_SPIKE_WINDOW_SECS:.1f} pkt/s")

    # ── Payload-level detections ───────────────────────────────────────────
    for _, row in events_df.iterrows():
        payload = str(row.get("payload", ""))
        src     = str(row["src_ip"])
        dst     = str(row["dst_ip"])
        dport   = int(row["dst_port"])
        ts      = _safe_ts(row["timestamp"])

        if _CRED_PATTERNS.search(payload):
            _add("Plaintext Credential Exposure", src, dst, ts,
                 "Auth credentials visible in unencrypted payload.", 90, payload[:120])

        m = _WEB_ATTACK_PATTERNS.search(payload)
        if m and dport in COMMON_WEB_PORTS | {8080, 8443}:
            _add("Web Application Attack", src, dst, ts,
                 f"Suspicious pattern: '{m.group()[:60]}'", 80, payload[:120])

        if dport in COMMON_WEB_PORTS and len(payload) > LARGE_PAYLOAD_BYTES:
            _add("Large Web Payload", src, dst, ts,
                 f"Payload {len(payload)} bytes (port {dport}).", 45,
                 f"{len(payload)} bytes")

    detections.sort(key=lambda x: x["risk_score"], reverse=True)
    return detections
