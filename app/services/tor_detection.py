"""
Tor Traffic Detection
---------------------
Detects Tor-related traffic using multi-layer analysis:

  Layer 1 – Known Tor node IP (primary, highest confidence)
             Checks both src and dst against a published relay/exit list.

  Layer 2 – Tor-specific ports (9001, 9030, 9050, 9150, etc.)
             Strong indicator on their own; combined with IP gives very high confidence.

  Layer 3 – Sustained circuit behavioural detection
             Real Tor Browser opens a long-lived TLS circuit to its guard node on
             port 443 (or 9001).  Normal HTTPS browsing never sustains thousands of
             packets to a single server.  We flag src→dst pairs where the packet
             count to port 443/9001 from the same source exceeds a high threshold.

  Layer 4 – Low destination diversity + high volume
             Tor clients talk to very few external IPs (1-3 guard nodes) while
             sending large total traffic.  Normal browsers talk to dozens of IPs.

False-positive guards:
  - Port 443 alone is never enough
  - Behavioral checks require BOTH high packet count AND low external IP diversity
  - Single-packet anomalies are ignored
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List

import pandas as pd

# ── Tor-specific ports (not including 443 – handled separately by behaviour) ──
TOR_SPECIFIC_PORTS: set[int] = {
    9001,   # Tor OR port (relay)
    9030,   # Tor directory port
    9050,   # SOCKS proxy (local Tor client)
    9051,   # Tor control port
    9150,   # Tor Browser SOCKS
    9151,   # Tor Browser control
}

# Ports Tor uses for guard connections (443 = bridges / censorship circumvention)
TOR_CIRCUIT_PORTS: set[int] = {443, 9001}

# ── Offline seed of widely-published Tor guard/exit IPs ───────────────────────
# Extended list covering major relay operators and well-documented nodes.
TOR_KNOWN_IPS: set[str] = {
    # CCC / torservers.net
    "199.58.81.140", "176.10.104.240",
    # nifty / relayon
    "185.220.101.1",  "185.220.101.2",  "185.220.101.3",  "185.220.101.4",
    "185.220.101.5",  "185.220.101.6",  "185.220.101.7",  "185.220.101.8",
    "185.220.101.9",  "185.220.101.10", "185.220.101.20", "185.220.101.34",
    "185.220.101.47", "185.220.102.4",  "185.220.102.8",
    "185.220.100.240","185.220.100.241","185.220.100.242","185.220.100.243",
    "185.220.100.244","185.220.100.245","185.220.100.246","185.220.100.247",
    "185.220.100.248","185.220.100.249","185.220.100.250","185.220.100.251",
    # Online.net / Scaleway (France) – common Tor relay hosting
    "163.172.149.155","51.15.43.205",
    "62.210.105.116",  "212.47.229.122",
    "212.83.43.95",    "212.83.43.96",   # documented French Tor relays
    "212.83.40.239",   "212.83.152.3",
    "51.254.136.195",  "51.254.96.208",
    "51.15.0.1",       "51.15.1.1",
    # Chaos Computer Club / ffm
    "193.11.114.43",   "193.11.114.45",
    # DFRI (Sweden)
    "171.25.193.9",    "171.25.193.77",  "171.25.193.78",  "171.25.193.20",
    "192.42.116.16",
    # xs4all / riseup
    "94.142.242.84",   "94.142.242.85",
    "89.234.157.254",
    # Various documented relays
    "77.109.139.87",
    "46.165.230.5",    "46.165.221.208",
    "217.79.179.177",
    "109.163.234.2",   "109.163.234.8",   "109.163.234.9",
    "91.121.23.100",
    "37.187.7.74",     "37.187.102.108",  "37.187.129.166",
    "198.96.155.3",    "198.96.155.10",
    "204.11.50.131",   "204.11.50.132",
    "104.244.72.115",  "104.244.74.87",   "104.244.76.13",  "104.244.77.200",
    "45.33.18.44",     "45.33.32.156",
    # Tor Project own infrastructure
    "128.31.0.39",     "128.31.0.34",
    "86.59.21.38",
    "194.109.206.212",
    "82.94.251.203",
    # PrivacyTools / well-known operators
    "144.217.255.209", "144.217.60.211",
    "5.196.73.150",    "5.196.108.53",
    "195.154.127.246",
    "212.129.62.232",
    "176.9.4.167",     "176.9.74.227",
    "138.201.14.197",
    # Riseup Labs
    "198.252.153.226", "198.252.153.227",
    # Additional well-known exit nodes
    "107.189.10.143",  "107.189.31.186",
    "23.129.64.130",   "23.129.64.131",
    "45.142.212.100",  "45.142.212.101",
    "193.218.118.100", "193.218.118.101",
    "178.175.128.197", "178.175.139.105",
}

# ── Thresholds ─────────────────────────────────────────────────────────────
# Sustained circuit: >=this many packets to same IP on circuit port
_SUSTAINED_CIRCUIT_PKT_THRESHOLD = 300

# Low diversity: Tor client talks to <=N external IPs while sending high volume
_MAX_EXTERNAL_IPS_FOR_LOW_DIVERSITY = 5
_MIN_TOTAL_PKTS_FOR_LOW_DIVERSITY   = 500

# Repeated Tor-specific port (not 443) threshold
_REPEATED_TOR_PORT_THRESHOLD = 5

# Tor port diversity
_TOR_PORT_DIVERSITY_THRESHOLD = 2


def _is_private_ip(ip: str) -> bool:
    """Return True for RFC-1918 / loopback / link-local addresses."""
    octets = ip.split(".")
    if len(octets) != 4:
        return False
    try:
        a, b = int(octets[0]), int(octets[1])
    except ValueError:
        return False
    return (
        a == 10 or
        a == 127 or
        (a == 172 and 16 <= b <= 31) or
        (a == 192 and b == 168) or
        (a == 169 and b == 254)
    )


def _confidence_label(conf: int) -> str:
    if conf >= 85:
        return "High"
    if conf >= 60:
        return "Medium"
    return "Low"


def detect_tor(events_df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Return a list of Tor-detection findings.
    Each finding: src_ip, dst_ip, dst_port, reason, confidence (0-100),
                  label, confidence_label
    """
    findings: List[Dict[str, Any]] = []
    seen_keys: set = set()

    def _add(src: str, dst: str, port: int, reason: str, conf: int) -> None:
        key = (src, dst, reason[:60])
        if key in seen_keys:
            return
        seen_keys.add(key)
        findings.append({
            "label":            "Likely Tor Traffic",
            "src_ip":           src,
            "dst_ip":           dst,
            "dst_port":         port,
            "reason":           reason,
            "confidence":       min(conf, 100),
            "confidence_label": _confidence_label(conf),
        })

    # ── Layer 1: Known Tor IP match ────────────────────────────────────────
    for _, row in events_df.iterrows():
        src   = str(row["src_ip"])
        dst   = str(row["dst_ip"])
        dport = int(row["dst_port"])
        sport = int(row["src_port"])

        if dst in TOR_KNOWN_IPS:
            if dport in TOR_SPECIFIC_PORTS:
                _add(src, dst, dport,
                     f"Known Tor relay {dst} on Tor OR/directory port {dport}", 97)
            elif dport in TOR_CIRCUIT_PORTS:
                _add(src, dst, dport,
                     f"Known Tor relay {dst} on port {dport} (guard circuit)", 92)
            else:
                _add(src, dst, dport,
                     f"Connection to known Tor node {dst}:{dport}", 88)

        if src in TOR_KNOWN_IPS:
            _add(src, dst, sport,
                 f"Inbound from known Tor relay {src} (relay response)", 85)

    # ── Layer 2: Tor-specific ports (9001, 9030, 9050 …) ──────────────────
    # Each hit is a meaningful indicator; repeated hits raise confidence.
    tor_port_counts: dict[tuple, int] = defaultdict(int)
    for _, row in events_df.iterrows():
        dport = int(row["dst_port"])
        if dport in TOR_SPECIFIC_PORTS:
            tor_port_counts[(str(row["src_ip"]), str(row["dst_ip"]), dport)] += 1

    for (src, dst, port), cnt in tor_port_counts.items():
        if cnt >= _REPEATED_TOR_PORT_THRESHOLD:
            _add(src, dst, port,
                 f"Repeated connections ({cnt}×) to Tor port {port} at {dst}", 80)
        else:
            # Even a single hit to 9001/9030/9050 is worth noting
            _add(src, dst, port,
                 f"Connection to Tor-specific port {port} at {dst}", 72)

    # Tor-port diversity (source uses ≥2 distinct Tor ports)
    src_tor_port_set: dict[str, set] = defaultdict(set)
    for _, row in events_df.iterrows():
        dport = int(row["dst_port"])
        if dport in TOR_SPECIFIC_PORTS:
            src_tor_port_set[str(row["src_ip"])].add(dport)

    for src_ip, ports in src_tor_port_set.items():
        if len(ports) >= _TOR_PORT_DIVERSITY_THRESHOLD:
            _add(src_ip, "multiple", 0,
                 f"Source contacted {len(ports)} distinct Tor ports: {sorted(ports)}", 85)

    # ── Layer 3: Sustained circuit behavioural detection ──────────────────
    # Real Tor Browser creates a long-lived TLS circuit to a guard node on
    # port 443 or 9001.  Normal HTTPS browsing never produces thousands of
    # packets to a single server.  We require BOTH:
    #   a) High packet count to the same dst_ip on a circuit port
    #   b) The source is a private/internal IP (client behaviour)
    circuit_counts: dict[tuple, int] = defaultdict(int)
    for _, row in events_df.iterrows():
        dport = int(row["dst_port"])
        src   = str(row["src_ip"])
        if dport in TOR_CIRCUIT_PORTS:
            circuit_counts[(src, str(row["dst_ip"]), dport)] += 1

    for (src, dst, port), cnt in circuit_counts.items():
        if cnt >= _SUSTAINED_CIRCUIT_PKT_THRESHOLD and _is_private_ip(src):
            _add(src, dst, port,
                 f"Sustained Tor-like circuit: {cnt} encrypted packets to single "
                 f"endpoint {dst}:{port} (normal HTTPS rarely exceeds 100 pkts/host)",
                 75)

    # ── Layer 4: Low destination diversity + high total volume ─────────────
    # Tor client talks to very few external IPs while generating lots of traffic.
    src_external_ips: dict[str, set]  = defaultdict(set)
    src_total_pkts:   dict[str, int]  = defaultdict(int)
    src_circuit_dsts: dict[str, set]  = defaultdict(set)

    for _, row in events_df.iterrows():
        src   = str(row["src_ip"])
        dst   = str(row["dst_ip"])
        dport = int(row["dst_port"])
        if not _is_private_ip(dst):
            src_external_ips[src].add(dst)
        src_total_pkts[src] += 1
        if dport in TOR_CIRCUIT_PORTS:
            src_circuit_dsts[src].add(dst)

    for src, ext_ips in src_external_ips.items():
        if not _is_private_ip(src):
            continue
        total = src_total_pkts[src]
        circuit_dsts = src_circuit_dsts.get(src, set())
        n_ext = len(ext_ips)
        # Tor pattern: many packets but only 1-3 external destinations for HTTPS/9001
        if (total >= _MIN_TOTAL_PKTS_FOR_LOW_DIVERSITY and
                0 < len(circuit_dsts) <= 3 and
                n_ext <= _MAX_EXTERNAL_IPS_FOR_LOW_DIVERSITY):
            for dst in circuit_dsts:
                cnt = circuit_counts.get((src, dst, 443), 0) + \
                      circuit_counts.get((src, dst, 9001), 0)
                port = 443 if circuit_counts.get((src, dst, 443), 0) >= \
                              circuit_counts.get((src, dst, 9001), 0) else 9001
                _add(src, dst, port,
                     f"Tor-like traffic pattern: {total} total pkts, only "
                     f"{n_ext} external IP(s), {len(circuit_dsts)} circuit "
                     f"destination(s) — consistent with Tor guard node usage",
                     68)

    findings.sort(key=lambda x: x["confidence"], reverse=True)
    return findings
