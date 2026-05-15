"""
JA3-like TLS Fingerprinting (Simplified)
-----------------------------------------
Extracts TLS ClientHello metadata from Scapy-parsed packets and produces
a JA3-style fingerprint hash.

JA3 formula  (RFC-compliant):
  MD5( SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats )
  where each field is a '-'-joined decimal list.

When raw packet bytes aren't available (CSV/log input) the module falls back
to heuristic fingerprinting based on port, protocol and payload patterns.
"""
from __future__ import annotations

import hashlib
import struct
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

# ── TLS record / handshake constants ──────────────────────────────────────
_TLS_RECORD_HANDSHAKE  = 0x16
_TLS_HANDSHAKE_CHELLO  = 0x01

# Cipher suites that strongly suggest Tor's default TLS configuration
_TOR_CIPHERS: set[int] = {
    0xC02B, 0xC02F, 0xCC13, 0xCC14, 0xC00A, 0xC009,
    0xC013, 0xC014, 0x002F, 0x0035,
}

# Grease values to strip (per RFC 8701)
_GREASE: set[int] = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
    0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# Known suspicious / anonymiser fingerprints (md5 → label)
_KNOWN_FINGERPRINTS: Dict[str, str] = {
    "e7d705a3286e19ea42f587b344ee6865": "Tor Browser (Firefox-based)",
    "a0e9f5d64349fb13191bc781f81f42e1": "Curl / automation tool",
    "37f463bf4616ecd445d4a1937da06e19": "Python requests",
    "b32309a26951912be7dba376398d2d3f": "OpenSSL s_client",
}

# ── Low-level TLS parser ──────────────────────────────────────────────────

def _read_uint8(data: bytes, offset: int) -> Tuple[int, int]:
    return data[offset], offset + 1

def _read_uint16(data: bytes, offset: int) -> Tuple[int, int]:
    return struct.unpack_from(">H", data, offset)[0], offset + 2

def _read_uint24(data: bytes, offset: int) -> Tuple[int, int]:
    hi, offset = _read_uint8(data, offset)
    lo, offset = _read_uint16(data, offset)
    return (hi << 16) | lo, offset


def _parse_client_hello(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Attempt to parse a TLS ClientHello from raw bytes.
    Returns None if the bytes are not a valid ClientHello.
    """
    try:
        if len(data) < 6:
            return None
        record_type = data[0]
        if record_type != _TLS_RECORD_HANDSHAKE:
            return None
        # TLS record version (2 bytes), length (2 bytes)
        record_len = struct.unpack_from(">H", data, 3)[0]
        if len(data) < 5 + record_len:
            return None
        payload = data[5 : 5 + record_len]
        if payload[0] != _TLS_HANDSHAKE_CHELLO:
            return None
        msg_len, pos = _read_uint24(payload, 1)
        if len(payload) < 4 + msg_len:
            return None
        msg = payload[4 : 4 + msg_len]
        # Client hello version
        ssl_version, pos = _read_uint16(msg, 0)
        pos += 32                      # skip random (32 bytes)
        session_len, pos = _read_uint8(msg, pos)
        pos += session_len             # skip session id
        # Cipher suites
        cs_len, pos = _read_uint16(msg, pos)
        ciphers = []
        for _ in range(cs_len // 2):
            cs, pos = _read_uint16(msg, pos)
            if cs not in _GREASE:
                ciphers.append(cs)
        # Compression methods
        comp_len, pos = _read_uint8(msg, pos)
        pos += comp_len
        # Extensions
        extensions: List[int] = []
        elliptic_curves: List[int] = []
        ec_formats: List[int] = []
        if pos + 2 <= len(msg):
            ext_total_len, pos = _read_uint16(msg, pos)
            ext_end = pos + ext_total_len
            while pos + 4 <= ext_end:
                ext_type, pos = _read_uint16(msg, pos)
                ext_len,  pos = _read_uint16(msg, pos)
                ext_data = msg[pos : pos + ext_len]
                pos += ext_len
                if ext_type not in _GREASE:
                    extensions.append(ext_type)
                if ext_type == 0x000A and len(ext_data) >= 4:  # supported_groups
                    grp_len = struct.unpack_from(">H", ext_data, 0)[0]
                    for i in range(2, 2 + grp_len, 2):
                        if i + 2 <= len(ext_data):
                            grp = struct.unpack_from(">H", ext_data, i)[0]
                            if grp not in _GREASE:
                                elliptic_curves.append(grp)
                elif ext_type == 0x000B and len(ext_data) >= 1:  # ec_point_formats
                    fmt_cnt = ext_data[0]
                    for i in range(1, 1 + fmt_cnt):
                        if i < len(ext_data):
                            ec_formats.append(ext_data[i])
        return {
            "ssl_version":     ssl_version,
            "ciphers":         ciphers,
            "extensions":      extensions,
            "elliptic_curves": elliptic_curves,
            "ec_formats":      ec_formats,
        }
    except Exception:
        return None


def _make_ja3(parsed: Dict[str, Any]) -> str:
    """Compute JA3 string and its MD5 hash."""
    fields = [
        str(parsed["ssl_version"]),
        "-".join(map(str, parsed["ciphers"])),
        "-".join(map(str, parsed["extensions"])),
        "-".join(map(str, parsed["elliptic_curves"])),
        "-".join(map(str, parsed["ec_formats"])),
    ]
    ja3_str = ",".join(fields)
    return hashlib.md5(ja3_str.encode()).hexdigest()


def _heuristic_fingerprint(src_ip: str, dst_port: int, protocol: str,
                            payload: str) -> str:
    """Stable pseudo-fingerprint when raw bytes aren't available."""
    raw = f"{src_ip}|{dst_port}|{protocol}|{payload[:64]}"
    return hashlib.md5(raw.encode()).hexdigest()


def _classify(fp: str, ciphers: Optional[List[int]]) -> str:
    if fp in _KNOWN_FINGERPRINTS:
        return f"Suspicious – {_KNOWN_FINGERPRINTS[fp]}"
    if ciphers is not None:
        tor_overlap = len(set(ciphers) & _TOR_CIPHERS)
        if tor_overlap >= 3:
            return "Tor-like / anonymized client"
        if tor_overlap >= 1:
            return "Suspicious – unusual cipher set"
    return "Normal"


# ── Public API ─────────────────────────────────────────────────────────────

def fingerprint_tls(events_df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Analyse the DataFrame for TLS traffic and return per-source fingerprint records.
    """
    results: List[Dict[str, Any]] = []
    # Group TLS/HTTPS rows by source IP for aggregation
    tls_mask = (
        (events_df["dst_port"].isin([443, 8443, 9001, 9150])) |
        (events_df["protocol"].isin(["HTTPS", "TLS"]))
    )
    tls_df = events_df[tls_mask].copy()
    if tls_df.empty:
        return results

    seen: set = set()
    per_src: dict = defaultdict(list)

    for _, row in tls_df.iterrows():
        src      = str(row["src_ip"])
        dst      = str(row["dst_ip"])
        dport    = int(row["dst_port"])
        payload  = str(row.get("payload", ""))
        protocol = str(row.get("protocol", ""))

        # Try to parse actual TLS ClientHello from payload bytes
        parsed = None
        try:
            raw_bytes = payload.encode("latin-1")
            parsed = _parse_client_hello(raw_bytes)
        except Exception:
            pass

        if parsed:
            fp   = _make_ja3(parsed)
            cls  = _classify(fp, parsed["ciphers"])
            ciphers_info = [hex(c) for c in parsed["ciphers"][:8]]
        else:
            fp   = _heuristic_fingerprint(src, dport, protocol, payload)
            cls  = _classify(fp, None)
            ciphers_info = []

        key = (src, fp)
        if key not in seen:
            seen.add(key)
            per_src[src].append({
                "src_ip":         src,
                "dst_ip":         dst,
                "dst_port":       dport,
                "ja3_fingerprint": fp,
                "classification": cls,
                "ciphers_sample": ciphers_info,
                "parsed":         parsed is not None,
            })

    for src_ip, entries in per_src.items():
        # Summarise repeated or suspicious behaviour
        suspicious_count = sum(1 for e in entries if e["classification"] != "Normal")
        for entry in entries:
            entry["repeated_suspicious"] = suspicious_count > 1
        results.extend(entries)

    results.sort(key=lambda x: (x["classification"] != "Normal", x["classification"]), reverse=True)
    return results
