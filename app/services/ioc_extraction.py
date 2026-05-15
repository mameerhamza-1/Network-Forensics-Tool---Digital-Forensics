from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter
from typing import Any, Dict, List
from urllib.parse import urlparse

import pandas as pd

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:[A-Za-z]{2,24})\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
UA_RE = re.compile(r"User-Agent:\s*([^\r\n]+)", re.IGNORECASE)
SUSPICIOUS_RE = re.compile(
    r"(\.\./|%2e%2e|union\s+select|<script|cmd=|shell=|/bin/sh|powershell|mimikatz|passwd|password=|token=)",
    re.IGNORECASE,
)

PRIVATE_HOSTS = {"localhost", "localdomain"}


def _valid_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


def _clean_domain(domain: str) -> str:
    return domain.lower().strip(". ,;:()[]{}<>\"'")


def _hash_type(value: str) -> str:
    l = len(value)
    if l == 32:
        return "md5"
    if l == 40:
        return "sha1"
    if l == 64:
        return "sha256"
    return "unknown"


def extract_iocs(events_df: pd.DataFrame, source_path: str | None = None, include_private_ips: bool = True) -> Dict[str, Any]:
    """Extract network and content indicators from normalized forensic events."""
    ip_counter: Counter[str] = Counter()
    domain_counter: Counter[str] = Counter()
    url_counter: Counter[str] = Counter()
    hash_counter: Counter[str] = Counter()
    email_counter: Counter[str] = Counter()
    ua_counter: Counter[str] = Counter()
    suspicious_payloads: List[Dict[str, Any]] = []

    text_columns = [c for c in ["payload", "raw_line", "http_host", "http_path"] if c in events_df.columns]

    for _, row in events_df.iterrows():
        for col in ["src_ip", "dst_ip"]:
            ip = str(row.get(col, "")).strip()
            if ip and ip != "unknown" and (include_private_ips or _valid_public_ip(ip)):
                ip_counter[ip] += 1

        combined = " ".join(str(row.get(c, "")) for c in text_columns if str(row.get(c, "")))
        for ip in IP_RE.findall(combined):
            if include_private_ips or _valid_public_ip(ip):
                ip_counter[ip] += 1
        for url in URL_RE.findall(combined):
            clean = url.rstrip(".,;)']}")
            url_counter[clean] += 1
            host = urlparse(clean).hostname
            if host:
                domain_counter[_clean_domain(host)] += 1
        for dom in DOMAIN_RE.findall(combined):
            dom = _clean_domain(dom)
            if dom not in PRIVATE_HOSTS and not IP_RE.fullmatch(dom):
                domain_counter[dom] += 1
        for h in HASH_RE.findall(combined):
            hash_counter[h.lower()] += 1
        for email in EMAIL_RE.findall(combined):
            email_counter[email.lower()] += 1
        for ua in UA_RE.findall(combined):
            ua_counter[ua.strip()[:180]] += 1
        if SUSPICIOUS_RE.search(combined):
            suspicious_payloads.append({
                "src_ip": str(row.get("src_ip", "unknown")),
                "dst_ip": str(row.get("dst_ip", "unknown")),
                "timestamp": str(row.get("timestamp", "")),
                "excerpt": combined[:300],
            })

    if source_path:
        try:
            with open(source_path, "rb") as handle:
                blob = handle.read()
            hash_counter[hashlib.sha256(blob).hexdigest()] += 1
            hash_counter[hashlib.md5(blob).hexdigest()] += 1
        except Exception:
            pass

    hashes = [{"value": h, "type": _hash_type(h), "count": c} for h, c in hash_counter.most_common()]
    return {
        "ips": [{"value": v, "count": c, "public": _valid_public_ip(v)} for v, c in ip_counter.most_common()],
        "domains": [{"value": v, "count": c} for v, c in domain_counter.most_common()],
        "urls": [{"value": v, "count": c} for v, c in url_counter.most_common()],
        "hashes": hashes,
        "emails": [{"value": v, "count": c} for v, c in email_counter.most_common()],
        "user_agents": [{"value": v, "count": c} for v, c in ua_counter.most_common()],
        "suspicious_payloads": suspicious_payloads[:50],
        "summary": {
            "ip_count": len(ip_counter),
            "domain_count": len(domain_counter),
            "url_count": len(url_counter),
            "hash_count": len(hash_counter),
            "email_count": len(email_counter),
            "suspicious_payload_count": len(suspicious_payloads),
        },
    }
