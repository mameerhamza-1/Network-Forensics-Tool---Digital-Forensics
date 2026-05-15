
from __future__ import annotations

import re
from typing import Any, Dict
from urllib.parse import unquote_plus, parse_qs

import pandas as pd

# Field names that indicate credential data in form-encoded POST bodies
_CRED_FIELD_PATTERNS = re.compile(
    r'\b(user(name)?|email|login|pass(word)?|passwd|pwd|credential|token|secret)\b',
    re.IGNORECASE
)

# HTTP POST login-path patterns
_LOGIN_PATH_PATTERN = re.compile(
    r'POST\s+/[^\s]*?(login|signin|auth|session|account|user)[^\s]*',
    re.IGNORECASE
)


def _extract_credentials_from_payload(payload: str) -> dict | None:
    """
    Parse an HTTP payload for credential fields.
    Handles application/x-www-form-urlencoded POST bodies.
    Returns a dict of {field: value} or None if no credentials found.
    """
    if not payload:
        return None

    # Try to find the POST body (after double CRLF or double newline)
    body = None
    for sep in ["\r\n\r\n", "\n\n"]:
        if sep in payload:
            body = payload.split(sep, 1)[1].strip()
            break

    # If no header/body separator, treat the whole thing as body if it looks form-encoded
    if body is None:
        if "=" in payload and ("&" in payload or _CRED_FIELD_PATTERNS.search(payload)):
            body = payload.strip()

    if not body:
        return None

    # URL-decode the body
    try:
        decoded_body = unquote_plus(body)
    except Exception:
        decoded_body = body

    # Parse as form fields
    try:
        fields = parse_qs(decoded_body, keep_blank_values=True)
    except Exception:
        return None

    # Collect credential-related fields
    creds = {}
    for key, values in fields.items():
        if _CRED_FIELD_PATTERNS.search(key):
            creds[key] = values[0] if values else ""

    return creds if creds else None


def build_protocol_analysis(events_df: pd.DataFrame) -> Dict[str, Any]:
    protocol_counts = (
        events_df.groupby("protocol").size().reset_index(name="count").sort_values("count", ascending=False)
    )
    top_ports = (
        events_df.groupby("dst_port").size().reset_index(name="count").sort_values("count", ascending=False).head(10)
    )
    top_talkers = (
        events_df.groupby("src_ip").size().reset_index(name="count").sort_values("count", ascending=False).head(10)
    )

    credential_hits = []
    seen_payloads = set()

    for _, row in events_df.iterrows():
        payload = str(row.get("payload", ""))
        if not payload:
            continue

        lower = payload.lower()

        # Quick pre-filter: must contain a credential indicator
        has_cred_token = any(tok in lower for tok in [
            "password=", "passwd=", "pwd=", "username=", "user=", "email=",
            "login=", "authorization: basic", "token=", "credential"
        ])
        # Also check if it's an HTTP POST to a login-related endpoint
        is_login_post = bool(_LOGIN_PATH_PATTERN.search(payload))

        if not (has_cred_token or is_login_post):
            continue

        # Attempt structured extraction
        creds = _extract_credentials_from_payload(payload)

        if creds:
            # Build a readable excerpt showing extracted fields
            cred_summary = " | ".join(f"{k}={v}" for k, v in creds.items())
            # Deduplicate by payload fingerprint
            fp = (row["src_ip"], row["dst_ip"], cred_summary)
            if fp in seen_payloads:
                continue
            seen_payloads.add(fp)

            credential_hits.append({
                "timestamp": row["timestamp"],
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "method": "POST",
                "credentials": creds,
                "payload_excerpt": cred_summary[:300],
            })
        elif has_cred_token:
            # Fallback: show the raw HTTP line that triggered the match (header or first body line)
            lines = [l for l in payload.splitlines() if any(
                tok in l.lower() for tok in ["password=", "username=", "authorization:"]
            )]
            excerpt = lines[0][:300] if lines else payload[:300]
            fp = (row["src_ip"], row["dst_ip"], excerpt[:80])
            if fp in seen_payloads:
                continue
            seen_payloads.add(fp)
            credential_hits.append({
                "timestamp": row["timestamp"],
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "method": "HTTP",
                "credentials": {},
                "payload_excerpt": excerpt,
            })

    return {
        "protocol_counts": protocol_counts.to_dict(orient="records"),
        "top_ports": top_ports.to_dict(orient="records"),
        "top_talkers": top_talkers.to_dict(orient="records"),
        "credential_hits": credential_hits,
    }
