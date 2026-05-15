from __future__ import annotations

from pathlib import Path
import re
import pandas as pd

try:
    from scapy.all import rdpcap, IP, TCP, UDP, Raw
except Exception:
    rdpcap = None
    IP = TCP = UDP = Raw = None


import re as _re

_HTTP_CRED_FIELDS = {
    "username", "user", "uname", "email", "login", "account",
    "password", "passwd", "pass", "pwd", "secret", "token",
}

def _extract_http_from_payload(payload: str) -> dict:
    """Extract HTTP method, host, path, status, and credentials from a raw payload string."""
    result = {}
    try:
        lines = payload.split("\r\n")
        if not lines:
            return result
        first = lines[0]
        m = _re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (.+?) HTTP/", first)
        if m:
            result["http_method"] = m.group(1)
            result["http_path"]   = m.group(2)[:200]
        m2 = _re.match(r"^HTTP/[\d.]+ (\d{3})", first)
        if m2:
            result["http_status"] = m2.group(1)
        h = _re.search(r"\r\nHost:\s*([^\r\n]+)", payload, _re.IGNORECASE)
        if h:
            result["http_host"] = h.group(1).strip()[:200]
        # Credential extraction from POST body
        if result.get("http_method") == "POST":
            sep = payload.find("\r\n\r\n")
            if sep != -1:
                body = payload[sep + 4:].strip()
                ct_m = _re.search(r"Content-Type:\s*([^\r\n]+)", payload, _re.IGNORECASE)
                ct = ct_m.group(1).lower() if ct_m else ""
                if "urlencoded" in ct or "=" in body:
                    try:
                        from urllib.parse import parse_qs, unquote_plus
                        parsed = parse_qs(body, keep_blank_values=True)
                        creds = {}
                        for k, vs in parsed.items():
                            if k.lower().strip() in _HTTP_CRED_FIELDS and vs:
                                creds[k] = unquote_plus(vs[0])[:200]
                        if creds:
                            result["credentials"] = creds
                    except Exception:
                        pass
    except Exception:
        pass
    return result

_TCP_FLAG_BITS = {
    0x001: "FIN", 0x002: "SYN", 0x004: "RST",
    0x008: "PSH", 0x010: "ACK", 0x020: "URG",
}

def _flags_to_str(flags_int) -> str:
    """Convert integer TCP flags to a human-readable string like 'SYN ACK'."""
    if isinstance(flags_int, str):
        return flags_int  # already a string
    try:
        n = int(flags_int)
        return " ".join(name for bit, name in _TCP_FLAG_BITS.items() if n & bit) or ""
    except Exception:
        return ""


STANDARD_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "length", "payload", "event_type", "raw_line", "flags",
    "http_method", "http_host", "http_path", "http_status",
]

def _normalize(df: pd.DataFrame) -> pd.DataFrame:
    result = df.copy()
    for col in STANDARD_COLUMNS:
        if col not in result.columns:
            result[col] = None
    result["timestamp"] = pd.to_datetime(result["timestamp"], errors="coerce")
    result["src_port"] = pd.to_numeric(result["src_port"], errors="coerce").fillna(0).astype(int)
    result["dst_port"] = pd.to_numeric(result["dst_port"], errors="coerce").fillna(0).astype(int)
    result["length"] = pd.to_numeric(result["length"], errors="coerce").fillna(0).astype(int)
    result["protocol"] = result["protocol"].fillna("UNKNOWN").astype(str).str.upper()
    result["payload"] = result["payload"].fillna("").astype(str)
    result["event_type"] = result["event_type"].fillna("network_event").astype(str)
    result["raw_line"] = result["raw_line"].fillna("").astype(str)
    # FIX BUG-11: normalize flags to consistent string (was int from PCAP, 0 from CSV)
    if "flags" in result.columns:
        result["flags"] = result["flags"].apply(lambda x: _flags_to_str(x) if x is not None else "")
    else:
        result["flags"] = ""
    result["src_ip"] = result["src_ip"].fillna("unknown").astype(str)
    result["dst_ip"] = result["dst_ip"].fillna("unknown").astype(str)
    result = result.sort_values("timestamp", na_position="last").reset_index(drop=True)
    return result[STANDARD_COLUMNS]

def _parse_csv(path: Path) -> pd.DataFrame:
    rename_map = {
        # Standard internal format
        "time": "timestamp", "date": "timestamp",
        "source_ip": "src_ip", "destination_ip": "dst_ip",
        "source_port": "src_port", "destination_port": "dst_port",
        "proto": "protocol", "size": "length",
        "message": "payload", "data": "payload", "type": "event_type",
        # Wireshark CSV export column names
        "source": "src_ip", "destination": "dst_ip",
        "no.": "frame_no", "no": "frame_no",
        "info": "payload", "length": "length",
    }

    try:
        df = pd.read_csv(
            path,
            engine="python",
            quotechar='"',
            escapechar="\\",
            on_bad_lines="skip",
        )
    except Exception:
        df = pd.read_csv(
            path,
            engine="python",
            sep=None,
            quotechar='"',
            escapechar="\\",
            on_bad_lines="skip",
        )

    df = df.rename(columns={c: rename_map.get(str(c).lower().strip(), str(c).lower().strip()) for c in df.columns})

    # Wireshark "Source"/"Destination" columns may contain "IP:port" or just IP.
    # Try to split port from IP column when no separate port column exists.
    def _split_ip_port(series, port_col, df_cols):
        """If the IP column has 'ip:port' format, split it and fill port_col."""
        if port_col in df_cols:
            return series, None   # port column already exists
        has_colon = series.astype(str).str.contains(r":\d+$", regex=True)
        if has_colon.any():
            split_df = series.astype(str).str.rsplit(":", n=1, expand=True)
            return split_df[0], split_df[1]
        return series, None

    if "src_ip" in df.columns and "src_port" not in df.columns:
        df["src_ip"], extracted_sport = _split_ip_port(df["src_ip"], "src_port", df.columns)
        if extracted_sport is not None:
            df["src_port"] = extracted_sport

    if "dst_ip" in df.columns and "dst_port" not in df.columns:
        df["dst_ip"], extracted_dport = _split_ip_port(df["dst_ip"], "dst_port", df.columns)
        if extracted_dport is not None:
            df["dst_port"] = extracted_dport

    # Try to parse port info from the payload/info column (Wireshark-style)
    # e.g. Info: "51234 → 21 [SYN]" or "21 → 51234 [SYN, ACK]"
    if "payload" in df.columns and ("src_port" not in df.columns or "dst_port" not in df.columns):
        port_arrow_re = re.compile(r"(\d{1,5})\s*[→>]\s*(\d{1,5})")
        def _extract_ports_from_info(info_str):
            m = port_arrow_re.search(str(info_str))
            if m:
                return int(m.group(1)), int(m.group(2))
            return None, None

        if "src_port" not in df.columns or "dst_port" not in df.columns:
            ports_extracted = df["payload"].apply(_extract_ports_from_info)
            if "src_port" not in df.columns:
                df["src_port"] = ports_extracted.apply(lambda x: x[0])
            if "dst_port" not in df.columns:
                df["dst_port"] = ports_extracted.apply(lambda x: x[1])

    return _normalize(df)

def _parse_text_lines(path: Path) -> pd.DataFrame:
    rows = []
    line_re = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})?.*?'
        r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)?(?::(?P<src_port>\d+))?.*?'
        r'(->|to)?\s*'
        r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)?(?::(?P<dst_port>\d+))?.*?'
        r'(?P<protocol>TCP|UDP|HTTP|HTTPS|DNS|FTP|SSH|ICMP)?',
        re.IGNORECASE
    )
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            match = line_re.search(line)
            rows.append({
                "timestamp": match.group("timestamp") if match else None,
                "src_ip": match.group("src_ip") if match else None,
                "dst_ip": match.group("dst_ip") if match else None,
                "src_port": match.group("src_port") if match else None,
                "dst_port": match.group("dst_port") if match else None,
                "protocol": (match.group("protocol") if match else None) or "UNKNOWN",
                "length": len(line),
                "payload": line,
                "event_type": "log_event",
                "raw_line": line,
            })
    return _normalize(pd.DataFrame(rows))

def _parse_pcap(path: Path) -> pd.DataFrame:
    if rdpcap is None:
        raise RuntimeError("Scapy/libpcap is unavailable on this system. CSV/TXT/LOG still works.")
    packets = rdpcap(str(path))
    rows = []
    for packet in packets:
        if IP not in packet:
            continue
        proto = "IP"
        src_port = 0
        dst_port = 0
        payload = ""
        flags = 0
        if TCP and TCP in packet:
            proto = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            flags = int(packet[TCP].flags)  # integer bitmask: SYN=0x02, ACK=0x10, etc.
        elif UDP and UDP in packet:
            proto = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        if Raw and Raw in packet:
            try:
                payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")
            except Exception:
                payload = repr(bytes(packet[Raw].load)[:80])
        app_proto = proto
        if dst_port in [80, 8080] or src_port in [80, 8080]:
            app_proto = "HTTP"
        elif dst_port == 443 or src_port == 443:
            app_proto = "HTTPS"
        elif dst_port == 53 or src_port == 53:
            app_proto = "DNS"
        elif dst_port == 21 or src_port == 21:
            app_proto = "FTP"
        elif dst_port == 22 or src_port == 22:
            app_proto = "SSH"
        # FIX BUG-10: extract HTTP info including credentials from payload
        http_info = {}
        http_ports = {80, 8080, 8888, 8000, 3000, 5000}
        if (src_port in http_ports or dst_port in http_ports or
                payload[:4] in ("GET ", "POST", "PUT ", "DELE", "HEAD", "HTTP")):
            http_info = _extract_http_from_payload(payload)

        row = {
            "timestamp": pd.to_datetime(float(packet.time), unit="s", errors="coerce"),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": app_proto,
            "length": len(packet),
            "payload": payload,
            "event_type": "packet",
            "raw_line": payload[:250],
            "flags": flags,
        }
        row.update(http_info)
        rows.append(row)
    return _normalize(pd.DataFrame(rows))

def load_input_data(file_path: str, source_type: str = "auto") -> pd.DataFrame:
    path = Path(file_path)
    suffix = path.suffix.lower()
    mode = source_type.lower()
    if mode == "auto":
        if suffix in [".csv"]:
            mode = "csv"
        elif suffix in [".pcap", ".pcapng"]:
            mode = "pcap"
        else:
            mode = "text"
    if mode == "csv":
        return _parse_csv(path)
    if mode == "pcap":
        return _parse_pcap(path)
    return _parse_text_lines(path)
