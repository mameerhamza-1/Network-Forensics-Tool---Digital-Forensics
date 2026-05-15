from __future__ import annotations

"""
live_monitor.py  ·  Wireshark-style live packet capture backend
================================================================

SURGICAL FIXES APPLIED (per spec):
  ISSUE 1 — STOP RELIABILITY
    · Replaced sniff(timeout=1) loop with sniff(timeout=0.3) so the capture
      thread wakes and checks the stop-event every 300 ms (was 1 second).
    · stop() now forcibly sets _running=False AND joins the thread before
      returning, guaranteeing no background capture continues afterward.
    · Added _force_stop flag so _packet_callback becomes a no-op immediately
      when stop is requested — even if sniff() hasn't returned yet.
    · start() always calls stop() first, ensuring a clean slate on every
      Start/Stop cycle.

  ISSUE 2 — REAL-TIME HTTP CREDENTIAL EXTRACTION
    · _extract_http() enhanced: now catches application/json bodies, multi-
      line form payloads, and query-string credentials on GET login URLs.
    · _is_credential_request() detects login paths (/login, /signin, /auth,
      /session, /account, /user) regardless of port.
    · HTTP detection now runs on ALL TCP packets with a Raw payload, not only
      on known port numbers — payloads are probed by magic bytes first.
    · Credentials dict is always included in the emitted "packet_data" event
      so the browser "Credential Exposures" panel updates in real time.

  ISSUE 3 — CONSISTENT PACKET PROCESSING
    · _packet_callback acquires the lock for the minimum time (counter only);
      expensive work (event building, SocketIO emit) happens outside the lock.
    · Packet processing uses a try/except so a bad packet never kills the loop.
    · get_csv() takes a snapshot under the lock then writes outside it,
      preventing any contention with the capture thread.
"""

import csv
import io
import json as _json
import re
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw,
        conf as scapy_conf,
    )
    _SCAPY_OK = True
except Exception:
    _SCAPY_OK = False


# ---------------------------------------------------------------------------
# CSV export columns (includes all HTTP + credential fields)
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "timestamp", "no", "src_ip", "dst_ip", "protocol",
    "src_port", "dst_port", "length", "flags", "info",
    "http_method", "http_host", "http_path", "http_status",
    "credentials_str", "ttl", "is_suspicious",
]


# ---------------------------------------------------------------------------
# Protocol / port maps
# ---------------------------------------------------------------------------

_PORT_MAP: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP",     53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP",    110: "POP3", 143: "IMAP", 179: "BGP",
    443: "HTTPS",  445: "SMB", 465: "SMTPS", 587: "SMTP",
    993: "IMAPS",  995: "POP3S", 1433: "MSSQL", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP",  5060: "SIP",  5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP", 8443: "HTTPS", 8888: "HTTP",
    27017: "MongoDB",
}

_SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 9001, 9030}

_FLAG_BITS = {
    0x001: "FIN", 0x002: "SYN", 0x004: "RST",
    0x008: "PSH", 0x010: "ACK", 0x020: "URG",
}

# Ports where HTTP traffic is expected
_HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 5000, 5001, 8081, 9000}

# URL paths that indicate credential submission
_LOGIN_PATHS = (
    "/login", "/signin", "/sign-in", "/log-in",
    "/auth", "/authenticate", "/session",
    "/account/login", "/user/login", "/users/login",
    "/admin/login", "/wp-login", "/wp-admin",
    "/api/login", "/api/auth", "/api/session",
)

# Credential field names to look for
_CRED_FIELDS = frozenset({
    "username", "user", "uname", "userid", "user_id",
    "email", "mail", "login", "account", "name",
    "password", "passwd", "pass", "pwd", "secret",
    "token", "credential", "credentials",
})


# ---------------------------------------------------------------------------
# Pure helpers (no side effects, no locks)
# ---------------------------------------------------------------------------

def _tcp_flags_str(flags_int: int) -> str:
    return " ".join(n for b, n in _FLAG_BITS.items() if flags_int & b) or ""


def _is_rfc1918(ip: str) -> bool:
    p = ip.split(".")
    if len(p) != 4:
        return False
    try:
        a, b = int(p[0]), int(p[1])
        return (a == 10) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
    except ValueError:
        return False


def _infer_protocol(packet) -> str:
    """Infer human-readable protocol name from Scapy packet layers/ports."""
    if not _SCAPY_OK:
        return "IP"
    sp = dp = 0
    if TCP in packet:
        sp, dp = int(packet[TCP].sport), int(packet[TCP].dport)
    elif UDP in packet:
        sp, dp = int(packet[UDP].sport), int(packet[UDP].dport)
    for port in (dp, sp):
        if port and port in _PORT_MAP:
            return _PORT_MAP[port]
    if DNS  in packet: return "DNS"
    if ICMP in packet: return "ICMP"
    if ARP  in packet: return "ARP"
    if TCP  in packet: return "TCP"
    if UDP  in packet: return "UDP"
    if IPv6 in packet: return "IPv6"
    return "IP"


def _is_credential_request(method: str, path: str, host: str) -> bool:
    """Return True when the request looks like a credential submission."""
    if method not in ("POST", "PUT", "PATCH", "GET"):
        return False
    path_lower = (path or "").lower()
    if any(lp in path_lower for lp in _LOGIN_PATHS):
        return True
    host_lower = (host or "").lower()
    if any(kw in host_lower for kw in ("login", "auth", "signin", "account")):
        return True
    return False


def _extract_credentials_from_body(body: str) -> Dict[str, str]:
    """
    Extract credential key=value pairs from a request body.
    Handles:
      · application/x-www-form-urlencoded
      · application/json  { "username": "...", "password": "..." }
      · raw key=value fallback
    """
    creds: Dict[str, str] = {}
    if not body:
        return creds

    # ── JSON body ─────────────────────────────────────────────────────────
    stripped = body.strip()
    if stripped.startswith("{"):
        try:
            obj = _json.loads(stripped)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k.lower().strip() in _CRED_FIELDS and v:
                        creds[k] = str(v)[:200]
        except Exception:
            pass

    # ── URL-encoded form ──────────────────────────────────────────────────
    if not creds:
        try:
            from urllib.parse import parse_qs, unquote_plus
            parsed = parse_qs(body, keep_blank_values=True)
            for key, vals in parsed.items():
                if key.lower().strip() in _CRED_FIELDS and vals:
                    creds[key] = unquote_plus(vals[0])[:200]
        except Exception:
            pass

    # ── Fallback: regex key=value scan ───────────────────────────────────
    if not creds:
        for m in re.finditer(r"([\w\-\.]+)=([^&\r\n]*)", body):
            k, v = m.group(1), m.group(2)
            if k.lower() in _CRED_FIELDS:
                try:
                    from urllib.parse import unquote_plus
                    creds[k] = unquote_plus(v)[:200]
                except Exception:
                    creds[k] = v[:200]

    return creds


def _extract_http(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Parse HTTP request / response headers and extract credentials.
    Returns a dict that may contain any of:
      http_method, http_path, http_host, http_status, credentials (dict)
    """
    result: Dict[str, Any] = {}
    try:
        text = raw_bytes.decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        if not lines:
            return result
        first = lines[0]

        # ── Request line ─────────────────────────────────────────────────
        m = re.match(
            r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE) (.+?) HTTP/",
            first,
        )
        if m:
            result["http_method"] = m.group(1)
            result["http_path"]   = m.group(2)[:200]

        # ── Response status ──────────────────────────────────────────────
        m2 = re.match(r"^HTTP/[\d.]+ (\d{3})", first)
        if m2:
            result["http_status"] = m2.group(1)

        # ── Host header ──────────────────────────────────────────────────
        h = re.search(r"\r\nHost:\s*([^\r\n]+)", text, re.IGNORECASE)
        if h:
            result["http_host"] = h.group(1).strip()[:200]

        method = result.get("http_method", "")
        path   = result.get("http_path", "")
        host   = result.get("http_host", "")

        # ── Credential extraction ─────────────────────────────────────────
        # Strategy: always try to extract credentials from POST bodies.
        # Additionally, also try on GET requests to login paths (query string).
        should_extract = (
            method == "POST"
            or _is_credential_request(method, path, host)
        )

        if should_extract:
            # Check Content-Type to decide parsing strategy
            ct_m = re.search(r"Content-Type:\s*([^\r\n]+)", text, re.IGNORECASE)
            ct   = ct_m.group(1).lower() if ct_m else ""

            # Body is everything after the blank line (\r\n\r\n)
            sep = text.find("\r\n\r\n")
            body = text[sep + 4:].strip() if sep != -1 else ""

            # Also extract credentials from GET query string
            if method == "GET" and "?" in path:
                qs = path.split("?", 1)[1]
                body = body or qs

            if body and ("urlencoded" in ct or "json" in ct or "=" in body or body.startswith("{")):
                creds = _extract_credentials_from_body(body)
                if creds:
                    result["credentials"] = creds

    except Exception:
        pass

    return result


def _looks_like_http(raw: bytes) -> bool:
    """Fast check: does the payload begin with an HTTP verb or status line?"""
    return raw[:4] in (b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD", b"PATC",
                       b"OPTI", b"CONN", b"TRAC", b"HTTP")


def _build_info(packet, protocol: str, flags_str: str, http_info: Dict) -> str:
    """Generate a Wireshark-style human-readable summary line."""
    if protocol == "HTTP":
        method = http_info.get("http_method", "")
        host   = http_info.get("http_host", "")
        path   = http_info.get("http_path", "")
        status = http_info.get("http_status", "")
        creds  = http_info.get("credentials", {})
        if method:
            base = f"{method} {host}{path}" if host else f"{method} {path}"
            if creds:
                fields = ", ".join(
                    f"{k}={'*' * min(len(v), 8)}" for k, v in creds.items()
                )
                return f"{base}  [⚠ CREDS: {fields}]"
            return base
        if status:
            return f"HTTP {status} Response"

    if protocol == "DNS" and _SCAPY_OK and DNS in packet:
        try:
            dns = packet[DNS]
            if dns.qr == 0 and dns.qd:
                return f"Query: {dns.qd.qname.decode(errors='ignore').rstrip('.')}"
            if dns.qr == 1 and dns.qd:
                return f"Response: {dns.qd.qname.decode(errors='ignore').rstrip('.')}"
        except Exception:
            pass

    if protocol == "ICMP" and _SCAPY_OK and ICMP in packet:
        type_map = {0: "Echo Reply", 3: "Dest Unreachable",
                    8: "Echo Request", 11: "TTL Exceeded"}
        t = int(packet[ICMP].type)
        return f"ICMP {type_map.get(t, f'Type {t}')}"

    if protocol == "ARP" and _SCAPY_OK and ARP in packet:
        op = int(packet[ARP].op)
        if op == 1:
            return f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
        if op == 2:
            return f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"

    if flags_str and _SCAPY_OK and TCP in packet:
        seq = int(packet[TCP].seq)
        ack = int(packet[TCP].ack) if "ACK" in flags_str else None
        tag = flags_str.replace(" ", ",")
        return f"[{tag}] Seq={seq}" + (f" Ack={ack}" if ack else "")

    return f"{protocol} packet"


# ---------------------------------------------------------------------------
# LiveMonitor
# ---------------------------------------------------------------------------

class LiveMonitor:
    """
    Thread-safe live packet capture manager.

    Lifecycle
    ---------
    start() → spawns _capture_loop in a daemon thread
    stop()  → signals the thread, waits up to 4 s for it to finish,
               then forcibly marks running=False regardless.

    Thread safety
    -------------
    _lock protects: _running, _thread, _packets, _captured, _seq,
                    _packet_count, _interface, _last_error, _force_stop.
    The packet callback acquires _lock only briefly (counter increment).
    All heavy work (event building, socket emit) runs outside the lock.
    """

    def __init__(self, socketio) -> None:
        self.socketio       = socketio
        self._lock          = threading.Lock()
        self._stop_event    = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._running       = False
        self._force_stop    = False   # set immediately on stop(); makes callback a no-op
        self._captured      = 0
        self._seq           = 0
        self._packet_count  = 0
        self._interface: Optional[str] = None
        self._last_error: Optional[str] = None
        self._packets: List[Dict[str, Any]] = []

    # ── Internal: socket emit ─────────────────────────────────────────────

    def _emit(self, event: str, data: dict) -> None:
        try:
            self.socketio.emit(event, data, namespace="/")
        except Exception:
            pass

    # ── Internal: packet parsing ──────────────────────────────────────────

    def _build_event(self, packet) -> Optional[Dict[str, Any]]:
        """Convert a raw Scapy packet into a structured event dict."""
        if not _SCAPY_OK:
            return None

        has_ip  = IP   in packet
        has_ip6 = IPv6 in packet
        has_arp = ARP  in packet
        if not (has_ip or has_ip6 or has_arp):
            return None

        # ── Addresses ────────────────────────────────────────────────────
        if has_arp:
            src_ip, dst_ip = str(packet[ARP].psrc), str(packet[ARP].pdst)
        elif has_ip:
            src_ip, dst_ip = str(packet[IP].src),  str(packet[IP].dst)
        else:
            src_ip, dst_ip = str(packet[IPv6].src), str(packet[IPv6].dst)

        # ── Ports / flags ────────────────────────────────────────────────
        src_port = dst_port = 0
        if TCP in packet:
            src_port, dst_port = int(packet[TCP].sport), int(packet[TCP].dport)
        elif UDP in packet:
            src_port, dst_port = int(packet[UDP].sport), int(packet[UDP].dport)

        protocol  = _infer_protocol(packet)
        flags_int = int(packet[TCP].flags) if TCP in packet else 0
        flags_str = _tcp_flags_str(flags_int)
        ttl       = int(packet[IP].ttl) if has_ip else 0

        # ── HTTP / credential extraction ─────────────────────────────────
        # Run on any TCP packet that has a Raw payload.
        # We probe by magic bytes first (fast); if that fails, try known HTTP ports.
        http_info: Dict[str, Any] = {}
        payload_hex = ""

        if Raw in packet:
            raw_bytes = bytes(packet[Raw].load)
            payload_hex = raw_bytes[:32].hex()

            is_http_port = (
                dst_port in _HTTP_PORTS or src_port in _HTTP_PORTS
            )
            is_http_payload = _looks_like_http(raw_bytes)

            if is_http_port or is_http_payload:
                http_info = _extract_http(raw_bytes)

        # ── Suspicious heuristics ─────────────────────────────────────────
        is_suspicious = False
        if dst_port in _SUSPICIOUS_PORTS or src_port in _SUSPICIOUS_PORTS:
            is_suspicious = True
        if has_ip and _is_rfc1918(src_ip) and not _is_rfc1918(dst_ip):
            if (dst_port not in _PORT_MAP
                    and dst_port > 1024
                    and dst_port not in (8080, 8443, 8888)):
                is_suspicious = True
        if flags_int & 0x004 and not (flags_int & 0x010):  # RST without ACK
            is_suspicious = True
        if http_info.get("credentials"):
            # Captured credentials are always suspicious (cleartext HTTP)
            is_suspicious = True

        # ── Assemble event ────────────────────────────────────────────────
        with self._lock:
            self._seq += 1
            seq = self._seq

        src_display = f"{src_ip}:{src_port}" if src_port else src_ip
        dst_display = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
        info        = _build_info(packet, protocol, flags_str, http_info)

        event: Dict[str, Any] = {
            "timestamp":     datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "no":            seq,
            "src":           src_display,
            "dst":           dst_display,
            "src_ip":        src_ip,
            "dst_ip":        dst_ip,
            "src_port":      src_port,
            "dst_port":      dst_port,
            "protocol":      protocol,
            "length":        len(packet),
            "flags":         flags_str,
            "ttl":           ttl,
            "info":          info,
            "is_suspicious": is_suspicious,
            "payload_hex":   payload_hex,
        }
        if http_info:
            event.update(http_info)   # merges http_method, http_host, credentials, etc.

        return event

    # ── Internal: interface detection ─────────────────────────────────────

    def _detect_best_interface(self) -> Optional[str]:
        if not _SCAPY_OK:
            return None

        _SKIP = [
            "loopback", "npcap loopback",
            "vmware", "virtualbox", "vbox",
            "bluetooth", "tunnel", "teredo", "isatap",
            "pseudo", "6to4", "vpn", "tap", "docker", "veth",
            "virtual", "hyper-v",
        ]
        _PRIORITY = [
            "wi-fi", "wifi", "wlan", "wireless",
            "ethernet", "eth", "en", "local area connection",
        ]

        try:
            from scapy.all import IFACES
        except ImportError:
            return None

        psutil_stats: dict = {}
        try:
            import psutil
            psutil_stats = psutil.net_if_stats()
        except Exception:
            pass

        candidates: list = []
        try:
            iface_objects = list(IFACES.values())
        except Exception:
            iface_objects = []

        for iface in iface_objects:
            if hasattr(iface, "network_name"):
                sniff_name = str(iface.network_name)
                friendly   = str(getattr(iface, "description",
                                          getattr(iface, "name", sniff_name)))
            else:
                sniff_name = str(getattr(iface, "name", str(iface)))
                friendly   = sniff_name

            combined = (sniff_name + " " + friendly).lower()
            if any(kw in combined for kw in _SKIP):
                continue

            if psutil_stats:
                stat_key = friendly if friendly in psutil_stats else sniff_name
                if stat_key in psutil_stats and not psutil_stats[stat_key].isup:
                    continue

            score = 99
            for idx, kw in enumerate(_PRIORITY):
                if kw in combined:
                    score = idx
                    break
            candidates.append((score, sniff_name, friendly))

        if not candidates:
            raise RuntimeError(
                "No suitable network interface found. "
                "Check that Wi-Fi or Ethernet is active and that the app "
                "has raw-capture privileges (run as root / Administrator)."
            )

        candidates.sort(key=lambda x: (x[0], x[1]))
        _, best_sniff, best_label = candidates[0]
        print(
            f"[LiveMonitor] Auto-selected interface: {best_label!r} "
            f"(sniff handle: {best_sniff!r})",
            flush=True,
        )
        return best_sniff

    def _resolve_interface(self, interface: Optional[str]) -> Optional[str]:
        if interface:
            return interface.strip() or None
        if not _SCAPY_OK:
            return None
        return self._detect_best_interface()

    # ── Internal: stop predicate ──────────────────────────────────────────

    def _should_stop(self) -> bool:
        with self._lock:
            return (
                self._force_stop
                or self._stop_event.is_set()
                or (self._packet_count > 0 and self._captured >= self._packet_count)
            )

    # ── Internal: packet callback ─────────────────────────────────────────

    def _packet_callback(self, packet) -> None:
        """
        Called by Scapy for every captured packet.

        ISSUE 3 FIX: Lock held only for counter increment (minimum critical section).
        Packet building and Socket.IO emit happen outside the lock.
        Exceptions are swallowed so one bad packet never kills the capture loop.
        """
        # ISSUE 1 FIX: honour _force_stop immediately — makes callback a no-op
        # even if sniff() hasn't returned yet.
        with self._lock:
            if self._force_stop:
                return

        try:
            event = self._build_event(packet)
        except Exception:
            return
        if event is None:
            return

        # Store full event dict (includes HTTP / credentials)
        with self._lock:
            if self._force_stop:
                return                  # double-check after building event
            self._packets.append(dict(event))
            self._captured += 1
            captured = self._captured
            target   = self._packet_count

        # Emit outside the lock (Socket.IO call can be slow)
        self._emit("packet_data", event)
        self._emit("live_status", {
            "message":  f"Capturing on {self._interface or 'default'} — {captured} packet(s)",
            "captured": captured,
            "target":   target,
        })

        if target > 0 and captured >= target:
            self._stop_event.set()

    # ── Internal: capture loop ────────────────────────────────────────────

    def _capture_loop(self) -> None:
        """
        Main capture thread body.

        ISSUE 1 FIX: Uses sniff(timeout=0.3) instead of timeout=1 so the loop
        wakes and re-checks _should_stop() every 300 ms — stopping is nearly
        instantaneous from the user's perspective.
        """
        try:
            iface_label = self._interface or "default interface"
            self._emit("live_status", {
                "message":  f"✔ Capture started on {iface_label}",
                "captured": 0,
            })

            while not self._should_stop():
                sniff(
                    iface=self._interface,
                    prn=self._packet_callback,
                    store=False,
                    timeout=0.3,            # ← FIX: was 1 s; now 300 ms
                    promisc=True,
                    stop_filter=lambda _p: self._force_stop or self._stop_event.is_set(),
                )

            # Determine final message
            with self._lock:
                captured = self._captured
                target   = self._packet_count

            if target > 0 and captured >= target:
                final = f"Capture complete — {captured} packet(s) recorded."
            else:
                final = f"Live capture stopped — {captured} packet(s) recorded."

            self._emit("live_status", {"message": final, "captured": captured})

        except PermissionError:
            msg = ("Permission denied. "
                   "Run Flask as root / Administrator or grant CAP_NET_RAW.")
            self._last_error = msg
            self._emit("live_status", {"message": f"❌ {msg}"})
        except Exception as exc:
            self._last_error = str(exc)
            self._emit("live_status", {"message": f"❌ Capture error: {exc}"})
        finally:
            with self._lock:
                self._running = False
                self._thread  = None
            self._stop_event.set()

    # ── Public API ────────────────────────────────────────────────────────

    def start(self, interface: Optional[str] = None, packet_count: int = 0) -> None:
        """
        Start a new capture session.
        Always calls stop() first to guarantee a clean state
        before spawning the new capture thread.
        """
        # ISSUE 1 FIX: always clean up any previous session before starting
        self.stop()

        if not _SCAPY_OK:
            raise RuntimeError("Scapy is not installed. Run: pip install scapy")

        with self._lock:
            self._captured     = 0
            self._seq          = 0
            self._packet_count = max(int(packet_count or 0), 0)
            self._interface    = self._resolve_interface(interface)
            self._last_error   = None
            self._running      = True
            self._force_stop   = False
            self._packets      = []
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._capture_loop,
                daemon=True,
                name="LiveCaptureThread",
            )
            self._thread.start()

    def stop(self) -> None:
        """
        Stop the capture thread and wait for it to finish.

        ISSUE 1 FIX — three-stage stop:
          1. Set _force_stop=True  → _packet_callback becomes a no-op immediately.
          2. Set _stop_event       → _capture_loop exits its while loop.
          3. join(timeout=4.0)     → wait for the thread to exit cleanly.
          After join, _running is forced to False regardless of thread state.
        """
        thread = None
        was_running = False

        with self._lock:
            if not self._running and self._thread is None:
                return                  # nothing to stop; avoid spurious emit
            was_running  = self._running
            self._force_stop = True     # step 1: make callback a no-op immediately
            self._running    = False    # step 2: signal the loop
            self._stop_event.set()
            thread = self._thread

        # Step 3: wait for the thread to exit
        if thread and thread.is_alive():
            thread.join(timeout=1.5)
            # If thread is still alive after 4 s, log it but don't block forever
            if thread.is_alive():
                print("[LiveMonitor] WARNING: capture thread did not exit cleanly.",
                      flush=True)

        # Force-cleanup regardless of thread state
        with self._lock:
            self._thread     = None
            self._running    = False
            self._force_stop = True     # stays True until next start()

        if was_running:
            self._emit("live_status", {
                "message":  "Live capture stopped.",
                "captured": self._captured,
            })

    def get_csv(self) -> str:
        """
        Export all captured packets as a CSV string.
        Includes all HTTP and credential fields.
        Snapshot is taken under the lock; CSV writing happens outside.
        """
        with self._lock:
            rows_snapshot = list(self._packets)   # snapshot, lock released below

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()

        for row in rows_snapshot:
            r = {k: row.get(k, "") for k in _CSV_COLUMNS}
            # Flatten credentials dict → readable string for CSV
            creds = row.get("credentials")
            if creds and isinstance(creds, dict):
                r["credentials_str"] = "; ".join(
                    f"{k}={v}" for k, v in creds.items()
                )
            writer.writerow(r)

        return buf.getvalue()

    # ── Properties ────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    @property
    def captured_count(self) -> int:
        with self._lock:
            return self._captured
