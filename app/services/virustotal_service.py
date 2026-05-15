from __future__ import annotations

import base64
import logging
import time
from typing import Any, Dict, Iterable, List

import requests

from app.core.config import Config
from app.services.threat_intel_db import get_cached, set_cached

log = logging.getLogger(__name__)
VT_BASE = "https://www.virustotal.com/api/v3"


def _b64_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


class VirusTotalService:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or Config.VIRUSTOTAL_API_KEY
        self.enabled = bool(self.api_key)
        self.timeout = Config.API_TIMEOUT_SECONDS
        self.ttl = Config.API_CACHE_TTL_SECONDS
        self.session = requests.Session()
        if self.enabled:
            self.session.headers.update({"x-apikey": self.api_key})

    def _request(self, indicator_type: str, indicator: str, endpoint: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"provider": "VirusTotal", "indicator": indicator, "type": indicator_type, "status": "disabled", "error": "VIRUSTOTAL_API_KEY missing"}
        cached = get_cached("virustotal", indicator_type, indicator, self.ttl)
        if cached:
            cached["cached"] = True
            return cached
        url = f"{VT_BASE}/{endpoint}"
        last_error = None
        for attempt in range(1, Config.API_RETRY_COUNT + 1):
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 429:
                    return {"provider": "VirusTotal", "indicator": indicator, "type": indicator_type, "status": "rate_limited", "error": "VirusTotal API rate limit reached"}
                if resp.status_code == 404:
                    data = {"provider": "VirusTotal", "indicator": indicator, "type": indicator_type, "status": "not_found", "score": 0, "malicious": 0, "suspicious": 0}
                    set_cached("virustotal", indicator_type, indicator, data)
                    return data
                resp.raise_for_status()
                data = self._summarize(indicator_type, indicator, resp.json())
                set_cached("virustotal", indicator_type, indicator, data)
                return data
            except requests.RequestException as exc:
                last_error = str(exc)
                time.sleep(min(2 * attempt, 5))
        log.warning("VirusTotal lookup failed for %s: %s", indicator, last_error)
        return {"provider": "VirusTotal", "indicator": indicator, "type": indicator_type, "status": "error", "error": last_error or "unknown error"}

    def _summarize(self, indicator_type: str, indicator: str, raw: dict) -> Dict[str, Any]:
        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected
        reputation = int(attrs.get("reputation", 0) or 0)
        score = min(100, malicious * 18 + suspicious * 10 + max(0, -reputation))
        categories = attrs.get("categories", {}) or {}
        return {
            "provider": "VirusTotal",
            "indicator": indicator,
            "type": indicator_type,
            "status": "ok",
            "score": score,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total,
            "detection_ratio": f"{malicious + suspicious}/{total}" if total else "0/0",
            "reputation": reputation,
            "categories": list(categories.values())[:8] if isinstance(categories, dict) else categories,
            "last_analysis_stats": stats,
        }

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        return self._request("ip", ip, f"ip_addresses/{ip}")

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        return self._request("domain", domain, f"domains/{domain}")

    def lookup_url(self, url: str) -> Dict[str, Any]:
        return self._request("url", url, f"urls/{_b64_url_id(url)}")

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        return self._request("hash", file_hash, f"files/{file_hash}")

    def enrich_iocs(self, iocs: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        max_each = Config.MAX_API_IOCS_PER_TYPE
        results = {"ips": [], "domains": [], "urls": [], "hashes": []}
        # Only public IPs are useful for VT reputation; private IPs remain local forensic IOCs.
        for item in [x for x in iocs.get("ips", []) if x.get("public")][:max_each]:
            results["ips"].append(self.lookup_ip(item["value"]))
        for item in iocs.get("domains", [])[:max_each]:
            results["domains"].append(self.lookup_domain(item["value"]))
        for item in iocs.get("urls", [])[:max_each]:
            results["urls"].append(self.lookup_url(item["value"]))
        for item in iocs.get("hashes", [])[:max_each]:
            results["hashes"].append(self.lookup_hash(item["value"]))
        return results
