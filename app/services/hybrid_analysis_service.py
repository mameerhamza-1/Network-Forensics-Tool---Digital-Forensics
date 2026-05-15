from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Dict, List
import re

import requests

from app.core.config import Config
from app.services.threat_intel_db import get_cached, set_cached

log = logging.getLogger(__name__)
HA_BASE = "https://www.hybrid-analysis.com/api/v2"


class HybridAnalysisService:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or Config.HYBRID_ANALYSIS_API_KEY
        self.enabled = bool(self.api_key)
        self.timeout = Config.API_TIMEOUT_SECONDS
        self.ttl = Config.API_CACHE_TTL_SECONDS
        self.session = requests.Session()
        if self.enabled:
            self.session.headers.update({
                "api-key": self.api_key,
                "User-Agent": "Falcon Sandbox",
                "Accept": "application/json",
            })

    def _handle_response(self, resp: requests.Response) -> Any:
        """Normalize Hybrid Analysis API responses without crashing the Flask app."""
        if resp.status_code == 429:
            return {"status": "rate_limited", "error": "Hybrid Analysis API rate limit reached"}
        if resp.status_code in (401, 403):
            return {"status": "auth_error", "error": "Hybrid Analysis API authentication/vetting failed"}
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    def _get(self, endpoint: str, params: dict | None = None) -> Any:
        resp = self.session.get(f"{HA_BASE}/{endpoint}", params=params, timeout=self.timeout)
        return self._handle_response(resp)

    def _post(self, endpoint: str, data: dict | None = None, files: dict | None = None) -> Any:
        resp = self.session.post(f"{HA_BASE}/{endpoint}", data=data, files=files, timeout=self.timeout)
        return self._handle_response(resp)

    @staticmethod
    def _valid_hash(file_hash: str) -> bool:
        return bool(re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", file_hash or ""))

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"provider": "Hybrid Analysis", "indicator": file_hash, "type": "hash", "status": "disabled", "error": "HYBRID_ANALYSIS_API_KEY missing"}
        normalized_hash = (file_hash or "").strip().lower()
        if not self._valid_hash(normalized_hash):
            return {"provider": "Hybrid Analysis", "indicator": file_hash, "type": "hash", "status": "skipped", "error": "Invalid hash format"}

        cached = get_cached("hybrid_analysis", "hash", normalized_hash, self.ttl)
        if cached:
            cached["cached"] = True
            return cached

        last_error = None
        for attempt in range(1, Config.API_RETRY_COUNT + 1):
            try:
                # Hybrid Analysis API v2 now uses GET /search/hash?hash=<hash>.
                # The old POST /search/hash call can return HTTP 400 Bad Request.
                raw = self._get("search/hash", params={"hash": normalized_hash})

                # Auth/rate-limit errors are returned as structured dictionaries by _handle_response.
                if isinstance(raw, dict) and raw.get("status") in {"rate_limited", "auth_error"}:
                    data = {
                        "provider": "Hybrid Analysis",
                        "indicator": normalized_hash,
                        "type": "hash",
                        "status": raw.get("status"),
                        "error": raw.get("error"),
                    }
                    set_cached("hybrid_analysis", "hash", normalized_hash, data)
                    return data

                data = self._summarize_hash(normalized_hash, raw)
                set_cached("hybrid_analysis", "hash", normalized_hash, data)
                return data
            except requests.HTTPError as exc:
                status = getattr(exc.response, "status_code", None)
                body = ""
                try:
                    body = exc.response.text[:300] if exc.response is not None else ""
                except Exception:
                    body = ""
                last_error = f"HTTP {status}: {body}" if status else str(exc)
                if status in (400, 404):
                    break
                time.sleep(min(2 * attempt, 5))
            except requests.RequestException as exc:
                last_error = str(exc)
                time.sleep(min(2 * attempt, 5))

        log.warning("Hybrid Analysis hash lookup failed for %s: %s", normalized_hash, last_error)
        return {"provider": "Hybrid Analysis", "indicator": normalized_hash, "type": "hash", "status": "error", "error": last_error or "unknown error"}

    def submit_file(self, file_path: str, environment_id: int | None = None) -> Dict[str, Any]:
        if not self.enabled:
            return {"provider": "Hybrid Analysis", "type": "file_submission", "status": "disabled", "error": "HYBRID_ANALYSIS_API_KEY missing"}
        path = Path(file_path)
        if not path.exists() or path.stat().st_size > Config.HA_MAX_SUBMIT_BYTES:
            return {"provider": "Hybrid Analysis", "type": "file_submission", "status": "skipped", "error": "File missing or too large for automatic sandbox submission"}
        try:
            with open(path, "rb") as handle:
                files = {"file": (path.name, handle)}
                data = {
                    "environment_id": str(environment_id or Config.HA_ENVIRONMENT_ID),
                    "allow_community_access": "no",
                    "no_share_third_party": "yes",
                }
                raw = self._post("submit/file", data=data, files=files)
            return {"provider": "Hybrid Analysis", "type": "file_submission", "status": "submitted", "raw": raw}
        except requests.RequestException as exc:
            return {"provider": "Hybrid Analysis", "type": "file_submission", "status": "error", "error": str(exc)}

    def _summarize_hash(self, file_hash: str, raw: Any) -> Dict[str, Any]:
        rows = raw if isinstance(raw, list) else raw.get("result", []) if isinstance(raw, dict) else []
        best = rows[0] if rows else {}
        verdict = best.get("verdict") or best.get("threat_score") or "unknown"
        threat_score = int(best.get("threat_score", 0) or 0)
        score = min(100, threat_score)
        mitre = best.get("mitre_attcks") or best.get("mitre_attacks") or []
        return {
            "provider": "Hybrid Analysis",
            "indicator": file_hash,
            "type": "hash",
            "status": "ok" if rows else "not_found",
            "score": score,
            "threat_score": threat_score,
            "verdict": verdict,
            "malware_family": best.get("vx_family") or best.get("type") or "unknown",
            "environment": best.get("environment_description", "N/A"),
            "mitre_attck": mitre[:8] if isinstance(mitre, list) else mitre,
            "network_indicators": best.get("hosts", [])[:10] if isinstance(best.get("hosts", []), list) else [],
            "sandbox_summary": best.get("analysis_start_time") or best.get("submit_name") or "No public sandbox summary available.",
        }

    def enrich_iocs(self, iocs: Dict[str, Any], source_path: str | None = None) -> Dict[str, Any]:
        max_each = Config.MAX_API_IOCS_PER_TYPE
        results = {"hashes": []}
        for item in iocs.get("hashes", [])[:max_each]:
            results["hashes"].append(self.lookup_hash(item["value"]))
        # Submission is opt-in by env var to avoid unintentionally uploading private evidence.
        if source_path and Config.HA_AUTO_SUBMIT:
            results["submission"] = self.submit_file(source_path)
        else:
            results["submission"] = {"provider": "Hybrid Analysis", "type": "file_submission", "status": "skipped", "error": "Automatic file submission disabled"}
        return results
