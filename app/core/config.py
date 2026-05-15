from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

BASE_DIR = Path(__file__).resolve().parents[2]


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "network-forensics-demo-secret-key")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(200 * 1024 * 1024)))
    UPLOAD_FOLDER = str(BASE_DIR / "uploads")
    REPORT_FOLDER = str(BASE_DIR / "reports")

    # Threat-intelligence API configuration. Keep secrets in .env, not in source code.
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "").strip()
    THREAT_INTEL_ENABLED = _bool_env("THREAT_INTEL_ENABLED", True)
    MAX_API_IOCS_PER_TYPE = int(os.getenv("MAX_API_IOCS_PER_TYPE", "8"))
    API_TIMEOUT_SECONDS = int(os.getenv("API_TIMEOUT_SECONDS", "15"))
    API_RETRY_COUNT = int(os.getenv("API_RETRY_COUNT", "2"))
    API_CACHE_TTL_SECONDS = int(os.getenv("API_CACHE_TTL_SECONDS", str(24 * 60 * 60)))
    THREAT_INTEL_DB = os.getenv("THREAT_INTEL_DB", str(BASE_DIR / "instance" / "threat_intel.sqlite3"))

    # Hybrid Analysis sandbox submission is disabled by default to avoid uploading private evidence.
    HA_AUTO_SUBMIT = _bool_env("HA_AUTO_SUBMIT", False)
    HA_ENVIRONMENT_ID = int(os.getenv("HA_ENVIRONMENT_ID", "160"))
    HA_MAX_SUBMIT_BYTES = int(os.getenv("HA_MAX_SUBMIT_BYTES", str(32 * 1024 * 1024)))
