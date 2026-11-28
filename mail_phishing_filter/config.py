"""設定ファイル・パス定数・Gemini APIキー取得を担当するモジュール。"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from typing import Any

CONFIG_DIR = Path(
    os.environ.get("MAIL_PHISHING_FILTER_CONFIG_DIR", "").strip()
    or (Path.home() / ".config" / "mail-phishing-filter")
)
CONFIG_PATH = CONFIG_DIR / "config.json"
CACHE_DB_PATH = CONFIG_DIR / "cache.sqlite3"
HISTORY_LOG_PATH = CONFIG_DIR / "history.jsonl"
STATE_PATH = CONFIG_DIR / "scan_state.json"
API_KEY_FILE = CONFIG_DIR / "api_key"
KEYCHAIN_SERVICE = "mail-phishing-filter-gemini-api-key"

DEFAULT_CONFIG: dict[str, Any] = {
    "model": "gemini-3.5-flash-lite",
    "junk_confidence_threshold": 0.85,
    "suspicious_confidence_threshold": 0.60,
    "action_on_suspicious": "highlight",  # "highlight" | "junk" | "none"
    "timeout_seconds": 35,
    "max_body_chars": 3000,
    "max_links": 20,
    "batch_size": 10,
    "max_batch_body_chars": 24000,
    "batch_interval_seconds": 2.0,
    "max_retries": 3,
    "flood_protection_enabled": True,
    "flood_window_seconds": 600,
    "flood_threshold": 8,
    "content_flood_window_seconds": 3600,
    "content_flood_threshold": 3,
    "content_flood_min_chars": 30,
    "nonsense_filter_enabled": True,
    "whitelist_domains": [],
    "whitelist_addresses": [],
    "whitelist_require_auth": True,
    "notify_on_junk": True,
    "dry_run": False,
}


def ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_config(config_path: Path = CONFIG_PATH) -> dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    if config_path.exists():
        try:
            user_cfg = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(user_cfg, dict):
                cfg.update(user_cfg)
        except Exception:
            pass
    return cfg


def save_default_config_if_missing(config_path: Path = CONFIG_PATH) -> None:
    try:
        ensure_config_dir()
        if not config_path.exists():
            config_path.write_text(
                json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
    except OSError:
        pass


def get_api_key() -> str | None:
    """環境変数 → macOSキーチェーン → 設定ファイル の順に Gemini API キーを取得する。"""
    for env_name in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        val = os.environ.get(env_name, "").strip()
        if val:
            return val

    try:
        proc = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass

    if API_KEY_FILE.exists():
        try:
            key = API_KEY_FILE.read_text(encoding="utf-8").strip()
            if key:
                return key
        except Exception:
            pass

    return None
