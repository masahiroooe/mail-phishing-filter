"""Mac標準「メール」アプリ向け AIフィッシング自動振り分けパッケージ。"""

from .analyzer import analyze_email_bytes, analyze_emails_batch, decide_action, format_applescript_line
from .config import (
    API_KEY_FILE,
    CACHE_DB_PATH,
    CONFIG_DIR,
    CONFIG_PATH,
    DEFAULT_CONFIG,
    HISTORY_LOG_PATH,
    KEYCHAIN_SERVICE,
    get_api_key,
    load_config,
    save_default_config_if_missing,
)
from .email_parser import compute_content_fingerprint, parse_raw_email
from .gemini_client import RetryableAPIError, call_gemini_with_retry
from .local_rules import detect_obvious_nonsense, is_whitelisted

__all__ = [
    "API_KEY_FILE",
    "CACHE_DB_PATH",
    "CONFIG_DIR",
    "CONFIG_PATH",
    "DEFAULT_CONFIG",
    "HISTORY_LOG_PATH",
    "KEYCHAIN_SERVICE",
    "RetryableAPIError",
    "analyze_email_bytes",
    "analyze_emails_batch",
    "call_gemini_with_retry",
    "compute_content_fingerprint",
    "decide_action",
    "detect_obvious_nonsense",
    "format_applescript_line",
    "get_api_key",
    "is_whitelisted",
    "load_config",
    "parse_raw_email",
    "save_default_config_if_missing",
]
