"""ローカル即時判定ルール（ホワイトリスト・機械的無意味メール検知）モジュール。"""

from __future__ import annotations

import re
from typing import Any

_RE_URL = re.compile(r"https?://[^\s<>\"'）)]+")
_RE_WS = re.compile(r"\s+")
_RE_REPLY_PREFIX = re.compile(r"^(?:re|fwd|fw)\s*[:：]", re.IGNORECASE)
_RE_NONWORD = re.compile(r"[\W_]+")
_RE_REPEAT_CHAR = re.compile(r"(.)\1{29,}")
_RE_JAPANESE = re.compile(r"[\u3040-\u30ff\u4e00-\u9fff]")
_RE_LONG_GIBBERISH = re.compile(r"[A-Za-z0-9+/=_\-]{40,}")


def prepare_whitelist(cfg: dict[str, Any]) -> tuple[set[str], set[str], bool]:
    wl_addrs = {a.strip().lower() for a in cfg.get("whitelist_addresses", []) if a.strip()}
    wl_domains = {d.strip().lower().lstrip("@.") for d in cfg.get("whitelist_domains", []) if d.strip()}
    require_auth = bool(cfg.get("whitelist_require_auth", True))
    return wl_addrs, wl_domains, require_auth


def matches_whitelist(
    parsed: dict[str, Any], wl_addrs: set[str], wl_domains: set[str], require_auth: bool
) -> bool:
    from_addr = parsed["from_addr"]
    from_domain = parsed["from_domain"]
    if not from_addr and not from_domain:
        return False

    matched = from_addr in wl_addrs or any(
        from_domain == d or from_domain.endswith("." + d) for d in wl_domains
    )
    if not matched:
        return False

    if require_auth:
        auth = parsed["auth"]
        if auth["spf"] == "fail" or auth["dmarc"] == "fail":
            return False
        return auth["spf"] == "pass" or auth["dkim"] == "pass" or auth["dmarc"] == "pass"

    return True


def is_whitelisted(parsed: dict[str, Any], cfg: dict[str, Any]) -> bool:
    """信頼済みドメイン/アドレスに一致するか確認する（必要に応じ認証通過を確認）。"""
    return matches_whitelist(parsed, *prepare_whitelist(cfg))


def detect_obvious_nonsense(parsed: dict[str, Any]) -> str | None:
    """明確に機械的な無意味メール（空・ランダム文字列・文字化け・異常反復）をローカル検知する。"""
    if parsed.get("attachments") or parsed.get("has_images"):
        return None
    subj = (parsed.get("subject") or "").strip()
    if _RE_REPLY_PREFIX.match(subj):
        return None

    body = (parsed.get("body_text") or "").strip()
    body_no_url = _RE_URL.sub("", body).strip()

    # 1) 件名・本文ともに実質空
    if len(_RE_NONWORD.sub("", subj)) < 2 and len(_RE_NONWORD.sub("", body_no_url)) < 2:
        return "件名・本文ともに実質空の無意味なメール"

    if not body_no_url:
        return None

    # 2) 文字化け置換文字（\ufffd）だらけ
    if len(body_no_url) >= 20 and (body_no_url.count("\ufffd") / len(body_no_url)) >= 0.30:
        return "文字化け・破損文字が大半を占める無意味なメール"

    # 3) 同一文字の異常な繰り返し
    compact = _RE_WS.sub("", body_no_url)
    if len(compact) >= 30:
        m_rep = _RE_REPEAT_CHAR.search(compact)
        if m_rep and (len(m_rep.group(0)) / len(compact)) >= 0.5:
            return "同一文字の異常な繰り返しによる無意味なメール"

    # 4) スペース無しの長大なランダム英数字列のみ
    if not _RE_JAPANESE.search(body_no_url) and len(compact) >= 60:
        gibberish_len = sum(len(t) for t in _RE_LONG_GIBBERISH.findall(body_no_url))
        if gibberish_len / len(compact) >= 0.80:
            return "ランダムな英数字列が大半を占める無意味なメール"

    return None
