"""RFC 2822 生メール解析・HTMLリンク抽出・認証ヘッダー解析・正規化ハッシュ生成モジュール。"""

from __future__ import annotations

import email
import email.header
import email.policy
import email.utils
import hashlib
import html
from html.parser import HTMLParser
import re
import time
import urllib.parse
from typing import Any

# DoS 対策：巨大メール・巨大HTMLパートの解析上限
MAX_HTML_PARSE_CHARS = 200_000
MAX_PLAIN_PARSE_CHARS = 200_000

# 事前コンパイル済み正規表現
_RE_URL = re.compile(r"https?://[^\s<>\"'）)]+")
_RE_URL_DOMAIN = re.compile(r"https?://([a-zA-Z0-9.\-]+)")
_RE_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_RE_DIGITS = re.compile(r"\d+")
_RE_WS = re.compile(r"\s+")
_RE_HSPACE = re.compile(r"[ \t]+")
_RE_DKIM_D = re.compile(r"\bd=([a-zA-Z0-9.\-]+)")
_RE_HEADER_D = re.compile(r"header\.d=([a-z0-9.\-]+)")
_RE_IMG_TAG = re.compile(r"<img\b", re.IGNORECASE)
_RE_SUBSTANTIAL_STRIP = re.compile(r"<(?:url|email|n)>|\W+")


class _HTMLContentExtractor(HTMLParser):
    """HTMLメールから可視テキストと全アンカーリンク（表示テキスト＋実URL）を抽出する。"""

    SKIP_TAGS = {"script", "style", "head", "title", "noscript"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self.text_chunks: list[str] = []
        self.links: list[dict[str, str]] = []
        self._in_a = False
        self._current_href = ""
        self._current_anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        if tag_l in self.SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth > 0:
            return
        if tag_l in {"br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4"}:
            self.text_chunks.append("\n")
        if tag_l == "a":
            for k, v in attrs:
                if k.lower() == "href" and v and v.strip():
                    self._in_a = True
                    self._current_href = v.strip()
                    self._current_anchor_text = []
                    break

    def handle_endtag(self, tag: str) -> None:
        tag_l = tag.lower()
        if tag_l in self.SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
            return
        if tag_l == "a" and self._in_a:
            anchor = " ".join("".join(self._current_anchor_text).split()).strip()
            self.links.append({"text": anchor[:120], "href": self._current_href[:300]})
            self._in_a = False
            self._current_href = ""
            self._current_anchor_text = []

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0 or not data:
            return
        self.text_chunks.append(data)
        if self._in_a:
            self._current_anchor_text.append(data)

    def get_text(self) -> str:
        raw = "".join(self.text_chunks)
        compact: list[str] = []
        prev_blank = False
        for line in raw.splitlines():
            cleaned = _RE_HSPACE.sub(" ", line).strip()
            if not cleaned:
                if not prev_blank:
                    compact.append("")
                prev_blank = True
            else:
                compact.append(cleaned)
                prev_blank = False
        return "\n".join(compact).strip()


def compute_content_fingerprint(subject: str, body_text: str, min_chars: int = 30) -> str:
    """URLや数字の差分を吸収して本文・件名から同一内容判定用の正規化ハッシュを作る。"""
    normalized_body = _RE_URL.sub(" <URL> ", body_text)
    normalized_body = _RE_EMAIL.sub(" <EMAIL> ", normalized_body)
    normalized_body = _RE_DIGITS.sub("<N>", normalized_body)
    normalized_body = _RE_WS.sub(" ", normalized_body).strip().lower()

    substantial = _RE_SUBSTANTIAL_STRIP.sub("", normalized_body)
    if len(substantial) < min_chars:
        return ""

    normalized_subj = _RE_WS.sub(" ", _RE_DIGITS.sub("<N>", subject)).strip().lower()
    payload = (
        normalized_body[:1500]
        if len(substantial) >= 60
        else f"{normalized_subj}|{normalized_body[:1500]}"
    )
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


def _safe_decode_header(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(email.header.make_header(email.header.decode_header(value)))
    except Exception:
        return str(value)


def _extract_domain(addr: str) -> str:
    addr = addr.strip().lower()
    return addr.rsplit("@", 1)[1].strip(" >\"'") if "@" in addr else ""


def _extract_url_domain(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _decode_part_payload(part: email.message.Message) -> str:
    """MIMEパートからテキスト本文を安全にデコードする。"""
    try:
        payload = part.get_content()
    except Exception:
        raw_payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        return raw_payload.decode(charset, errors="replace")
    if isinstance(payload, bytes):
        return payload.decode("utf-8", errors="replace")
    return str(payload)


def _parse_auth_results(auth_headers: list[str]) -> dict[str, Any]:
    joined = " ; ".join(auth_headers)
    lower = joined.lower()

    def _find_status(proto: str) -> str:
        m = re.search(rf"\b{proto}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", lower)
        return m.group(1) if m else "unknown"

    return {
        "spf": _find_status("spf"),
        "dkim": _find_status("dkim"),
        "dmarc": _find_status("dmarc"),
        "dkim_domains": sorted(set(_RE_HEADER_D.findall(lower))),
        "raw": joined[:600],
    }


def parse_raw_email(raw_bytes: bytes, cfg: dict[str, Any]) -> dict[str, Any]:
    """生のRFC 2822メールデータを解析し、判定用の特徴量辞書を返す。"""
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    from_raw = _safe_decode_header(msg.get("From", ""))
    from_name, from_addr = email.utils.parseaddr(from_raw)
    from_addr = from_addr.lower()
    from_domain = _extract_domain(from_addr)

    _, reply_to_addr = email.utils.parseaddr(_safe_decode_header(msg.get("Reply-To", "")))
    reply_to_addr = reply_to_addr.lower()
    reply_to_domain = _extract_domain(reply_to_addr)

    _, return_path_addr = email.utils.parseaddr(_safe_decode_header(msg.get("Return-Path", "")))
    return_path_addr = return_path_addr.lower()
    return_path_domain = _extract_domain(return_path_addr)

    subject = _safe_decode_header(msg.get("Subject", ""))
    to_header = _safe_decode_header(msg.get("To", ""))
    date_header = _safe_decode_header(msg.get("Date", ""))
    message_id = (msg.get("Message-ID") or "").strip()

    try:
        dt = email.utils.parsedate_to_datetime(date_header) if date_header else None
        date_ts = int(dt.timestamp()) if dt is not None else int(time.time())
    except Exception:
        date_ts = int(time.time())

    auth_headers = [
        f"{h_name}: {str(val).strip()}"
        for h_name in ("Authentication-Results", "ARC-Authentication-Results", "Received-SPF")
        for val in msg.get_all(h_name, [])
    ]
    auth_summary = _parse_auth_results(auth_headers)

    dkim_sig_domains: set[str] = set(auth_summary["dkim_domains"])
    for sig in msg.get_all("DKIM-Signature", []):
        m = _RE_DKIM_D.search(str(sig))
        if m:
            dkim_sig_domains.add(m.group(1).lower())
    auth_summary["dkim_domains"] = sorted(dkim_sig_domains)

    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[str] = []

    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if msg.is_multipart():
            disp = (part.get_content_disposition() or "").lower()
            filename = part.get_filename()
            if disp == "attachment" or filename:
                attachments.append(_safe_decode_header(filename or "unnamed"))
                continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            plain_parts.append(_decode_part_payload(part))
        elif ctype == "text/html":
            html_parts.append(_decode_part_payload(part))
        elif not msg.is_multipart():
            plain_parts.append(_decode_part_payload(part))

    links: list[dict[str, str]] = []
    html_text = ""
    has_images = False
    if html_parts:
        joined_html = "\n".join(html_parts)[:MAX_HTML_PARSE_CHARS]
        has_images = bool(_RE_IMG_TAG.search(joined_html))
        extractor = _HTMLContentExtractor()
        extractor.feed(joined_html)
        html_text = extractor.get_text()
        links.extend(extractor.links)

    plain_text = "\n".join(plain_parts)[:MAX_PLAIN_PARSE_CHARS].strip()
    body_text = plain_text if len(plain_text) >= 40 else (html_text or plain_text)

    seen_hrefs = {item["href"] for item in links}
    for url in _RE_URL.findall(plain_text):
        cleaned = html.unescape(url.rstrip(".,;:"))
        if cleaned not in seen_hrefs:
            links.append({"text": "(plain URL)", "href": cleaned[:300]})
            seen_hrefs.add(cleaned)

    max_links = int(cfg.get("max_links", 20))
    enriched_links: list[dict[str, Any]] = []
    for item in links[:max_links]:
        href = item["href"]
        href_domain = _extract_url_domain(href)
        text_url_match = _RE_URL_DOMAIN.search(item["text"])
        mismatch = False
        if text_url_match and href_domain:
            displayed_dom = text_url_match.group(1).lower()
            if displayed_dom != href_domain and not href_domain.endswith("." + displayed_dom):
                mismatch = True
        enriched_links.append(
            {
                "text": item["text"],
                "href": href,
                "domain": href_domain,
                "display_url_mismatch": mismatch,
                "is_punycode": "xn--" in href_domain,
            }
        )

    max_chars = int(cfg.get("max_body_chars", 3000))
    if len(body_text) > max_chars:
        head_len = int(max_chars * 0.75)
        tail_len = max_chars - head_len
        body_text = body_text[:head_len] + "\n... [中略] ...\n" + body_text[-tail_len:]

    heuristic_notes: list[str] = []
    if from_name and "@" in from_name and from_addr and from_addr not in from_name.lower():
        heuristic_notes.append("From表示名に送信元と異なるメールアドレスが含まれています")
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        heuristic_notes.append(f"Reply-Toドメイン({reply_to_domain})とFromドメイン({from_domain})が異なります")
    if return_path_domain and from_domain and return_path_domain != from_domain:
        heuristic_notes.append(f"Return-Pathドメイン({return_path_domain})とFromドメイン({from_domain})が異なります")
    if auth_summary["spf"] in ("fail", "softfail"):
        heuristic_notes.append(f"SPF認証失敗({auth_summary['spf']})")
    if auth_summary["dmarc"] == "fail":
        heuristic_notes.append("DMARC認証失敗")
    if auth_summary["dkim"] == "fail":
        heuristic_notes.append("DKIM認証失敗")
    if any(l["display_url_mismatch"] for l in enriched_links):
        heuristic_notes.append("リンクの表示URLと実際の遷移先ドメインが不一致の箇所があります")
    if any(l["is_punycode"] for l in enriched_links):
        heuristic_notes.append("リンクに国際化ドメイン(Punycode: xn--)が含まれています")

    if message_id:
        cache_key = hashlib.sha256(message_id.encode("utf-8", errors="ignore")).hexdigest()
    else:
        sig = f"{from_addr}|{subject}|{date_header}|{body_text[:500]}"
        cache_key = hashlib.sha256(sig.encode("utf-8", errors="ignore")).hexdigest()

    min_content_chars = int(cfg.get("content_flood_min_chars", 30))
    content_hash = compute_content_fingerprint(subject, body_text, min_chars=min_content_chars)

    return {
        "cache_key": cache_key,
        "content_hash": content_hash,
        "has_images": has_images,
        "message_id": message_id,
        "date": date_header,
        "date_ts": date_ts,
        "to": to_header,
        "subject": subject,
        "from_raw": from_raw,
        "from_name": from_name,
        "from_addr": from_addr,
        "from_domain": from_domain,
        "reply_to_addr": reply_to_addr,
        "reply_to_domain": reply_to_domain,
        "return_path_addr": return_path_addr,
        "return_path_domain": return_path_domain,
        "auth": auth_summary,
        "attachments": attachments[:10],
        "links": enriched_links,
        "heuristic_notes": heuristic_notes,
        "body_text": body_text,
    }
