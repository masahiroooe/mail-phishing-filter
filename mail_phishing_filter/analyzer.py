"""フィッシング判定パイプライン（ローカル判定 → キャッシュ → Geminiバッチ判定）モジュール。"""

from __future__ import annotations

from pathlib import Path
import time
from typing import Any, Callable

from .config import CACHE_DB_PATH, DEFAULT_CONFIG, get_api_key, load_config
from .email_parser import parse_raw_email
from .gemini_client import (
    BATCH_RESPONSE_SCHEMA,
    RESPONSE_SCHEMA,
    build_analysis_prompt,
    build_batch_analysis_prompt,
    call_gemini_with_retry,
)
from .local_rules import detect_obvious_nonsense, matches_whitelist, prepare_whitelist
from .storage import (
    append_history_batch,
    count_content_burst,
    count_sender_burst,
    get_cached_result,
    open_db_session,
    put_cached_result,
    record_content_events,
    record_sender_events,
)


def decide_action(
    llm_result: dict[str, Any], cfg: dict[str, Any], dry_run: bool = False
) -> str:
    verdict = str(llm_result.get("verdict", "legitimate")).lower()
    try:
        confidence = float(llm_result.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0

    junk_th = float(cfg.get("junk_confidence_threshold", 0.85))
    susp_th = float(cfg.get("suspicious_confidence_threshold", 0.60))
    susp_action = str(cfg.get("action_on_suspicious", "highlight")).lower()

    if verdict == "phishing" and confidence >= junk_th:
        action = "JUNK"
    elif (verdict in ("phishing", "suspicious")) and confidence >= susp_th:
        action = {"junk": "JUNK", "highlight": "SUSPICIOUS"}.get(susp_action, "OK")
    else:
        action = "OK"

    return "OK" if (dry_run or cfg.get("dry_run", False)) else action


def _format_window_label(seconds: int) -> str:
    return f"{seconds // 60}分間" if seconds % 60 == 0 else f"{seconds}秒間"


def _build_result_record(
    parsed: dict[str, Any],
    llm_res: dict[str, Any],
    cfg: dict[str, Any],
    model: str,
    dry_run: bool,
) -> dict[str, Any]:
    verdict = str(llm_res.get("verdict", "legitimate")).lower()
    brand = "" if verdict == "legitimate" else str(llm_res.get("impersonated_brand", ""))
    rec_action = decide_action(llm_res, cfg, dry_run=False)
    is_dry = dry_run or bool(cfg.get("dry_run", False))
    return {
        "action": "OK" if is_dry else rec_action,
        "recommended_action": rec_action,
        "verdict": verdict,
        "confidence": float(llm_res.get("confidence", 0.0)),
        "impersonated_brand": brand,
        "signals": list(llm_res.get("signals", [])),
        "reason": str(llm_res.get("reason", "")),
        "model": model,
        "cached": False,
        "dry_run": is_dry,
        "from": parsed["from_addr"],
        "subject": parsed["subject"],
        "to": parsed["to"],
        "auth": {
            "spf": parsed["auth"]["spf"],
            "dkim": parsed["auth"]["dkim"],
            "dmarc": parsed["auth"]["dmarc"],
        },
    }


def _build_local_rule_record(
    parsed: dict[str, Any],
    cfg: dict[str, Any],
    dry_run: bool,
    *,
    recommended_action: str,
    verdict: str,
    model_tag: str,
    signal: str,
    reason: str,
) -> dict[str, Any]:
    is_dry = dry_run or bool(cfg.get("dry_run", False))
    return {
        "action": "OK" if is_dry else recommended_action,
        "recommended_action": recommended_action,
        "verdict": verdict,
        "confidence": 1.0,
        "impersonated_brand": "",
        "signals": [signal],
        "reason": reason,
        "model": model_tag,
        "cached": False,
        "dry_run": is_dry,
        "from": parsed["from_addr"],
        "subject": parsed["subject"],
        "to": parsed["to"],
    }


def _build_error_record(
    parsed: dict[str, Any], signal: str, reason: str, dry_run: bool
) -> dict[str, Any]:
    return {
        "action": "ERROR",
        "recommended_action": "OK",
        "verdict": "error",
        "confidence": 0.0,
        "impersonated_brand": "",
        "signals": [signal],
        "reason": reason,
        "cached": False,
        "dry_run": dry_run,
        "from": parsed["from_addr"],
        "subject": parsed["subject"],
        "to": parsed["to"],
    }


def _chunk_pending_items(
    pending: list[tuple[int, dict[str, Any]]],
    batch_size: int,
    max_batch_body_chars: int,
) -> list[list[tuple[int, dict[str, Any]]]]:
    """件数上限と合計本文長上限の両方を満たすバッチに分割する。"""
    chunks: list[list[tuple[int, dict[str, Any]]]] = []
    cur: list[tuple[int, dict[str, Any]]] = []
    cur_chars = 0

    for item in pending:
        body_len = len(item[1]["body_text"]) + 400
        if cur and (len(cur) >= batch_size or cur_chars + body_len > max_batch_body_chars):
            chunks.append(cur)
            cur = []
            cur_chars = 0
        cur.append(item)
        cur_chars += body_len

    if cur:
        chunks.append(cur)
    return chunks


def analyze_emails_batch(
    raw_bytes_list: list[bytes],
    cfg: dict[str, Any] | None = None,
    *,
    api_key: str | None = None,
    use_cache: bool = True,
    dry_run: bool = False,
    write_log: bool = True,
    batch_size: int | None = None,
    cache_db_path: Path = CACHE_DB_PATH,
    caller_fn: Callable[..., dict[str, Any]] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    progress_fn: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """複数メールを1つのDBセッションでローカル判定・キャッシュ照合し、未判定分をバッチでGemini解析する。"""
    if not raw_bytes_list:
        return []

    cfg = cfg or load_config()
    eff_batch_size = max(1, int(batch_size or cfg.get("batch_size", 10)))
    max_batch_chars = int(cfg.get("max_batch_body_chars", 24000))
    batch_interval = float(cfg.get("batch_interval_seconds", 2.0))
    max_retries = int(cfg.get("max_retries", 3))
    model = str(cfg.get("model", DEFAULT_CONFIG["model"]))
    timeout_s = int(cfg.get("timeout_seconds", 35))
    flood_enabled = bool(cfg.get("flood_protection_enabled", True))
    flood_window = int(cfg.get("flood_window_seconds", 600))
    flood_threshold = int(cfg.get("flood_threshold", 8))
    content_flood_window = int(cfg.get("content_flood_window_seconds", 3600))
    content_flood_threshold = int(cfg.get("content_flood_threshold", 3))
    nonsense_enabled = bool(cfg.get("nonsense_filter_enabled", True))
    is_dry = dry_run or bool(cfg.get("dry_run", False))

    wl_addrs, wl_domains, wl_require_auth = prepare_whitelist(cfg)
    parsed_items = [parse_raw_email(raw_bytes, cfg) for raw_bytes in raw_bytes_list]
    whitelisted_flags = [
        matches_whitelist(p, wl_addrs, wl_domains, wl_require_auth) for p in parsed_items
    ]

    results: list[dict[str, Any] | None] = [None] * len(raw_bytes_list)
    pending: list[tuple[int, dict[str, Any]]] = []
    history_buffer: list[dict[str, Any]] = []

    # フェーズ1: ローカル判定＋キャッシュ照合のみ DB セッション内で実行し、API 通信前にロックを完全解放する
    with open_db_session(cache_db_path) as conn:
        if flood_enabled:
            record_sender_events(
                conn,
                [
                    (p["from_addr"], p["cache_key"], p["date_ts"])
                    for p, is_wl in zip(parsed_items, whitelisted_flags)
                    if not is_wl and p["from_addr"]
                ],
            )
            record_content_events(
                conn,
                [
                    (p["content_hash"], p["cache_key"], p["from_addr"], p["date_ts"])
                    for p, is_wl in zip(parsed_items, whitelisted_flags)
                    if not is_wl and p["content_hash"]
                ],
            )

        for idx, (parsed, is_wl) in enumerate(zip(parsed_items, whitelisted_flags)):
            if is_wl:
                results[idx] = _build_local_rule_record(
                    parsed,
                    cfg,
                    dry_run,
                    recommended_action="OK",
                    verdict="legitimate",
                    model_tag="rule:whitelist",
                    signal="ホワイトリスト登録済み送信元（認証確認済み）",
                    reason="信頼済み送信元のためスキップ",
                )
                continue

            if flood_enabled and parsed["from_addr"]:
                burst_count = count_sender_burst(
                    conn, parsed["from_addr"], parsed["date_ts"], flood_window
                )
                if burst_count >= flood_threshold:
                    win_label = _format_window_label(flood_window)
                    rec = _build_local_rule_record(
                        parsed,
                        cfg,
                        dry_run,
                        recommended_action="JUNK",
                        verdict="phishing",
                        model_tag="rule:sender-flood",
                        signal=f"同一送信元からの大量送信（{win_label}に{burst_count}通）",
                        reason=f"同一アドレスから{win_label}に{burst_count}通の大量送信を検知したため無条件で迷惑メール分類",
                    )
                    results[idx] = rec
                    history_buffer.append(rec)
                    continue

            if flood_enabled and parsed["content_hash"]:
                c_count, unique_senders = count_content_burst(
                    conn, parsed["content_hash"], parsed["date_ts"], content_flood_window
                )
                if (unique_senders >= 2 and c_count >= content_flood_threshold) or (
                    c_count >= flood_threshold
                ):
                    win_label = _format_window_label(content_flood_window)
                    rec = _build_local_rule_record(
                        parsed,
                        cfg,
                        dry_run,
                        recommended_action="JUNK",
                        verdict="phishing",
                        model_tag="rule:content-flood",
                        signal=f"同一内容の大量送信（{win_label}に{c_count}通 / 送信元{unique_senders}件）",
                        reason=f"異なる送信元を含む同一内容メールを{win_label}に{c_count}通検知したため無条件で迷惑メール分類",
                    )
                    results[idx] = rec
                    history_buffer.append(rec)
                    continue

            if nonsense_enabled:
                nonsense_reason = detect_obvious_nonsense(parsed)
                if nonsense_reason:
                    rec = _build_local_rule_record(
                        parsed,
                        cfg,
                        dry_run,
                        recommended_action="JUNK",
                        verdict="phishing",
                        model_tag="rule:nonsense",
                        signal=nonsense_reason,
                        reason=f"{nonsense_reason}のため無条件で迷惑メール分類",
                    )
                    results[idx] = rec
                    history_buffer.append(rec)
                    continue

            if use_cache:
                cached = get_cached_result(conn, parsed["cache_key"])
                if cached:
                    rec_action = decide_action(cached, cfg, dry_run=False)
                    cached["recommended_action"] = rec_action
                    cached["action"] = "OK" if is_dry else rec_action
                    cached["dry_run"] = is_dry
                    if cached.get("verdict") == "legitimate":
                        cached["impersonated_brand"] = ""
                    results[idx] = cached
                    continue

            pending.append((idx, parsed))

    # フェーズ2: Gemini API 通信（DB ロックを保持しないため並列実行しても競合しない）
    new_cache_entries: list[tuple[str, dict[str, Any]]] = []
    if pending:
        key = api_key if api_key is not None else get_api_key()
        if not key:
            for idx, parsed in pending:
                rec = _build_error_record(
                    parsed,
                    "Gemini APIキー未設定",
                    "APIキーが未設定のため判定をスキップしました（setup.sh set-key で設定してください）",
                    dry_run,
                )
                results[idx] = rec
                history_buffer.append(rec)
        else:
            chunks = _chunk_pending_items(pending, eff_batch_size, max_batch_chars)
            for chunk_no, chunk in enumerate(chunks, 1):
                if chunk_no > 1 and batch_interval > 0:
                    sleep_fn(batch_interval)
                if progress_fn:
                    progress_fn(
                        f"  Gemini バッチ判定 {chunk_no}/{len(chunks)}（{len(chunk)}通を1リクエストで解析中）..."
                    )

                if len(chunk) == 1:
                    orig_idx, parsed = chunk[0]
                    try:
                        llm_res = call_gemini_with_retry(
                            key,
                            model,
                            build_analysis_prompt(parsed),
                            timeout_s,
                            schema=RESPONSE_SCHEMA,
                            max_output_tokens=512,
                            max_retries=max_retries,
                            caller_fn=caller_fn,
                            sleep_fn=sleep_fn,
                        )
                        rec = _build_result_record(parsed, llm_res, cfg, model, dry_run)
                        if use_cache:
                            new_cache_entries.append((parsed["cache_key"], rec))
                    except Exception as exc:
                        rec = _build_error_record(
                            parsed,
                            "API呼び出しエラー",
                            f"判定エラー（フェイルセーフで受信トレイ維持）: {str(exc)[:140]}",
                            dry_run,
                        )
                    results[orig_idx] = rec
                    history_buffer.append(rec)
                    continue

                parsed_list = [p for _, p in chunk]
                max_out = min(4096, max(768, 240 * len(chunk)))
                batch_timeout = max(timeout_s, 30 + len(chunk) * 3)
                try:
                    batch_resp = call_gemini_with_retry(
                        key,
                        model,
                        build_batch_analysis_prompt(parsed_list),
                        batch_timeout,
                        schema=BATCH_RESPONSE_SCHEMA,
                        max_output_tokens=max_out,
                        max_retries=max_retries,
                        caller_fn=caller_fn,
                        sleep_fn=sleep_fn,
                    )
                    by_local_idx: dict[int, dict[str, Any]] = {}
                    for item in batch_resp.get("results", []):
                        if isinstance(item, dict) and "index" in item:
                            try:
                                by_local_idx[int(item["index"])] = item
                            except (TypeError, ValueError):
                                pass

                    for local_i, (orig_idx, parsed) in enumerate(chunk):
                        llm_item = by_local_idx.get(local_i)
                        if llm_item is None:
                            rec = _build_error_record(
                                parsed,
                                "バッチ応答欠落",
                                "バッチ判定の応答に該当メールが含まれなかったため受信トレイを維持しました",
                                dry_run,
                            )
                        else:
                            rec = _build_result_record(parsed, llm_item, cfg, model, dry_run)
                            if use_cache:
                                new_cache_entries.append((parsed["cache_key"], rec))
                        results[orig_idx] = rec
                        history_buffer.append(rec)
                except Exception as exc:
                    err_msg = f"判定エラー（フェイルセーフで受信トレイ維持）: {str(exc)[:140]}"
                    for orig_idx, parsed in chunk:
                        rec = _build_error_record(parsed, "API呼び出しエラー", err_msg, dry_run)
                        results[orig_idx] = rec
                        history_buffer.append(rec)

    # フェーズ3: 新規キャッシュのみ短時間セッションで一括保存
    if new_cache_entries:
        with open_db_session(cache_db_path) as conn:
            for ckey, rec in new_cache_entries:
                put_cached_result(conn, ckey, rec)

    if write_log and history_buffer:
        append_history_batch(history_buffer)

    return [r for r in results if r is not None]


def analyze_email_bytes(
    raw_bytes: bytes,
    cfg: dict[str, Any] | None = None,
    *,
    api_key: str | None = None,
    use_cache: bool = True,
    dry_run: bool = False,
    write_log: bool = True,
    cache_db_path: Path = CACHE_DB_PATH,
    caller_fn: Callable[..., dict[str, Any]] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    return analyze_emails_batch(
        [raw_bytes],
        cfg,
        api_key=api_key,
        use_cache=use_cache,
        dry_run=dry_run,
        write_log=write_log,
        batch_size=1,
        cache_db_path=cache_db_path,
        caller_fn=caller_fn,
        sleep_fn=sleep_fn,
    )[0]


def format_applescript_line(result: dict[str, Any]) -> str:
    """AppleScriptが安全にパースできる1行出力（パイプ区切り）を返す。"""
    def _clean(s: Any) -> str:
        return str(s or "").replace("|", "／").replace("\n", " ").replace("\r", " ").strip()

    return "|".join(
        [
            _clean(result.get("action", "OK")),
            f"{float(result.get('confidence', 0.0)):.2f}",
            _clean(result.get("verdict", "")),
            _clean(result.get("impersonated_brand", "")),
            _clean(result.get("reason", "")),
        ]
    )
