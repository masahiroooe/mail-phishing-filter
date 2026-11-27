"""SQLite キャッシュ・バースト集計・JSONL 判定履歴ログを担当するモジュール。"""

from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Iterator

from .config import CACHE_DB_PATH, HISTORY_LOG_PATH


def init_cache_db(db_path: Path = CACHE_DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS verdicts (
            cache_key TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            result_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sender_events (
            from_addr TEXT NOT NULL,
            cache_key TEXT NOT NULL,
            event_ts INTEGER NOT NULL,
            PRIMARY KEY (from_addr, cache_key)
        );
        CREATE INDEX IF NOT EXISTS idx_sender_events_addr_ts
        ON sender_events (from_addr, event_ts);
        CREATE TABLE IF NOT EXISTS content_events (
            content_hash TEXT NOT NULL,
            cache_key TEXT NOT NULL,
            from_addr TEXT NOT NULL,
            event_ts INTEGER NOT NULL,
            PRIMARY KEY (content_hash, cache_key)
        );
        CREATE INDEX IF NOT EXISTS idx_content_events_hash_ts
        ON content_events (content_hash, event_ts);
        """
    )
    return conn


@contextmanager
def open_db_session(db_path: Path = CACHE_DB_PATH) -> Iterator[sqlite3.Connection | None]:
    """バッチ全体で1つの SQLite 接続を使い回し、終了時に一括掃除・コミットする。"""
    conn: sqlite3.Connection | None = None
    try:
        conn = init_cache_db(db_path)
    except Exception:
        conn = None
    try:
        yield conn
        if conn is not None:
            cutoff = int(time.time()) - 30 * 86400
            conn.execute("DELETE FROM verdicts WHERE created_at < ?", (cutoff,))
            conn.execute("DELETE FROM sender_events WHERE event_ts < ?", (cutoff,))
            conn.execute("DELETE FROM content_events WHERE event_ts < ?", (cutoff,))
            conn.commit()
    except Exception:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        raise
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def record_sender_events(
    conn: sqlite3.Connection | None, events: list[tuple[str, str, int]]
) -> None:
    if conn is None or not events:
        return
    try:
        conn.executemany(
            "INSERT OR IGNORE INTO sender_events (from_addr, cache_key, event_ts) VALUES (?, ?, ?)",
            [(addr, ckey, ts) for addr, ckey, ts in events if addr],
        )
    except Exception:
        pass


def record_content_events(
    conn: sqlite3.Connection | None, events: list[tuple[str, str, str, int]]
) -> None:
    if conn is None or not events:
        return
    try:
        conn.executemany(
            "INSERT OR IGNORE INTO content_events (content_hash, cache_key, from_addr, event_ts) VALUES (?, ?, ?, ?)",
            [(chash, ckey, addr, ts) for chash, ckey, addr, ts in events if chash],
        )
    except Exception:
        pass


def count_sender_burst(
    conn: sqlite3.Connection | None,
    from_addr: str,
    event_ts: int,
    window_seconds: int,
) -> int:
    """指定メールを含む長さ window_seconds の任意区間における同一送信元の最大通数を返す。"""
    if conn is None or not from_addr or window_seconds <= 0:
        return 0
    try:
        rows = conn.execute(
            """
            SELECT event_ts FROM sender_events
            WHERE from_addr = ? AND event_ts BETWEEN ? AND ?
            ORDER BY event_ts ASC
            """,
            (from_addr, event_ts - window_seconds, event_ts + window_seconds),
        ).fetchall()
    except Exception:
        return 0

    timestamps = [int(r[0]) for r in rows]
    best = 0
    left = 0
    for right, r_ts in enumerate(timestamps):
        while r_ts - timestamps[left] > window_seconds:
            left += 1
        if timestamps[left] <= event_ts <= r_ts:
            count = right - left + 1
            if count > best:
                best = count
    return best


def count_content_burst(
    conn: sqlite3.Connection | None,
    content_hash: str,
    event_ts: int,
    window_seconds: int,
) -> tuple[int, int]:
    """指定メールを含む長さ window_seconds の任意区間での同一内容の (最大通数, ユニーク送信元数) を返す。"""
    if conn is None or not content_hash or window_seconds <= 0:
        return (0, 0)
    try:
        rows = conn.execute(
            """
            SELECT event_ts, from_addr FROM content_events
            WHERE content_hash = ? AND event_ts BETWEEN ? AND ?
            ORDER BY event_ts ASC
            """,
            (content_hash, event_ts - window_seconds, event_ts + window_seconds),
        ).fetchall()
    except Exception:
        return (0, 0)

    items = [(int(r[0]), str(r[1] or "").lower()) for r in rows]
    best_count = 0
    best_unique_senders = 0
    left = 0
    for right, (r_ts, _) in enumerate(items):
        while r_ts - items[left][0] > window_seconds:
            left += 1
        if items[left][0] <= event_ts <= r_ts:
            count = right - left + 1
            unique_senders = len({addr for _, addr in items[left : right + 1] if addr})
            if (count > best_count) or (
                count == best_count and unique_senders > best_unique_senders
            ):
                best_count = count
                best_unique_senders = unique_senders
    return (best_count, best_unique_senders)


def get_cached_result(
    conn: sqlite3.Connection | None, cache_key: str
) -> dict[str, Any] | None:
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT result_json FROM verdicts WHERE cache_key = ?", (cache_key,)
        ).fetchone()
        if row:
            data = json.loads(row[0])
            data["cached"] = True
            return data
    except Exception:
        pass
    return None


def put_cached_result(
    conn: sqlite3.Connection | None, cache_key: str, result: dict[str, Any]
) -> None:
    if conn is None:
        return
    try:
        conn.execute(
            "INSERT OR REPLACE INTO verdicts (cache_key, created_at, result_json) VALUES (?, ?, ?)",
            (cache_key, int(time.time()), json.dumps(result, ensure_ascii=False)),
        )
    except Exception:
        pass


def append_history_batch(
    entries: list[dict[str, Any]], log_path: Path = HISTORY_LOG_PATH
) -> None:
    """判定履歴を1回のファイルオープンでまとめて追記する。"""
    if not entries:
        return
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        now_ts = int(time.time())
        with log_path.open("a", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps({"ts": now_ts, **entry}, ensure_ascii=False) + "\n")
    except Exception:
        pass
