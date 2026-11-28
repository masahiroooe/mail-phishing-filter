#!/usr/bin/env python3
"""
Mac標準「メール」アプリの受信トレイ（全アカウント）を差分スキャンする補助 CLI。

AppleScript による Mail.app 操作と状態管理は `mail_phishing_filter/mail_applescript.py`、
フィッシング判定パイプラインは `mail_phishing_filter/analyzer.py` に分離されています。
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime
import fcntl
import json
from pathlib import Path
import sys
import tempfile
from typing import Any, Iterator

from mail_phishing_filter.analyzer import analyze_emails_batch
from mail_phishing_filter.config import CONFIG_DIR, STATE_PATH, load_config
from mail_phishing_filter.mail_applescript import (
    APPLY_ACCOUNT_ACTIONS_SCRIPT,
    DUMP_ACCOUNT_INBOX_SCRIPT,
    DUMP_SELECTED_SCRIPT,
    LIST_ACCOUNTS_SCRIPT,
    apply_actions_batched,
    dump_account_inbox,
    dump_selected_messages,
    is_mail_app_running,
    list_accounts,
    load_scan_state,
    save_scan_state,
    send_macos_notification,
    update_account_watermark,
)

LOCK_PATH = CONFIG_DIR / "scan.lock"


@contextmanager
def acquire_scan_lock(lock_path: Path = LOCK_PATH) -> Iterator[bool]:
    """多重起動を防ぐ非ブロッキング排他ロック。すでに別プロセスが実行中なら False を返す。"""
    fh = None
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fh = lock_path.open("a+", encoding="utf-8")
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        if fh is not None:
            fh.close()
        yield False
        return
    except OSError:
        if fh is not None:
            fh.close()
        yield True
        return
    try:
        yield True
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()

__all__ = [
    "APPLY_ACCOUNT_ACTIONS_SCRIPT",
    "DUMP_ACCOUNT_INBOX_SCRIPT",
    "DUMP_SELECTED_SCRIPT",
    "LIST_ACCOUNTS_SCRIPT",
    "STATE_PATH",
    "load_scan_state",
    "main",
    "save_scan_state",
    "update_account_watermark",
]


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mail.app 受信トレイ差分フィッシングスキャン")
    parser.add_argument("--limit", type=int, default=30, help="1アカウントあたりの最大走査件数（デフォルト: 30）")
    parser.add_argument("--account", default="", help="特定アカウントのみに絞るキーワード（例: icloud, gmail）")
    parser.add_argument("--selected", action="store_true", help="Mail.app で現在選択中のメールのみを対象にする（最速）")
    parser.add_argument("--since-days", type=int, default=None, help="初回など未保存時に直近N日以内のみ対象にする")
    parser.add_argument("--dry-run", action="store_true", help="判定のみ行いメールは移動しない・前回日時も更新しない（デフォルト動作）")
    parser.add_argument("--apply", action="store_true", help="実際に迷惑メール移動・ハイライトを実行し、前回スキャン日時を保存する")
    parser.add_argument("--save-state", action="store_true", help="ドライランでも今回取得した最新受信日時を前回スキャン日時として保存する")
    parser.add_argument("--ignore-state", action="store_true", help="保存済みの前回スキャン日時を無視して再スキャンする")
    parser.add_argument("--reset-state", action="store_true", help="保存済みの前回スキャン日時をすべてリセットして終了する")
    parser.add_argument("--timeout", type=int, default=300, help="アカウント1件あたりの AppleScript タイムアウト秒数（デフォルト: 300秒）")
    parser.add_argument("--batch-size", type=int, default=10, help="Gemini 1リクエストにまとめる最大メール通数（デフォルト: 10）")
    parser.add_argument("--if-mail-running", action="store_true", help="Mail.app が起動している場合のみ実行する（定期実行向け）")
    parser.add_argument("--no-cache", action="store_true", help="キャッシュを無視して再判定")
    parser.add_argument("--json", action="store_true", help="結果をJSONで出力")
    return parser


def _collect_messages(
    args: argparse.Namespace,
    state: dict[str, Any],
    since_days_iso: str,
    tmp_dir: str,
) -> list[dict[str, str]]:
    if args.selected:
        if not args.json:
            print("Mail.app で選択中のメールを取得中...", file=sys.stderr, flush=True)
        return dump_selected_messages(tmp_dir)

    if not args.json:
        print("Mail.app のアカウント一覧を取得中...", file=sys.stderr, flush=True)

    items: list[dict[str, str]] = []
    acc_filter = args.account.lower()
    for acc_name, acc_addrs in list_accounts():
        if acc_filter and (acc_filter not in acc_name.lower()) and (acc_filter not in acc_addrs.lower()):
            continue

        saved_iso = (
            ""
            if args.ignore_state
            else state.get("accounts", {}).get(acc_name, {}).get("last_received_iso", "")
        )
        effective_cutoff = max(saved_iso, since_days_iso) if (saved_iso or since_days_iso) else ""

        if not args.json:
            label = (
                f"{effective_cutoff} 以降の新着を取得中"
                if effective_cutoff
                else f"初回スキャン：新着順に最大{args.limit}件を取得中（最大{args.timeout}秒待機）"
            )
            print(f"  [{acc_name}] {label}...", file=sys.stderr, flush=True)

        acc_items = dump_account_inbox(acc_name, args.limit, effective_cutoff, tmp_dir, args.timeout)
        items.extend(acc_items)
        if not args.json:
            print(f"    -> {len(acc_items)}件取得", file=sys.stderr, flush=True)

    return items


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    if args.reset_state:
        if STATE_PATH.exists():
            STATE_PATH.unlink()
            print(f"前回スキャン日時をリセットしました: {STATE_PATH}")
        else:
            print("保存済みのスキャン状態はありませんでした。")
        return 0

    if args.if_mail_running and not is_mail_app_running():
        return 0

    with acquire_scan_lock() as acquired:
        if not acquired:
            if not args.json and not args.if_mail_running:
                print("別のスキャンプロセスが実行中のためスキップしました。", file=sys.stderr)
            return 0
        return _run_scan(args)


def _run_scan(args: argparse.Namespace) -> int:
    dry_run = args.dry_run or (not args.apply)
    should_save_state = (not dry_run) or args.save_state
    cfg = load_config()
    state = load_scan_state()

    since_days_iso = ""
    if args.since_days is not None and args.since_days >= 0:
        cutoff_dt = datetime.datetime.now() - datetime.timedelta(days=args.since_days)
        since_days_iso = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")

    with tempfile.TemporaryDirectory(prefix="scan_mail_") as tmp_dir:
        try:
            items = _collect_messages(args, state, since_days_iso, tmp_dir)
        except Exception as exc:
            print(f"エラー: Mail.app からメールを取得できませんでした: {exc}", file=sys.stderr)
            print(
                "※ 初回で時間がかかりすぎる場合は `--timeout 600` や `--account gmail` で個別に試すか、\n"
                "  Mail.app で数通選択して `python3 scan_inbox.py --selected --dry-run` を実行してください。",
                file=sys.stderr,
            )
            return 1

        if not items:
            if not args.json:
                print("\n前回スキャン以降の新着メールはありませんでした。")
            else:
                print(json.dumps({"counts": {"JUNK": 0, "SUSPICIOUS": 0, "OK": 0, "ERROR": 0}, "results": []}, ensure_ascii=False))
            return 0

        mode_label = "本番適用モード（移動＋前回日時保存）" if not dry_run else "ドライラン（判定のみ・移動なし）"
        if not args.json:
            print(
                f"\n=== Mail.app 受信トレイスキャン ({mode_label}) : {len(items)}件 "
                f"（最大{args.batch_size}通/リクエストでバッチ判定） ===\n"
            )

        valid_items: list[dict[str, str]] = []
        raw_bytes_list: list[bytes] = []
        for item in items:
            eml_path = Path(item["eml_path"])
            if eml_path.exists():
                valid_items.append(item)
                raw_bytes_list.append(eml_path.read_bytes())

        progress_cb = None if args.json else (lambda msg: print(msg, file=sys.stderr, flush=True))
        batch_results = analyze_emails_batch(
            raw_bytes_list,
            cfg,
            use_cache=not args.no_cache,
            dry_run=dry_run,
            batch_size=args.batch_size,
            progress_fn=progress_cb,
        )

    pending_actions: dict[str, list[tuple[str, str]]] = {}
    newest_seen_by_account: dict[str, str] = {}
    account_had_error: set[str] = set()
    counts = {"JUNK": 0, "SUSPICIOUS": 0, "OK": 0, "ERROR": 0}

    for item, res in zip(valid_items, batch_results):
        rec_action = "ERROR" if res.get("verdict") == "error" else res.get("recommended_action", "OK")
        counts[rec_action] = counts.get(rec_action, 0) + 1
        if rec_action == "ERROR":
            account_had_error.add(item["account"])
        elif item["account"] and item["received_iso"]:
            if item["received_iso"] > newest_seen_by_account.get(item["account"], ""):
                newest_seen_by_account[item["account"]] = item["received_iso"]

        if (not dry_run) and rec_action in ("JUNK", "SUSPICIOUS") and item["account"]:
            pending_actions.setdefault(item["account"], []).append((item["id"], rec_action))

    applied_status_map = (
        apply_actions_batched(pending_actions, search_window=max(args.limit * 2, 50))
        if pending_actions
        else {}
    )

    results: list[dict[str, Any]] = []
    for idx, (item, res) in enumerate(zip(valid_items, batch_results), 1):
        rec_action = "ERROR" if res.get("verdict") == "error" else res.get("recommended_action", "OK")
        applied_status = (
            "DRY_RUN"
            if dry_run
            else applied_status_map.get((item["account"], item["id"]), "NOOP")
        )
        entry = {
            "account": item["account"],
            "id": item["id"],
            "received_iso": item["received_iso"],
            "from": res.get("from", ""),
            "subject": res.get("subject", ""),
            "recommended_action": rec_action,
            "applied_status": applied_status,
            "verdict": res.get("verdict"),
            "confidence": res.get("confidence"),
            "impersonated_brand": res.get("impersonated_brand"),
            "reason": res.get("reason"),
            "cached": res.get("cached", False),
        }
        results.append(entry)

        if not args.json:
            badge = {
                "JUNK": "[迷惑メール]",
                "SUSPICIOUS": "[要確認]    ",
                "OK": "[安全]      ",
                "ERROR": "[エラー]    ",
            }.get(rec_action, "[?]")
            brand = f" (偽装先: {entry['impersonated_brand']})" if entry["impersonated_brand"] else ""
            cache_tag = " [cache]" if entry["cached"] else ""
            print(
                f"{idx:2d}. {badge} ({entry['confidence']:.2f}) [{entry['account']}] "
                f"{entry['received_iso']} | {entry['subject'][:36]} | From: {entry['from']}{brand}{cache_tag}"
            )
            if rec_action != "OK":
                print(
                    f"    理由: {entry['reason']}"
                    + (f" -> {applied_status}" if not dry_run else "")
                )

    updated_accounts: list[tuple[str, str]] = []
    if should_save_state and not args.selected:
        for acc_name, newest_iso in newest_seen_by_account.items():
            if acc_name in account_had_error:
                continue
            if update_account_watermark(state, acc_name, newest_iso):
                updated_accounts.append((acc_name, newest_iso))
        if updated_accounts:
            save_scan_state(state)

    if (not dry_run) and cfg.get("notify_on_junk", True):
        moved_junk = [
            e for e in results
            if e["recommended_action"] == "JUNK"
            and e["applied_status"] in ("MOVED_TO_JUNK", "MARKED_JUNK_ONLY")
        ]
        if moved_junk:
            sample = moved_junk[0]
            msg = f"{len(moved_junk)}通を迷惑メールへ移動（例: {sample['subject'][:28]}）"
            send_macos_notification("AIフィッシング自動振り分け", msg)

    if args.json:
        print(
            json.dumps(
                {
                    "counts": counts,
                    "updated_watermarks": dict(updated_accounts),
                    "results": results,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(
            f"\n集計: 迷惑メール判定={counts['JUNK']}件 / 要確認={counts['SUSPICIOUS']}件 / "
            f"安全={counts['OK']}件 / エラー={counts['ERROR']}件"
        )
        if updated_accounts:
            print("次回スキャン基準日時（保存済み）:")
            for acc_name, newest_iso in updated_accounts:
                print(f"  - {acc_name}: {newest_iso} 以降")
        elif dry_run:
            print("※ ドライランのため移動・前回日時の更新は行っていません。")
            if counts["JUNK"] > 0 or counts["SUSPICIOUS"] > 0:
                print("→ 問題なければ `python3 scan_inbox.py --apply` で振り分け＋前回日時を保存できます。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
