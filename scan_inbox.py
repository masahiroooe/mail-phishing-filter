#!/usr/bin/env python3
"""
Mac標準「メール」アプリの受信トレイ（全アカウント）を差分スキャンする補助CLI。

特徴:
- アカウントごとに「前回スキャン済みの最新受信日時分秒 (YYYY-MM-DD HH:MM:SS)」を
  ~/.config/mail-phishing-filter/scan_state.json に保存し、2回目以降は差分だけ高速処理します。
- 複数メールをまとめて1リクエストで Gemini へ送るバッチ判定に対応しています。
- --apply 時の迷惑メール移動・ハイライトもアカウント単位で1回の AppleScript にまとめて高速実行します。
"""

from __future__ import annotations

import argparse
import datetime
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from phishing_analyzer import CONFIG_DIR, analyze_emails_batch, load_config

STATE_PATH = CONFIG_DIR / "scan_state.json"

# 共通の AppleScript ヘルパー（日時フォーマット＋UTF-8書き出し）
_AS_HELPERS = r'''
on formatIsoDate(d)
	set y to (year of d) as text
	set mo to text -2 thru -1 of ("0" & ((month of d) as integer))
	set dy to text -2 thru -1 of ("0" & (day of d))
	set hh to text -2 thru -1 of ("0" & (hours of d))
	set mm to text -2 thru -1 of ("0" & (minutes of d))
	set ss to text -2 thru -1 of ("0" & (seconds of d))
	return y & "-" & mo & "-" & dy & " " & hh & ":" & mm & ":" & ss
end formatIsoDate

on writeUTF8File(posixPath, contentText)
	set fRef to open for access (POSIX file posixPath) with write permission
	try
		set eof of fRef to 0
		write contentText to fRef as «class utf8»
		close access fRef
	on error errMsg
		try
			close access fRef
		end try
		error errMsg
	end try
end writeUTF8File
'''

# 有効なアカウント一覧のみを軽量取得
LIST_ACCOUNTS_SCRIPT = r'''
on run argv
	set outLines to {}
	tell application "Mail"
		repeat with acc in accounts
			set isEnabled to true
			try
				set isEnabled to enabled of acc
			end try
			if isEnabled then
				set accName to name of acc
				set accAddrs to ""
				try
					set AppleScript's text item delimiters to ","
					set accAddrs to (email addresses of acc) as text
					set AppleScript's text item delimiters to ""
				end try
				set end of outLines to (accName & tab & accAddrs)
			end if
		end repeat
	end tell
	set AppleScript's text item delimiters to linefeed
	set res to outLines as text
	set AppleScript's text item delimiters to ""
	return res
end run
'''

# 1アカウント分の受信トレイを新着順に辿り、cutoffIso 以降のメールだけをダンプ
DUMP_ACCOUNT_INBOX_SCRIPT = _AS_HELPERS + r'''
on run argv
	set targetAccName to item 1 of argv
	set maxMsgs to (item 2 of argv) as integer
	set cutoffIso to item 3 of argv
	set outDir to item 4 of argv
	set timeoutSec to (item 5 of argv) as integer
	set outLines to {}

	with timeout of timeoutSec seconds
		tell application "Mail"
			set acc to account targetAccName
			set inboxMb to missing value
			repeat with candName in {"INBOX", "Inbox", "受信"}
				try
					set inboxMb to mailbox (candName as text) of acc
					exit repeat
				end try
			end repeat
			if inboxMb is missing value then
				try
					repeat with mb in mailboxes of acc
						if name of mb is in {"INBOX", "Inbox", "受信"} then
							set inboxMb to mb
							exit repeat
						end if
					end repeat
				end try
			end if
			if inboxMb is missing value then return ""

			-- 先頭(1)と末尾(-1)の日時を比べて並び順を自動判定（count of messages を使わない）
			set newestAtFront to true
			try
				set firstDateIso to my formatIsoDate(date received of message 1 of inboxMb)
				set lastDateIso to my formatIsoDate(date received of message -1 of inboxMb)
				if lastDateIso > firstDateIso then set newestAtFront to false
			on error
				return ""
			end try

			set fetchedCount to 0
			set olderStreak to 0
			repeat with stepIdx from 1 to maxMsgs
				try
					if newestAtFront then
						set m to message stepIdx of inboxMb
					else
						set m to message (-stepIdx) of inboxMb
					end if
				on error
					exit repeat
				end try

				try
					set recvIso to my formatIsoDate(date received of m)
					set shouldTake to true
					if cutoffIso is not "" then
						if recvIso < cutoffIso then
							set shouldTake to false
							set olderStreak to olderStreak + 1
							if olderStreak >= 3 then exit repeat
						else
							set olderStreak to 0
						end if
					end if

					if shouldTake then
						set fetchedCount to fetchedCount + 1
						set mid to (id of m) as text
						set sndr to sender of m
						set subj to subject of m
						set emlPath to outDir & "/msg_" & fetchedCount & "_" & mid & ".eml"
						my writeUTF8File(emlPath, source of m)
						set end of outLines to (targetAccName & tab & mid & tab & recvIso & tab & emlPath & tab & sndr & tab & subj)
					end if
				end try
			end repeat
		end tell
	end timeout

	set AppleScript's text item delimiters to linefeed
	set res to outLines as text
	set AppleScript's text item delimiters to ""
	return res
end run
'''

# Mail.app で現在選択中のメールだけをダンプ（最速テスト用）
DUMP_SELECTED_SCRIPT = _AS_HELPERS + r'''
on run argv
	set outDir to item 1 of argv
	set outLines to {}
	with timeout of 120 seconds
		tell application "Mail"
			set selMsgs to selection
			set idx to 0
			repeat with m in selMsgs
				set idx to idx + 1
				try
					set mid to (id of m) as text
					set recvIso to my formatIsoDate(date received of m)
					set sndr to sender of m
					set subj to subject of m
					set accName to ""
					try
						set accName to name of account of mailbox of m
					end try
					set emlPath to outDir & "/sel_" & idx & "_" & mid & ".eml"
					my writeUTF8File(emlPath, source of m)
					set end of outLines to (accName & tab & mid & tab & recvIso & tab & emlPath & tab & sndr & tab & subj)
				end try
			end repeat
		end tell
	end timeout
	set AppleScript's text item delimiters to linefeed
	set res to outLines as text
	set AppleScript's text item delimiters to ""
	return res
end run
'''

# 1アカウント分の複数アクションを一括適用（osascript 起動回数をアカウントあたり1回に削減）
# argv: targetAccName, searchWindow, "id1:ACTION1,id2:ACTION2,..."
APPLY_ACCOUNT_ACTIONS_SCRIPT = _AS_HELPERS + r'''
on splitText(txt, delim)
	set oldTIDs to AppleScript's text item delimiters
	set AppleScript's text item delimiters to delim
	set outList to text items of txt
	set AppleScript's text item delimiters to oldTIDs
	return outList
end splitText

on run argv
	set targetAccName to item 1 of argv
	set searchWindow to (item 2 of argv) as integer
	set specStr to item 3 of argv
	if specStr is "" then return ""

	set pairs to my splitText(specStr, ",")
	set wantedIds to {}
	set wantedActions to {}
	repeat with pairStr in pairs
		set kv to my splitText(pairStr as text, ":")
		if (count of kv) >= 2 then
			set end of wantedIds to (item 1 of kv)
			set end of wantedActions to (item 2 of kv)
		end if
	end repeat
	if (count of wantedIds) is 0 then return ""

	set statusLines to {}

	with timeout of 180 seconds
		tell application "Mail"
			set acc to account targetAccName
			set inboxMb to missing value
			repeat with candName in {"INBOX", "Inbox", "受信"}
				try
					set inboxMb to mailbox (candName as text) of acc
					exit repeat
				end try
			end repeat
			if inboxMb is missing value then return ""

			-- 迷惑メールボックスをアカウントあたり1回だけ解決
			set targetJunk to missing value
			repeat with jName in {"Junk", "Spam", "迷惑メール", "[Gmail]/迷惑メール", "[Gmail]/Spam", "Bulk Mail", "Junk E-mail"}
				try
					set targetJunk to mailbox (jName as text) of acc
					exit repeat
				end try
			end repeat
			if targetJunk is missing value then
				try
					set targetJunk to junk mailbox
				end try
			end if

			-- 先頭(1)と末尾(-1)の日時で並び順を自動判定
			set newestAtFront to true
			try
				set firstDateIso to my formatIsoDate(date received of message 1 of inboxMb)
				set lastDateIso to my formatIsoDate(date received of message -1 of inboxMb)
				if lastDateIso > firstDateIso then set newestAtFront to false
			on error
				return ""
			end try

			-- 移動中にインデックスがズレないよう、1パス走査で対象メッセージ参照を先に集める
			set matchedMsgs to {}
			set matchedIds to {}
			set matchedActions to {}
			set remaining to count of wantedIds

			repeat with i from 1 to searchWindow
				if remaining <= 0 then exit repeat
				try
					if newestAtFront then
						set m to message i of inboxMb
					else
						set m to message (-i) of inboxMb
					end if
				on error
					exit repeat
				end try

				try
					set midStr to (id of m) as text
					repeat with wIdx from 1 to (count of wantedIds)
						if (item wIdx of wantedIds) is midStr then
							set end of matchedMsgs to m
							set end of matchedIds to midStr
							set end of matchedActions to (item wIdx of wantedActions)
							set item wIdx of wantedIds to ""
							set remaining to remaining - 1
							exit repeat
						end if
					end repeat
				end try
			end repeat

			-- 集めたメッセージ参照に対して一括で迷惑メール移動・ハイライトを実行
			repeat with mIdx from 1 to (count of matchedMsgs)
				set targetMsg to item mIdx of matchedMsgs
				set idStr to item mIdx of matchedIds
				set actionCode to item mIdx of matchedActions
				try
					if actionCode is "JUNK" then
						set junk mail status of targetMsg to true
						if targetJunk is not missing value then
							move targetMsg to targetJunk
							set end of statusLines to (idStr & tab & "MOVED_TO_JUNK")
						else
							set end of statusLines to (idStr & tab & "MARKED_JUNK_ONLY")
						end if
					else if actionCode is "SUSPICIOUS" then
						set background color of targetMsg to orange
						set end of statusLines to (idStr & tab & "HIGHLIGHTED")
					else
						set end of statusLines to (idStr & tab & "NOOP")
					end if
				on error
					set end of statusLines to (idStr & tab & "APPLY_ERROR")
				end try
			end repeat
		end tell
	end timeout

	set AppleScript's text item delimiters to linefeed
	set res to statusLines as text
	set AppleScript's text item delimiters to ""
	return res
end run
'''


# ==============================================================================
# 差分スキャン状態（前回受信日時分秒）管理
# ==============================================================================


def load_scan_state(state_path: Path = STATE_PATH) -> dict[str, Any]:
    if state_path.exists():
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("accounts"), dict):
                return data
        except Exception:
            pass
    return {"accounts": {}}


def save_scan_state(state: dict[str, Any], state_path: Path = STATE_PATH) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def update_account_watermark(
    state: dict[str, Any], account_name: str, newest_received_iso: str
) -> bool:
    """アカウントの最新受信日時(YYYY-MM-DD HH:MM:SS)をより新しい値で更新する。"""
    if not account_name or not newest_received_iso:
        return False
    accounts = state.setdefault("accounts", {})
    prev = accounts.get(account_name, {}).get("last_received_iso", "")
    if newest_received_iso > prev:
        accounts[account_name] = {
            "last_received_iso": newest_received_iso,
            "updated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        return True
    return False


# ==============================================================================
# AppleScript 実行ヘルパー
# ==============================================================================


def run_osascript(script: str, args: list[str], timeout: int = 300) -> str:
    proc = subprocess.run(
        ["/usr/bin/osascript", "-e", script, *args],
        capture_output=True,
        text=True,
        timeout=timeout + 15,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"osascript failed (code {proc.returncode})")
    return proc.stdout.strip()


def list_accounts() -> list[tuple[str, str]]:
    raw = run_osascript(LIST_ACCOUNTS_SCRIPT, [], timeout=30)
    accounts: list[tuple[str, str]] = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if parts and parts[0]:
            accounts.append((parts[0], parts[1] if len(parts) > 1 else ""))
    return accounts


def parse_dump_lines(raw: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) >= 6:
            rows.append(
                {
                    "account": parts[0],
                    "id": parts[1],
                    "received_iso": parts[2],
                    "eml_path": parts[3],
                    "sender": parts[4],
                    "subject": "\t".join(parts[5:]),
                }
            )
    return rows


def apply_actions_batched(
    actions_by_account: dict[str, list[tuple[str, str]]], search_window: int
) -> dict[tuple[str, str], str]:
    """アカウントごとに1回の osascript 起動で複数アクションをまとめて適用する。"""
    status_map: dict[tuple[str, str], str] = {}
    for acc_name, pairs in actions_by_account.items():
        if not acc_name or not pairs:
            continue
        spec_str = ",".join(f"{mid}:{act}" for mid, act in pairs)
        raw = run_osascript(
            APPLY_ACCOUNT_ACTIONS_SCRIPT,
            [acc_name, str(search_window), spec_str],
            timeout=180,
        )
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                status_map[(acc_name, parts[0])] = parts[1]
    return status_map


def main(argv: list[str] | None = None) -> int:
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
    parser.add_argument("--no-cache", action="store_true", help="キャッシュを無視して再判定")
    parser.add_argument("--json", action="store_true", help="結果をJSONで出力")
    args = parser.parse_args(argv)

    if args.reset_state:
        if STATE_PATH.exists():
            STATE_PATH.unlink()
            print(f"前回スキャン日時をリセットしました: {STATE_PATH}")
        else:
            print("保存済みのスキャン状態はありませんでした。")
        return 0

    dry_run = args.dry_run or (not args.apply)
    should_save_state = (not dry_run) or args.save_state
    cfg = load_config()
    state = load_scan_state()

    since_days_iso = ""
    if args.since_days is not None and args.since_days >= 0:
        cutoff_dt = datetime.datetime.now() - datetime.timedelta(days=args.since_days)
        since_days_iso = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")

    items: list[dict[str, str]] = []
    newest_seen_by_account: dict[str, str] = {}

    with tempfile.TemporaryDirectory(prefix="scan_mail_") as tmp_dir:
        try:
            if args.selected:
                if not args.json:
                    print("Mail.app で選択中のメールを取得中...", file=sys.stderr, flush=True)
                items = parse_dump_lines(run_osascript(DUMP_SELECTED_SCRIPT, [tmp_dir], timeout=120))
            else:
                if not args.json:
                    print("Mail.app のアカウント一覧を取得中...", file=sys.stderr, flush=True)
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

                    acc_items = parse_dump_lines(
                        run_osascript(
                            DUMP_ACCOUNT_INBOX_SCRIPT,
                            [acc_name, str(args.limit), effective_cutoff, tmp_dir, str(args.timeout)],
                            timeout=args.timeout,
                        )
                    )
                    items.extend(acc_items)
                    if not args.json:
                        print(f"    -> {len(acc_items)}件取得", file=sys.stderr, flush=True)
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

    # アカウント単位でアクションを一括適用（osascript 起動を最小化）
    pending_actions: dict[str, list[tuple[str, str]]] = {}
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
            "from": res.get("from") or item["sender"],
            "subject": res.get("subject") or item["subject"],
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
