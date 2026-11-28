"""Mac標準「メール」アプリ連携（AppleScript 実行・差分スキャン状態管理）モジュール。"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from .config import STATE_PATH

_RE_ISO_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
_RE_SAFE_EML_NAME = re.compile(r"^(?:msg|sel)_\d+_\d+\.eml$")

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
						set emlName to "msg_" & fetchedCount & "_" & mid & ".eml"
						set emlPath to outDir & "/" & emlName
						my writeUTF8File(emlPath, source of m)
						set end of outLines to (targetAccName & tab & mid & tab & recvIso & tab & emlName)
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
					set accName to ""
					try
						set accName to name of account of mailbox of m
					end try
					set emlName to "sel_" & idx & "_" & mid & ".eml"
					set emlPath to outDir & "/" & emlName
					my writeUTF8File(emlPath, source of m)
					set end of outLines to (accName & tab & mid & tab & recvIso & tab & emlName)
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

			set newestAtFront to true
			try
				set firstDateIso to my formatIsoDate(date received of message 1 of inboxMb)
				set lastDateIso to my formatIsoDate(date received of message -1 of inboxMb)
				if lastDateIso > firstDateIso then set newestAtFront to false
			on error
				return ""
			end try

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


def parse_dump_lines(raw: str, expected_dir: str | Path) -> list[dict[str, str]]:
    """AppleScript 出力を厳密検証してパースする（行インジェクション・パストラバーサル防止）。"""
    base_dir = Path(expected_dir).resolve()
    rows: list[dict[str, str]] = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        acc_name, msg_id, recv_iso, eml_name = parts
        if not msg_id.isdigit():
            continue
        if not _RE_ISO_DATETIME.match(recv_iso):
            continue
        if not _RE_SAFE_EML_NAME.match(eml_name):
            continue
        resolved = (base_dir / eml_name).resolve()
        if resolved.parent != base_dir:
            continue
        rows.append(
            {
                "account": acc_name,
                "id": msg_id,
                "received_iso": recv_iso,
                "eml_path": str(resolved),
            }
        )
    return rows


def dump_account_inbox(
    account_name: str, limit: int, cutoff_iso: str, out_dir: str, timeout: int
) -> list[dict[str, str]]:
    raw = run_osascript(
        DUMP_ACCOUNT_INBOX_SCRIPT,
        [account_name, str(limit), cutoff_iso, out_dir, str(timeout)],
        timeout=timeout,
    )
    return parse_dump_lines(raw, out_dir)


def dump_selected_messages(out_dir: str) -> list[dict[str, str]]:
    return parse_dump_lines(run_osascript(DUMP_SELECTED_SCRIPT, [out_dir], timeout=120), out_dir)


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


def is_mail_app_running() -> bool:
    """Mail.app が現在起動しているかを軽量確認する（未起動時に勝手に立ち上げないため）。"""
    try:
        proc = subprocess.run(
            ["/usr/bin/pgrep", "-x", "Mail"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        return proc.returncode == 0
    except Exception:
        return False


_NOTIFY_SCRIPT = r'''
on run argv
	display notification (item 1 of argv) with title (item 2 of argv)
end run
'''


def send_macos_notification(title: str, message: str) -> None:
    """引数配列経由で安全に macOS 通知センターへ通知を送る。"""
    try:
        subprocess.run(
            ["/usr/bin/osascript", "-e", _NOTIFY_SCRIPT, message[:160], title[:60]],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except Exception:
        pass
