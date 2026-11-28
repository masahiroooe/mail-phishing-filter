-- Mac標準「メール」アプリ（Mail.app）用 AIフィッシング自動振り分けスクリプト（バッチ判定・POP救済・通知対応）
-- 配置先: ~/Library/Application Scripts/com.apple.mail/PhishingFilter.scpt
--
-- メール.app の「設定 > ルール」で以下のように登録して使用します:
--   条件: 「すべてのメッセージ」
--   操作: 「AppleScriptを実行」→「PhishingFilter」

-- ※ `./setup.sh install` 実行時に __PROJECT_DIR__ が現在の配置パスへ自動展開されます
property analyzerScriptPath : "__PROJECT_DIR__/phishing_analyzer.py"
property scanInboxScriptPath : "__PROJECT_DIR__/scan_inbox.py"
property pythonBinaryPath : "__PROJECT_DIR__/.venv/bin/python3"
property fallbackPythonPath : "/usr/bin/python3"

using terms from application "Mail"
	on perform mail action with messages caughtMessages for rule catchingRule
		my processMessages(caughtMessages)
	end perform mail action with messages
end using terms from

-- スクリプトエディタやメニューから「現在選択中のメール」に対して手動テスト実行することも可能
on run
	tell application "Mail"
		set selectedMsgs to selection
		if (count of selectedMsgs) is 0 then
			display notification "メールを選択してから実行してください" with title "AIフィッシング判定"
			return
		end if
	end tell
	my processMessages(selectedMsgs)
end run

on processMessages(msgList)
	if (count of msgList) is 0 then return
	set pyBin to my resolvePythonBinary()
	set targetMsgs to {}
	set tmpPaths to {}
	set hadPopRace to false

	-- 1) 対象メールの生ソースをユーザー専用プライベート一時ディレクトリへ書き出し（同時受信の複数通を1リクエストにまとめる）
	set tmpBase to POSIX path of (path to temporary items from user domain)
	if tmpBase does not end with "/" then set tmpBase to tmpBase & "/"

	repeat with eachMsg in msgList
		try
			set shouldSkip to false
			tell application "Mail"
				try
					set mbName to name of mailbox of eachMsg
					if mbName is in {"Junk", "Spam", "迷惑メール", "Trash", "ゴミ箱"} then
						set shouldSkip to true
					end if
				end try
				if not shouldSkip then
					set rawSource to source of eachMsg
				end if
			end tell

			if not shouldSkip then
				set tmpPath to tmpBase & "mail_phishing_" & (do shell script "/usr/bin/uuidgen") & ".eml"
				my writeUTF8File(tmpPath, rawSource)
				set end of targetMsgs to eachMsg
				set end of tmpPaths to tmpPath
			end if
		on error errMsg number errNum
			if errNum is -1719 or errNum is -1728 or (errMsg contains "Incoming POP Messages") then
				-- POP受信直後の参照失効（Apple Mail既知挙動）→ 後段で差分スキャンを非同期キックして救済
				set hadPopRace to true
			else
				my logError("Dump error (" & errNum & "): " & errMsg)
			end if
		end try
	end repeat

	-- 2) 取得できたメールを --batch で一括判定＆振り分け
	set movedJunkCount to 0
	set firstJunkReason to ""

	if (count of targetMsgs) > 0 then
		set argsStr to ""
		repeat with p in tmpPaths
			set argsStr to argsStr & " " & quoted form of (p as text)
		end repeat

		try
			set cmd to quoted form of pyBin & " " & quoted form of analyzerScriptPath & " --batch" & argsStr
			set outputText to do shell script cmd
			set resultLines to paragraphs of outputText

			set lineCount to count of resultLines
			set msgCount to count of targetMsgs
			repeat with i from 1 to msgCount
				if i <= lineCount then
					try
						set parts to my splitByPipe(item i of resultLines)
						if (count of parts) >= 1 then
							set actionCode to item 1 of parts
							set theMsg to item i of targetMsgs
							tell application "Mail"
								if actionCode is "JUNK" then
									set junk mail status of theMsg to true
									set targetJunk to my findJunkMailboxForMessage(theMsg)
									if targetJunk is not missing value then
										move theMsg to targetJunk
									end if
									set movedJunkCount to movedJunkCount + 1
									if firstJunkReason is "" and (count of parts) >= 5 then
										set firstJunkReason to item 5 of parts
									end if
								else if actionCode is "SUSPICIOUS" then
									set background color of theMsg to orange
								end if
							end tell
						end if
					on error errMsg number errNum
						my logError("Route error (" & errNum & "): " & errMsg)
					end try
				end if
			end repeat
		on error errMsg number errNum
			my logError("Batch evaluate error (" & errNum & "): " & errMsg)
		end try

		-- 3) 一時ファイルを1回のコマンドで一括削除
		try
			do shell script "/bin/rm -f" & argsStr
		end try
	end if

	if movedJunkCount > 0 then
		try
			set noteText to (movedJunkCount as text) & "通を迷惑メールへ移動しました"
			if firstJunkReason is not "" then
				set noteText to noteText & "（" & firstJunkReason & "）"
			end if
			display notification noteText with title "AIフィッシング自動振り分け"
		end try
	end if

	-- 4) POP参照失効が発生した場合、数秒後に差分スキャンを非同期実行して確実に救済する
	if hadPopRace then
		try
			set rescueCmd to "(sleep 3; " & quoted form of pyBin & " " & quoted form of scanInboxScriptPath & " --apply --if-mail-running --limit 15) >/dev/null 2>&1 &"
			do shell script rescueCmd
		on error errMsg number errNum
			my logError("POP rescue error (" & errNum & "): " & errMsg)
		end try
	end if
end processMessages

on findJunkMailboxForMessage(theMsg)
	tell application "Mail"
		try
			set srcMailbox to mailbox of theMsg
			set srcAccount to account of srcMailbox

			repeat with jName in {"Junk", "Spam", "迷惑メール", "[Gmail]/迷惑メール", "[Gmail]/Spam", "Bulk Mail", "Junk E-mail"}
				try
					return mailbox (jName as text) of srcAccount
				end try
			end repeat

			set accMailboxes to mailboxes of srcAccount
			repeat with mb in accMailboxes
				set n to name of mb
				if n is in {"Junk", "Spam", "迷惑メール", "Bulk Mail", "Junk E-mail"} then
					return mb
				end if
			end repeat
		end try

		try
			return junk mailbox
		end try
	end tell
	return missing value
end findJunkMailboxForMessage

on resolvePythonBinary()
	try
		do shell script "test -x " & quoted form of pythonBinaryPath
		return pythonBinaryPath
	on error
		return fallbackPythonPath
	end try
end resolvePythonBinary

on writeUTF8File(posixPath, contentText)
	set fileRef to open for access (POSIX file posixPath) with write permission
	try
		set eof of fileRef to 0
		write contentText to fileRef as «class utf8»
		close access fileRef
	on error errMsg
		try
			close access fileRef
		end try
		error errMsg
	end try
end writeUTF8File

on splitByPipe(inputText)
	set oldTIDs to AppleScript's text item delimiters
	set AppleScript's text item delimiters to "|"
	set itemsList to text items of inputText
	set AppleScript's text item delimiters to oldTIDs
	return itemsList
end splitByPipe

on logError(msgText)
	try
		set logDir to (POSIX path of (path to home folder)) & ".config/mail-phishing-filter"
		do shell script "/bin/mkdir -p " & quoted form of logDir & " && echo " & quoted form of ((do shell script "/bin/date '+%Y-%m-%d %H:%M:%S'") & " [AppleScript] " & msgText) & " >> " & quoted form of (logDir & "/applescript_error.log")
	end try
end logError
