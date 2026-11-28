#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIL_SCRIPTS_DIR="$HOME/Library/Application Scripts/com.apple.mail"
SCPT_TARGET="$MAIL_SCRIPTS_DIR/PhishingFilter.scpt"
CONFIG_DIR="$HOME/.config/mail-phishing-filter"
CONFIG_FILE="$CONFIG_DIR/config.json"
HISTORY_FILE="$CONFIG_DIR/history.jsonl"
KEYCHAIN_SERVICE="mail-phishing-filter-gemini-api-key"
LAUNCH_AGENT_LABEL="com.local.mail-phishing-filter"
LAUNCH_AGENT_PLIST="$HOME/Library/LaunchAgents/$LAUNCH_AGENT_LABEL.plist"

usage() {
  cat <<'EOF'
使い方:
  ./setup.sh set-key                  Gemini APIキーをmacOSキーチェーンに安全に保存
  ./setup.sh install                  Mail.app ルール用スクリプトをコンパイル＆配置
  ./setup.sh enable-auto [秒数]       バックグラウンド定期差分スキャンを有効化（デフォルト300秒＝5分）
  ./setup.sh disable-auto             バックグラウンド定期差分スキャンを無効化
  ./setup.sh allow <domain>           信頼済みドメインをホワイトリストに追加
  ./setup.sh stats [日数]             日別の判定実績・直近の迷惑メール振り分け一覧を表示（デフォルト7日）
  ./setup.sh logs [N]                 直近N件（デフォルト20件）の判定ログを表示
  ./setup.sh status                   設定・インストール・自動スキャン状態を確認
EOF
}

cmd="${1:-}"
case "$cmd" in
  set-key)
    echo -n "Gemini API キーを入力してください（画面には表示されません）: "
    read -rs api_key
    echo ""
    if [[ -z "$api_key" ]]; then
      echo "エラー: APIキーが空です。" >&2
      exit 1
    fi
    /usr/bin/security add-generic-password -U -a "$USER" -s "$KEYCHAIN_SERVICE" -w "$api_key"
    echo "完了: Gemini APIキーを macOS キーチェーン ($KEYCHAIN_SERVICE) に保存しました。"
    ;;

  install)
    mkdir -p "$MAIL_SCRIPTS_DIR"
    tmp_as="$(mktemp /tmp/mail_rule_XXXXXX.applescript)"
    trap 'rm -f "$tmp_as"' EXIT
    /usr/bin/python3 - "$PROJECT_DIR/mail_rule.applescript" "$tmp_as" "$PROJECT_DIR" <<'PY'
import sys
from pathlib import Path
src, dst, proj = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
dst.write_text(src.read_text(encoding="utf-8").replace("__PROJECT_DIR__", proj), encoding="utf-8")
PY
    /usr/bin/osacompile -o "$SCPT_TARGET" "$tmp_as"
    rm -f "$tmp_as"
    trap - EXIT
    /usr/bin/python3 "$PROJECT_DIR/phishing_analyzer.py" --init-config >/dev/null
    echo "完了: Mail.app ルール用スクリプトを配置しました:"
    echo "  $SCPT_TARGET"
    echo ""
    echo "【次の手順（Mail.appでのルール設定）】"
    echo "1. 「メール」アプリを開き、メニューから「メール > 設定... > ルール」を開く"
    echo "2. 「ルールを追加」をクリック"
    echo "3. 説明: AIフィッシング自動振り分け"
    echo "4. 条件: 「すべてのメッセージ」を選択"
    echo "5. 以下の操作を実行: 「AppleScriptを実行」を選び、「PhishingFilter」を選択"
    echo "6. 「OK」をクリック（既存のメッセージに適用するか聞かれたら、最初は「適用しない」推奨）"
    ;;

  enable-auto)
    interval="${2:-300}"
    if ! [[ "$interval" =~ ^[0-9]+$ ]] || [[ "$interval" -lt 60 ]]; then
      echo "エラー: 間隔は60以上の整数（秒）で指定してください（例: ./setup.sh enable-auto 300）" >&2
      exit 1
    fi
    mkdir -p "$HOME/Library/LaunchAgents" "$CONFIG_DIR"
    py_bin="/usr/bin/python3"
    if [[ -x "$PROJECT_DIR/.venv/bin/python3" ]]; then
      py_bin="$PROJECT_DIR/.venv/bin/python3"
    fi
    cat > "$LAUNCH_AGENT_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LAUNCH_AGENT_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$py_bin</string>
    <string>$PROJECT_DIR/scan_inbox.py</string>
    <string>--apply</string>
    <string>--if-mail-running</string>
    <string>--limit</string>
    <string>30</string>
  </array>
  <key>StartInterval</key>
  <integer>$interval</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$CONFIG_DIR/auto_scan.log</string>
  <key>StandardErrorPath</key>
  <string>$CONFIG_DIR/auto_scan.log</string>
</dict>
</plist>
EOF
    uid="$(id -u)"
    /bin/launchctl bootout "gui/$uid/$LAUNCH_AGENT_LABEL" >/dev/null 2>&1 || true
    /bin/launchctl bootstrap "gui/$uid" "$LAUNCH_AGENT_PLIST"
    echo "完了: バックグラウンド自動差分スキャンを有効化しました（${interval}秒おき・Mail.app起動中のみ実行）。"
    echo "  設定ファイル: $LAUNCH_AGENT_PLIST"
    echo "  実行ログ:     $CONFIG_DIR/auto_scan.log"
    ;;

  disable-auto)
    uid="$(id -u)"
    /bin/launchctl bootout "gui/$uid/$LAUNCH_AGENT_LABEL" >/dev/null 2>&1 || true
    rm -f "$LAUNCH_AGENT_PLIST"
    echo "完了: バックグラウンド自動差分スキャンを無効化しました。"
    ;;

  allow)
    domain="${2:-}"
    if [[ -z "$domain" ]]; then
      echo "エラー: ドメインを指定してください（例: ./setup.sh allow example.co.jp）" >&2
      exit 1
    fi
    /usr/bin/python3 "$PROJECT_DIR/phishing_analyzer.py" --init-config >/dev/null
    /usr/bin/python3 - "$CONFIG_FILE" "$domain" <<'PY'
import json, sys
from pathlib import Path

cfg_path = Path(sys.argv[1])
domain = sys.argv[2].strip().lower().lstrip("@.")
cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
wl = cfg.setdefault("whitelist_domains", [])
if domain not in wl:
    wl.append(domain)
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"追加しました: {domain}")
else:
    print(f"すでに登録済みです: {domain}")
PY
    ;;

  stats)
    days="${2:-7}"
    if [[ ! -f "$HISTORY_FILE" ]]; then
      echo "判定ログはまだありません ($HISTORY_FILE)"
      exit 0
    fi
    /usr/bin/python3 - "$HISTORY_FILE" "$CONFIG_DIR/applescript_error.log" "$days" <<'PY'
import datetime, json, sys
from collections import Counter
from pathlib import Path

hist_path = Path(sys.argv[1])
err_path = Path(sys.argv[2])
days = int(sys.argv[3])
cutoff_ts = int((datetime.datetime.now() - datetime.timedelta(days=days)).timestamp())

by_day = {}
recent_flagged = []
for line in hist_path.read_text(encoding="utf-8").splitlines():
    try:
        d = json.loads(line)
    except Exception:
        continue
    ts = int(d.get("ts", 0))
    if ts < cutoff_ts:
        continue
    day = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
    act = "ERROR" if d.get("verdict") == "error" else d.get("recommended_action", d.get("action", "OK"))
    by_day.setdefault(day, Counter())[act] += 1
    if act in ("JUNK", "SUSPICIOUS"):
        recent_flagged.append((
            datetime.datetime.fromtimestamp(ts).strftime("%m/%d %H:%M"),
            act,
            d.get("from", ""),
            d.get("subject", "")[:34],
            d.get("reason", "")[:50],
        ))

print(f"=== 直近 {days} 日間の稼働実績 ===")
if not by_day:
    print("  （該当期間の判定履歴なし）")
else:
    for day, c in sorted(by_day.items()):
        print(f"  {day} | 迷惑メール: {c['JUNK']:3d}件 | 要確認: {c['SUSPICIOUS']:3d}件 | 安全: {c['OK']:4d}件 | エラー: {c['ERROR']:3d}件")

print("\n=== 直近の迷惑メール・要確認 振り分け一覧（最大15件） ===")
if not recent_flagged:
    print("  （該当なし）")
else:
    for ts_s, act, frm, subj, reason in recent_flagged[-15:]:
        print(f"  {ts_s} [{act:10s}] From: {frm} | {subj}")
        if reason:
            print(f"      理由: {reason}")

if err_path.exists():
    err_lines = [l for l in err_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"\nAppleScriptエラーログ総行数: {len(err_lines)}行 ({err_path})")
PY
    ;;

  logs)
    count="${2:-20}"
    if [[ ! -f "$HISTORY_FILE" ]]; then
      echo "判定ログはまだありません ($HISTORY_FILE)"
      exit 0
    fi
    /usr/bin/python3 - "$HISTORY_FILE" "$count" <<'PY'
import datetime, json, sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
n = int(sys.argv[2])
for line in lines[-n:]:
    try:
        d = json.loads(line)
    except Exception:
        continue
    ts = datetime.datetime.fromtimestamp(d.get("ts", 0)).strftime("%m/%d %H:%M")
    act = d.get("recommended_action", d.get("action", "?"))
    conf = d.get("confidence", 0.0)
    brand = f" [{d['impersonated_brand']}]" if d.get("impersonated_brand") else ""
    print(f"{ts} | {act:10s} ({conf:.2f}){brand} | From: {d.get('from','')} | {d.get('subject','')[:35]}")
    print(f"       理由: {d.get('reason','')}")
PY
    ;;

  status)
    echo "プロジェクト: $PROJECT_DIR"
    if [[ -f "$SCPT_TARGET" ]]; then
      echo "Mail.appスクリプト: 配置済み ($SCPT_TARGET)"
    else
      echo "Mail.appスクリプト: 未配置（./setup.sh install を実行してください）"
    fi
    if [[ -f "$LAUNCH_AGENT_PLIST" ]]; then
      echo "定期自動スキャン(launchd): 有効 ($LAUNCH_AGENT_PLIST)"
    else
      echo "定期自動スキャン(launchd): 無効（./setup.sh enable-auto で有効化可能）"
    fi
    if /usr/bin/security find-generic-password -s "$KEYCHAIN_SERVICE" -w >/dev/null 2>&1; then
      echo "Gemini APIキー: キーチェーンに設定済み"
    else
      echo "Gemini APIキー: 未設定（./setup.sh set-key を実行してください）"
    fi
    if [[ -f "$CONFIG_FILE" ]]; then
      echo "設定ファイル: $CONFIG_FILE"
    else
      echo "設定ファイル: 未作成（初回実行時に自動生成）"
    fi
    if [[ -f "$CONFIG_DIR/scan_state.json" ]]; then
      echo "前回スキャン基準日時 ($CONFIG_DIR/scan_state.json):"
      /usr/bin/python3 - "$CONFIG_DIR/scan_state.json" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for acc, info in data.get("accounts", {}).items():
    print(f"  - {acc}: {info.get('last_received_iso', '(なし)')} (更新: {info.get('updated_at', '')})")
PY
    else
      echo "前回スキャン基準日時: 未保存（次回 --apply 実行時に記録されます）"
    fi
    ;;

  *)
    usage
    exit 1
    ;;
esac
