#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAIL_SCRIPTS_DIR="$HOME/Library/Application Scripts/com.apple.mail"
SCPT_TARGET="$MAIL_SCRIPTS_DIR/PhishingFilter.scpt"
CONFIG_DIR="$HOME/.config/mail-phishing-filter"
CONFIG_FILE="$CONFIG_DIR/config.json"
HISTORY_FILE="$CONFIG_DIR/history.jsonl"
KEYCHAIN_SERVICE="mail-phishing-filter-gemini-api-key"

usage() {
  cat <<'EOF'
使い方:
  ./setup.sh set-key          Gemini APIキーをmacOSキーチェーンに安全に保存
  ./setup.sh install          Mail.app ルール用スクリプトをコンパイル＆配置
  ./setup.sh allow <domain>   信頼済みドメインをホワイトリストに追加
  ./setup.sh logs [N]         直近N件（デフォルト20件）の判定ログを表示
  ./setup.sh status           設定・インストール状態を確認
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
