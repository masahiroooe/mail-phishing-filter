# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-27

Mac標準「メール」アプリ（Mail.app）向け AIフィッシング自動振り分けツールの初回リリースです。
Xcode や有料の開発者署名なしで導入でき、Mail.app に登録されている全アカウント（IMAP / POP / Gmail / iCloud 等）に対応します。

### Added
- **AIフィッシング・なりすまし判定エンジン (`mail_phishing_filter/`)**
  - RFC 2822 生メールから From 表示名偽装、Return-Path/Reply-To 不一致、SPF/DKIM/DMARC 認証、HTMLリンクの表示URLと実遷移先の不一致、Punycode (`xn--`) を抽出。
  - Gemini Interactions API（`gemini-3.5-flash-lite`, `store=False`, Structured Output）による単体・バッチ一括判定（既定10通/リクエスト）と HTTP 429/503 の指数バックオフ自動リトライ。
  - `google-genai` SDK 優先・Python 標準ライブラリ（`urllib.request`）フォールバックにより追加依存なしでも動作。
- **API 消費ゼロのローカル無条件スパム検知**
  - 同一送信元アドレスからの単位時間内大量送信（既定：10分間8通以上）。
  - 異なる送信元アドレスを含む同一内容の大量送信（URL・数字を正規化、既定：60分間3通以上・送信元2件以上）。
  - 空メール・ランダム文字列・文字化け・同一文字の異常反復などの無意味メール検知（添付付き・返信/転送・画像付きHTMLの誤爆防止あり）。
- **差分スキャン CLI (`scan_inbox.py`)**
  - アカウントごとに前回スキャン日時（秒単位）を `~/.config/mail-phishing-filter/scan_state.json` に保持し、2回目以降は新着メールのみを高速処理。
  - `--dry-run` / `--apply` / `--selected` / `--account` / `--batch-size` / `--since-days` / `--reset-state` オプション対応。
  - `--apply` 時はアカウント単位で1回の AppleScript 起動により一括移動・ハイライトを実行。
- **Mail.app ルール連携 (`mail_rule.applescript`) と管理スクリプト (`setup.sh`)**
  - `./setup.sh set-key` で Gemini API キーを macOS キーチェーンへ安全に保存。
  - `./setup.sh install` で配置パスを動的展開し、`~/Library/Application Scripts/com.apple.mail/PhishingFilter.scpt` へコンパイル配置。
  - `./setup.sh allow <domain>` / `logs` / `status` コマンドを提供。
- **保守性・ドキュメント・テスト**
  - 循環依存のない単一責任モジュール構成（`config`, `storage`, `email_parser`, `local_rules`, `gemini_client`, `analyzer`, `mail_applescript`）。
  - モジュール単位の機能仕様書 `mail_phishing_filter/README.md`、ルート `README.md`、`LICENSE`（MIT License）、`.gitignore` を整備。
  - Python 3.12 および macOS 標準 `/usr/bin/python3`（3.9）双方で全18件のユニットテストを実装・検証。

### Security
- コマンドインジェクション / RCE 対策：`eval` / `exec` / `pickle` / `shell=True` 不使用、UUIDパス＋`quoted form of`＋配列引数のみ使用。
- 行インジェクション・パストラバーサル対策：AppleScript ダンプ出力から攻撃者制御可能な件名・差出人を排除し、ファイル名パターン（`^(msg|sel)_\d+_\d+\.eml$`）と一時ディレクトリ直下解決を厳密検証。
- SQL インジェクション対策：全 SQLite クエリでパラメータバインド（`?`）を使用（1バッチ1接続セッション管理）。
- SSRF・プロンプトインジェクション対策：メール内 URL への自動アクセスなし、Gemini API のツール実行無効・固定エンドポイントのみ通信。
- 認証情報・一時ファイル保護：API キーは macOS キーチェーン管理、Mail.app ルールの一時ファイルはユーザー専用プライベート一時ディレクトリ（`path to temporary items from user domain`）へ書き出し処理後即削除。
- DoS 対策：HTML・プレーンテキスト解析対象を各 200KB に上限キャップ。
- 公開前監査により個人情報・ローカル絶対パス・機密情報がリポジトリ内に含まれないことを確認済み。

### Notes
- 本リポジトリのコードおよびドキュメントは生成AIを活用して作成・編集されています。
- 個人利用の範囲を想定した公開であり、商用・業務運用等のサポートや動作保証は行いません。すべて自己責任にてご利用ください。
