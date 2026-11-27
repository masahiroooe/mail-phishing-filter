#!/usr/bin/env python3
"""
Mac標準「メール」アプリ向け AIフィッシング判定 CLI エントリポイント。

コアロジックは `mail_phishing_filter/` パッケージに機能別に分割されています。
後方互換のため、主要シンボルもこのモジュールから再エクスポートしています。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from mail_phishing_filter import (
    API_KEY_FILE,
    CACHE_DB_PATH,
    CONFIG_DIR,
    CONFIG_PATH,
    DEFAULT_CONFIG,
    HISTORY_LOG_PATH,
    KEYCHAIN_SERVICE,
    RetryableAPIError,
    analyze_email_bytes,
    analyze_emails_batch,
    call_gemini_with_retry,
    compute_content_fingerprint,
    decide_action,
    detect_obvious_nonsense,
    format_applescript_line,
    get_api_key,
    is_whitelisted,
    load_config,
    parse_raw_email,
    save_default_config_if_missing,
)

__all__ = [
    "API_KEY_FILE",
    "CACHE_DB_PATH",
    "CONFIG_DIR",
    "CONFIG_PATH",
    "DEFAULT_CONFIG",
    "HISTORY_LOG_PATH",
    "KEYCHAIN_SERVICE",
    "RetryableAPIError",
    "analyze_email_bytes",
    "analyze_emails_batch",
    "call_gemini_with_retry",
    "compute_content_fingerprint",
    "decide_action",
    "detect_obvious_nonsense",
    "format_applescript_line",
    "get_api_key",
    "is_whitelisted",
    "load_config",
    "main",
    "parse_raw_email",
    "save_default_config_if_missing",
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gemini AI フィッシングメール判定ツール")
    parser.add_argument("eml_paths", nargs="*", help="解析する.emlファイルパス（省略時は標準入力）")
    parser.add_argument("--batch", action="store_true", help="複数ファイルをバッチ判定し、入力順に1行ずつ出力")
    parser.add_argument("--batch-size", type=int, default=None, help="1リクエストあたりの最大まとめ件数（デフォルト: 10）")
    parser.add_argument("--json", action="store_true", help="詳細なJSON形式で出力")
    parser.add_argument("--dry-run", action="store_true", help="判定のみ行い、実行アクションは常にOKを返す")
    parser.add_argument("--no-cache", action="store_true", help="キャッシュを使わずに再判定する")
    parser.add_argument("--init-config", action="store_true", help="デフォルト設定ファイルを生成して終了")
    args = parser.parse_args(argv)

    save_default_config_if_missing()
    if args.init_config:
        print(str(CONFIG_PATH))
        return 0

    cfg = load_config()

    if args.batch or len(args.eml_paths) > 1:
        if not args.eml_paths:
            print("エラー: --batch 時は1つ以上の .eml ファイルを指定してください。", file=sys.stderr)
            return 1
        raw_list = [Path(p).read_bytes() for p in args.eml_paths]
        res_list = analyze_emails_batch(
            raw_list,
            cfg,
            use_cache=not args.no_cache,
            dry_run=args.dry_run,
            batch_size=args.batch_size,
        )
        if args.json:
            print(json.dumps(res_list, ensure_ascii=False, indent=2))
        else:
            for res in res_list:
                print(format_applescript_line(res))
        return 0

    raw_bytes = Path(args.eml_paths[0]).read_bytes() if args.eml_paths else sys.stdin.buffer.read()
    result = analyze_email_bytes(
        raw_bytes,
        cfg,
        use_cache=not args.no_cache,
        dry_run=args.dry_run,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(format_applescript_line(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
