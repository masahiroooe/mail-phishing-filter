#!/usr/bin/env python3
"""phishing_analyzer.py のユニットテスト（オフライン実行可能）"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import phishing_analyzer as pa
import scan_inbox as si


SAMPLE_PHISHING_EML = """\
From: =?UTF-8?B?5LiJ5LqV5L2P5Y+L44Kr44O844OJ?= <info@random-promo-8821.example>
To: user@example.jp
Reply-To: support@urgent-verify-card.example
Return-Path: <bounce@random-promo-8821.example>
Subject: =?UTF-8?B?44CQ6YeN6KaB44CR44Kr44O844OJ44Gu44GU5Yip55So44KS5LiA5pmC5YGc5q2i44GX44G+44GX44Gf?=
Date: Fri, 27 Nov 2026 09:30:00 +0900
Message-ID: <phish-test-001@random-promo-8821.example>
Authentication-Results: mx.example.jp; spf=fail smtp.mailfrom=random-promo-8821.example; dkim=none; dmarc=fail
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<html><body>
<p>三井住友カードをご利用いただきありがとうございます。</p>
<p>不審な取引を検知したため、24時間以内に以下より本人確認を行ってください。</p>
<a href="https://xn--card-verify-991.example/login">https://www.smbc-card.com/mem/login</a>
</body></html>
""".encode("utf-8")

SAMPLE_LEGIT_EML = b"""\
From: GitHub <noreply@github.com>
To: user@example.com
Return-Path: <noreply@github.com>
Subject: [GitHub] A new device signed in
Date: Fri, 27 Nov 2026 09:40:00 +0900
Message-ID: <legit-test-001@github.com>
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi there,
You signed in from a new device. Review your security settings at https://github.com/settings/security.
"""


class TestPhishingAnalyzer(unittest.TestCase):
    def test_parse_phishing_features(self) -> None:
        cfg = dict(pa.DEFAULT_CONFIG)
        parsed = pa.parse_raw_email(SAMPLE_PHISHING_EML, cfg)

        self.assertEqual(parsed["from_name"], "三井住友カード")
        self.assertEqual(parsed["from_addr"], "info@random-promo-8821.example")
        self.assertEqual(parsed["from_domain"], "random-promo-8821.example")
        self.assertEqual(parsed["reply_to_domain"], "urgent-verify-card.example")
        self.assertEqual(parsed["auth"]["spf"], "fail")
        self.assertEqual(parsed["auth"]["dmarc"], "fail")
        self.assertEqual(len(parsed["links"]), 1)
        self.assertTrue(parsed["links"][0]["display_url_mismatch"])
        self.assertTrue(parsed["links"][0]["is_punycode"])
        self.assertTrue(
            any("SPF認証失敗" in note for note in parsed["heuristic_notes"])
        )
        self.assertTrue(
            any("表示URL" in note for note in parsed["heuristic_notes"])
        )

    def test_whitelist_requires_auth(self) -> None:
        cfg = dict(pa.DEFAULT_CONFIG)
        cfg["whitelist_domains"] = ["github.com", "random-promo-8821.example"]
        cfg["whitelist_require_auth"] = True

        legit = pa.parse_raw_email(SAMPLE_LEGIT_EML, cfg)
        self.assertTrue(pa.is_whitelisted(legit, cfg))

        # SPF/DMARC fail の場合はホワイトリストにドメインがあっても通過させない
        phish = pa.parse_raw_email(SAMPLE_PHISHING_EML, cfg)
        self.assertFalse(pa.is_whitelisted(phish, cfg))

    def test_end_to_end_with_mock_gemini_phishing(self) -> None:
        def fake_gemini(api_key: str, model: str, prompt: str, timeout: int):
            self.assertIn("三井住友カード", prompt)
            self.assertIn("random-promo-8821.example", prompt)
            return {
                "verdict": "phishing",
                "confidence": 0.98,
                "impersonated_brand": "三井住友カード",
                "signals": ["送信元ドメイン不一致", "SPF/DMARC認証失敗", "リンク先URL偽装"],
                "reason": "三井住友カードを名乗るが送信元と遷移先が無関係なドメイン",
            }

        res = pa.analyze_email_bytes(
            SAMPLE_PHISHING_EML,
            dict(pa.DEFAULT_CONFIG),
            api_key="dummy-key",
            use_cache=False,
            write_log=False,
            caller_fn=fake_gemini,
        )
        self.assertEqual(res["action"], "JUNK")
        self.assertEqual(res["recommended_action"], "JUNK")
        line = pa.format_applescript_line(res)
        self.assertTrue(line.startswith("JUNK|0.98|phishing|三井住友カード|"))

    def test_suspicious_threshold_and_dry_run(self) -> None:
        def fake_suspicious(api_key: str, model: str, prompt: str, timeout: int):
            return {
                "verdict": "suspicious",
                "confidence": 0.72,
                "impersonated_brand": "運送会社",
                "signals": ["不自然なURL"],
                "reason": "やや不自然な不在通知",
            }

        res = pa.analyze_email_bytes(
            SAMPLE_PHISHING_EML,
            dict(pa.DEFAULT_CONFIG),
            api_key="dummy-key",
            use_cache=False,
            write_log=False,
            caller_fn=fake_suspicious,
        )
        self.assertEqual(res["action"], "SUSPICIOUS")

        res_dry = pa.analyze_email_bytes(
            SAMPLE_PHISHING_EML,
            dict(pa.DEFAULT_CONFIG),
            api_key="dummy-key",
            use_cache=False,
            dry_run=True,
            write_log=False,
            caller_fn=fake_suspicious,
        )
        self.assertEqual(res_dry["action"], "OK")
        self.assertEqual(res_dry["recommended_action"], "SUSPICIOUS")

    def test_failsafe_on_api_error(self) -> None:
        def failing_gemini(api_key: str, model: str, prompt: str, timeout: int):
            raise RuntimeError("network timeout")

        res = pa.analyze_email_bytes(
            SAMPLE_PHISHING_EML,
            dict(pa.DEFAULT_CONFIG),
            api_key="dummy-key",
            use_cache=False,
            write_log=False,
            caller_fn=failing_gemini,
        )
        self.assertEqual(res["action"], "ERROR")
        self.assertEqual(res["recommended_action"], "OK")

    def test_failsafe_when_no_api_key(self) -> None:
        res = pa.analyze_email_bytes(
            SAMPLE_PHISHING_EML,
            dict(pa.DEFAULT_CONFIG),
            api_key="",
            use_cache=False,
            write_log=False,
        )
        self.assertEqual(res["action"], "ERROR")
        self.assertEqual(res["recommended_action"], "OK")

    def test_scan_state_watermark_progression(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "scan_state.json"
            state = si.load_scan_state(state_path)
            self.assertEqual(state, {"accounts": {}})

            # 初回記録
            self.assertTrue(
                si.update_account_watermark(state, "So-net", "2026-11-27 10:20:30")
            )
            si.save_scan_state(state, state_path)

            loaded = si.load_scan_state(state_path)
            self.assertEqual(
                loaded["accounts"]["So-net"]["last_received_iso"],
                "2026-11-27 10:20:30",
            )

            # 古い日時や同一日時では上書きしない
            self.assertFalse(
                si.update_account_watermark(loaded, "So-net", "2026-11-27 10:20:29")
            )
            self.assertFalse(
                si.update_account_watermark(loaded, "So-net", "2026-11-27 10:20:30")
            )

            # 1秒でも新しければ更新する
            self.assertTrue(
                si.update_account_watermark(loaded, "So-net", "2026-11-27 10:20:31")
            )
            self.assertEqual(
                loaded["accounts"]["So-net"]["last_received_iso"],
                "2026-11-27 10:20:31",
            )

    def test_batch_analysis_single_request_and_brand_cleanup(self) -> None:
        calls = {"count": 0}

        def fake_batch_gemini(api_key: str, model: str, prompt: str, timeout: int):
            calls["count"] += 1
            return {
                "results": [
                    {
                        "index": 0,
                        "verdict": "phishing",
                        "confidence": 0.97,
                        "impersonated_brand": "三井住友カード",
                        "signals": ["送信元ドメイン不一致"],
                        "reason": "偽のカード停止通知",
                    },
                    {
                        "index": 1,
                        "verdict": "legitimate",
                        "confidence": 0.99,
                        "impersonated_brand": "GitHub",  # legitimate時は自動クリアされるべき
                        "signals": ["公式ドメインかつSPF/DKIM通過"],
                        "reason": "正規のセキュリティ通知",
                    },
                ]
            }

        results = pa.analyze_emails_batch(
            [SAMPLE_PHISHING_EML, SAMPLE_LEGIT_EML],
            dict(pa.DEFAULT_CONFIG),
            api_key="dummy-key",
            use_cache=False,
            write_log=False,
            batch_size=10,
            caller_fn=fake_batch_gemini,
            sleep_fn=lambda _: None,
        )
        self.assertEqual(calls["count"], 1)  # 2通が1リクエストにまとまった
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["action"], "JUNK")
        self.assertEqual(results[0]["impersonated_brand"], "三井住友カード")
        self.assertEqual(results[1]["action"], "OK")
        self.assertEqual(results[1]["impersonated_brand"], "")

    def test_retry_on_429_and_503(self) -> None:
        attempts = {"n": 0}
        slept: list[float] = []

        def flaky_gemini(api_key: str, model: str, prompt: str, timeout: int):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise pa.RetryableAPIError("Gemini API HTTP 429: Rate limit exceeded", retry_after=2.0)
            if attempts["n"] == 2:
                raise pa.RetryableAPIError("Gemini API HTTP 503: high demand")
            return {
                "verdict": "phishing",
                "confidence": 0.95,
                "impersonated_brand": "三井住友カード",
                "signals": ["送信元不一致"],
                "reason": "偽装メール",
            }

        res = pa.analyze_email_bytes(
            SAMPLE_PHISHING_EML,
            dict(pa.DEFAULT_CONFIG),
            api_key="dummy-key",
            use_cache=False,
            write_log=False,
            caller_fn=flaky_gemini,
            sleep_fn=lambda sec: slept.append(sec),
        )
        self.assertEqual(attempts["n"], 3)
        self.assertEqual(len(slept), 2)
        self.assertEqual(res["action"], "JUNK")

    def test_sender_flood_unconditional_junk_without_api(self) -> None:
        api_calls = {"count": 0}

        def should_not_be_called(*args, **kwargs):
            api_calls["count"] += 1
            return {
                "verdict": "legitimate",
                "confidence": 0.99,
                "impersonated_brand": "",
                "signals": [],
                "reason": "ok",
            }

        def make_eml(idx: int, minute: int, sender: str = "burst@spammer.example") -> bytes:
            return (
                f"From: Promo <{sender}>\n"
                f"To: user@example.com\n"
                f"Subject: Offer #{idx}\n"
                f"Date: Fri, 27 Nov 2026 10:{minute:02d}:00 +0900\n"
                f"Message-ID: <burst-{idx}@spammer.example>\n"
                f"MIME-Version: 1.0\n"
                f"Content-Type: text/plain; charset=UTF-8\n\n"
                f"Special offer number {idx}\n"
            ).encode("utf-8")

        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "cache.sqlite3"
            cfg = dict(pa.DEFAULT_CONFIG)
            cfg["flood_window_seconds"] = 600  # 10分
            cfg["flood_threshold"] = 5         # テスト用に5通以上

            # 1) 10分以内に5通連投 → API呼び出しゼロで全件無条件 JUNK
            burst_emls = [make_eml(i, minute=10 + i) for i in range(5)]
            results = pa.analyze_emails_batch(
                burst_emls,
                cfg,
                api_key="dummy-key",
                use_cache=False,
                write_log=False,
                cache_db_path=db_path,
                caller_fn=should_not_be_called,
            )
            self.assertEqual(api_calls["count"], 0)
            self.assertTrue(all(r["action"] == "JUNK" for r in results))
            self.assertTrue(all(r["model"] == "rule:sender-flood" for r in results))

            # 2) 同じ送信元でも30分以上離れた単発メールは通常判定（API呼び出しあり）
            later_eml = make_eml(99, minute=55)
            later_res = pa.analyze_emails_batch(
                [later_eml],
                cfg,
                api_key="dummy-key",
                use_cache=False,
                write_log=False,
                cache_db_path=db_path,
                caller_fn=should_not_be_called,
            )
            self.assertEqual(api_calls["count"], 1)
            self.assertEqual(later_res[0]["action"], "OK")

            # 3) 同一 Message-ID の再スキャンでは件数が水増しされない
            again_res = pa.analyze_emails_batch(
                [later_eml],
                cfg,
                api_key="dummy-key",
                use_cache=False,
                write_log=False,
                cache_db_path=db_path,
                caller_fn=should_not_be_called,
            )
            self.assertEqual(again_res[0]["action"], "OK")

    def test_different_senders_same_content_flood_without_api(self) -> None:
        api_calls = {"count": 0}

        def should_not_be_called(*args, **kwargs):
            api_calls["count"] += 1
            return {
                "verdict": "legitimate",
                "confidence": 0.99,
                "impersonated_brand": "",
                "signals": [],
                "reason": "ok",
            }

        # 毎回異なる送信元・異なるURL・異なる受付番号だが、本文テンプレートは同一
        emls = []
        for i, dom in enumerate(("spam-a.example", "spam-b.example", "spam-c.example")):
            emls.append(
                (
                    f"From: お知らせ <info@rnd{i}.{dom}>\n"
                    f"To: user@example.com\n"
                    f"Subject: ご案内内容のご確認をお願いします ({i + 1})\n"
                    f"Date: Fri, 27 Nov 2026 10:{10 + i * 5:02d}:00 +0900\n"
                    f"Message-ID: <same-body-{i}@{dom}>\n"
                    f"MIME-Version: 1.0\n"
                    f"Content-Type: text/plain; charset=UTF-8\n\n"
                    f"いつもご利用いただきありがとうございます。お客様のご契約内容について重要な確認事項がございます。\n"
                    f"受付番号: 9000{i} 以下のリンクより24時間以内にご確認ください。\n"
                    f"https://login-{i}.{dom}/verify?id=88{i}\n"
                ).encode("utf-8")
            )

        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "cache.sqlite3"
            cfg = dict(pa.DEFAULT_CONFIG)
            results = pa.analyze_emails_batch(
                emls,
                cfg,
                api_key="dummy-key",
                use_cache=False,
                write_log=False,
                cache_db_path=db_path,
                caller_fn=should_not_be_called,
            )
            self.assertEqual(api_calls["count"], 0)
            self.assertTrue(all(r["action"] == "JUNK" for r in results))
            self.assertTrue(all(r["model"] == "rule:content-flood" for r in results))

    def test_obvious_nonsense_emails_junk_without_api(self) -> None:
        api_calls = {"count": 0}

        def fake_gemini(*args, **kwargs):
            api_calls["count"] += 1
            return {
                "verdict": "legitimate",
                "confidence": 0.99,
                "impersonated_brand": "",
                "signals": [],
                "reason": "ok",
            }

        random_gibberish = (
            "From: nobody@weird.example\n"
            "To: user@example.com\n"
            "Subject: xk92a\n"
            "Date: Fri, 27 Nov 2026 10:00:00 +0900\n"
            "Message-ID: <gib-1@weird.example>\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain; charset=UTF-8\n\n"
            "a8fK29dPqLmN7vXzQ1wErTyUiOpAsDfGhJkLzXcVbNm0123456789qWeRtYuIoPaSdFgHjKlZxCvBnM\n"
        ).encode("utf-8")

        empty_mail = (
            "From: empty@weird.example\n"
            "To: user@example.com\n"
            "Subject:   \n"
            "Date: Fri, 27 Nov 2026 10:01:00 +0900\n"
            "Message-ID: <empty-1@weird.example>\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain; charset=UTF-8\n\n"
            "   \n"
        ).encode("utf-8")

        # 短い正規の返信はローカルで誤爆せず Gemini に渡ること
        short_reply = (
            "From: friend@example.org\n"
            "To: user@example.com\n"
            "Subject: Re: 明日の件\n"
            "Date: Fri, 27 Nov 2026 10:02:00 +0900\n"
            "Message-ID: <reply-1@example.org>\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain; charset=UTF-8\n\n"
            "了解です！\n"
        ).encode("utf-8")

        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "cache.sqlite3"
            cfg = dict(pa.DEFAULT_CONFIG)
            results = pa.analyze_emails_batch(
                [random_gibberish, empty_mail, short_reply],
                cfg,
                api_key="dummy-key",
                use_cache=False,
                write_log=False,
                cache_db_path=db_path,
                caller_fn=fake_gemini,
            )
            self.assertEqual(results[0]["action"], "JUNK")
            self.assertEqual(results[0]["model"], "rule:nonsense")
            self.assertEqual(results[1]["action"], "JUNK")
            self.assertEqual(results[1]["model"], "rule:nonsense")
            # 短い正規返信だけ Gemini に渡り、OKになる
            self.assertEqual(api_calls["count"], 1)
            self.assertEqual(results[2]["action"], "OK")


if __name__ == "__main__":
    unittest.main()
