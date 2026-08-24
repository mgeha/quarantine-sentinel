import io
import threading
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import quarantine_sentinel as qs
import update_rcpt_ignore


class RecipientIgnoreTests(unittest.TestCase):
    def test_matches_address_case_insensitively(self):
        ignored = qs._parse_rcpt_ignore(
            [" ignored@example.com ", "Second@Example.com"]
        )
        self.assertTrue(qs.is_ignored_recipient("IGNORED@example.com", ignored))
        self.assertTrue(qs.is_ignored_recipient("second@example.COM", ignored))
        self.assertFalse(qs.is_ignored_recipient("other@example.com", ignored))

    def test_rejects_non_list_configuration(self):
        with self.assertRaises(SystemExit) as raised:
            qs._parse_rcpt_ignore("ignored@example.com")
        self.assertEqual(
            str(raised.exception),
            "Config error: rcpt_ignore must be a list of e-mail addresses"
        )

    def test_appends_selected_recipients_to_multiline_config(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(
                'rcpt_ignore = [\n  "existing@example.com",\n]\n\n[pmg]\n',
                encoding="utf-8",
            )
            update_rcpt_ignore.add_recipients_to_config(
                path, ["new@example.com", "second@example.com"]
            )
            content = path.read_text(encoding="utf-8")
            self.assertIn('  "existing@example.com",', content)
            self.assertIn('  "new@example.com",', content)
            self.assertIn('  "second@example.com",', content)
            self.assertLess(content.index("second@example.com"), content.index("[pmg]"))

    def test_yes_prompt_defaults_to_no(self):
        with patch("builtins.input", return_value=""):
            self.assertFalse(update_rcpt_ignore.wants_to_ignore("user@example.com"))
        with patch("builtins.input", return_value="ja"):
            self.assertTrue(update_rcpt_ignore.wants_to_ignore("user@example.com"))


class ConfigValidationTests(unittest.TestCase):
    MINIMAL = (
        '[pmg]\nurl = "https://pmg.example.com:8006"\n'
        'username = "u@pam"\npassword = "p"\n'
        '[llm]\nbackend = "ollama"\nmodel = "m"\n'
    )

    def _load(self, extra=""):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(extra + self.MINIMAL, encoding="utf-8")
            return qs.load_config(str(path))

    def _assert_rejected(self, setting, needle):
        with self.assertRaises(SystemExit) as raised:
            self._load(setting + "\n")
        self.assertIn(needle, str(raised.exception))

    def test_rejects_zero_workers(self):
        # min(0, len(pending)) would abort ThreadPoolExecutor at run time.
        self._assert_rejected("max_workers = 0", "max_workers must be >= 1")

    def test_rejects_negative_mail_cap(self):
        # A negative cap makes `len(pending) >= cap` true immediately, so the
        # run would silently score nothing at all.
        self._assert_rejected(
            "max_mails_per_run = -1", "max_mails_per_run must be >= 1"
        )

    def test_rejects_negative_body_limit(self):
        # text[:-100] truncates from the wrong end instead of capping length.
        self._assert_rejected("body_max_chars = -100", "body_max_chars must be >= 1")

    def test_rejects_negative_lookback(self):
        # now - timedelta(days=-7) is a window in the future.
        self._assert_rejected("lookback_days = -7", "lookback_days must be >= 1")

    def test_rejects_threshold_above_one(self):
        self._assert_rejected(
            "confidence_threshold = 1.5",
            "confidence_threshold must be between 0.0 and 1.0",
        )

    def test_rejects_threshold_below_zero(self):
        self._assert_rejected(
            "confidence_threshold = -0.1",
            "confidence_threshold must be between 0.0 and 1.0",
        )

    def test_rejects_negative_pacing_interval(self):
        self._assert_rejected(
            "sleep_between_requests = -1.0", "sleep_between_requests must be >= 0.0"
        )

    def test_rejects_non_numeric_value_without_traceback(self):
        self._assert_rejected('lookback_days = "soon"', "lookback_days must be a number")

    def test_rejects_boolean_dressed_as_number(self):
        self._assert_rejected("max_workers = true", "max_workers must be a number")

    def _assert_config_rejected(self, text, needle):
        with self.assertRaises(SystemExit) as raised:
            with TemporaryDirectory() as directory:
                path = Path(directory) / "config.toml"
                path.write_text(text, encoding="utf-8")
                qs.load_config(str(path))
        self.assertIn(needle, str(raised.exception))

    def _config(self, pmg=None, llm=None, top=""):
        """Render a complete config, with per-table TOML overrides applied."""
        tables = {
            "pmg": {
                "url": '"https://pmg.example.com:8006"',
                "username": '"u@pam"',
                "password": '"p"',
            },
            "llm": {"backend": '"ollama"', "model": '"m"'},
        }
        tables["pmg"].update(pmg or {})
        tables["llm"].update(llm or {})
        return top + "".join(
            f"[{name}]\n" + "".join(f"{k} = {v}\n" for k, v in table.items())
            for name, table in tables.items()
        )

    def test_rejects_fractional_worker_count(self):
        self._assert_rejected("max_workers = 1.9", "max_workers must be a whole number")

    def test_rejects_non_finite_threshold(self):
        self._assert_rejected(
            "confidence_threshold = nan", "confidence_threshold must be a finite number"
        )

    def test_rejects_infinite_pacing_interval(self):
        self._assert_rejected(
            "sleep_between_requests = inf",
            "sleep_between_requests must be a finite number",
        )

    def test_rejects_non_string_pmg_settings(self):
        for key, needle in (
            ("url", "[pmg].url must be a string"),
            ("username", "[pmg].username must be a string"),
            ("password", "[pmg].password must be a string"),
        ):
            with self.subTest(key=key):
                self._assert_config_rejected(self._config(pmg={key: "8006"}), needle)

    def test_rejects_non_string_llm_settings(self):
        for key, needle in (
            ("backend", "[llm].backend must be a string"),
            ("model", "[llm].model must be a string"),
            ("ollama_url", "[llm].ollama_url must be a string"),
        ):
            with self.subTest(key=key):
                self._assert_config_rejected(self._config(llm={key: "11434"}), needle)

    def test_rejects_stringly_typed_verify_ssl(self):
        # bool("false") is True, the exact opposite of what was configured.
        self._assert_config_rejected(
            self._config(pmg={"verify_ssl": '"false"'}),
            "[pmg].verify_ssl must be true or false",
        )

    def test_rejects_non_string_db_path(self):
        self._assert_rejected("db_path = 5", "db_path must be a string")

    def test_rejects_scalar_where_table_expected(self):
        self._assert_config_rejected('llm = "ollama"\n', "[llm] must be a table")

    def test_accepts_integral_float_worker_count(self):
        self.assertEqual(self._load("max_workers = 4.0\n").max_workers, 4)

    def test_accepts_inclusive_threshold_bounds(self):
        self.assertEqual(self._load("confidence_threshold = 0.0\n").confidence_threshold, 0.0)
        self.assertEqual(self._load("confidence_threshold = 1.0\n").confidence_threshold, 1.0)

    def test_accepts_zero_pacing_interval(self):
        self.assertEqual(self._load("sleep_between_requests = 0\n").sleep_between_requests, 0.0)

    def test_applies_documented_defaults_when_keys_absent(self):
        cfg = self._load()
        self.assertEqual(cfg.lookback_days, 7)
        self.assertEqual(cfg.confidence_threshold, 0.70)
        self.assertEqual(cfg.max_mails_per_run, 200)
        self.assertEqual(cfg.max_workers, 5)
        self.assertEqual(cfg.sleep_between_requests, 0.5)

    def test_accepts_valid_overrides(self):
        cfg = self._load(
            "lookback_days = 3\nmax_workers = 1\nmax_mails_per_run = 10\n"
            "body_max_chars = 500\nconfidence_threshold = 0.9\n"
            "sleep_between_requests = 2.5\n"
        )
        self.assertEqual(
            (cfg.lookback_days, cfg.max_workers, cfg.max_mails_per_run,
             cfg.body_max_chars, cfg.confidence_threshold, cfg.sleep_between_requests),
            (3, 1, 10, 500, 0.9, 2.5),
        )


class AuthenticationContextTests(unittest.TestCase):
    def test_extracts_case_insensitive_folded_spam_rules(self):
        raw = (
            "x-spam-level: SPF_FAIL 3.000 sender SPF failed\r\n"
            "\tDKIM_INVALID 2.000 signature invalid\r\n"
            "Subject: ordinary message\r\n\r\nHello"
        )
        rules = qs.extract_spam_rules(raw)
        self.assertIn("SPF_FAIL", rules)
        self.assertIn("DKIM_INVALID", rules)

    def test_extracts_and_unfolds_all_authentication_results(self):
        raw = (
            "Authentication-Results: mx.example; spf=fail smtp.mailfrom=a.example;\r\n"
            " dkim=fail header.d=a.example\r\n"
            "Authentication-Results: forwarder.example; arc=pass\r\n\r\nHello"
        )
        results = qs.extract_authentication_results(raw)
        self.assertIn("spf=fail", results)
        self.assertIn("dkim=fail", results)
        self.assertIn("arc=pass", results)
        self.assertNotIn("\r\n ", results)

    def test_prompt_labels_authentication_as_context(self):
        prompt = qs._build_prompt(
            {"subject": "SPAM: legitimate forwarded mail"},
            "Expected invoice",
            "  SPF_FAIL 3.000 sender SPF failed",
            "mx.example; spf=fail; dkim=fail; arc=pass",
        )
        self.assertIn("context only; not a verdict", prompt)
        self.assertIn("arc=pass", prompt)

    def test_system_prompt_rejects_circular_gateway_prefix_evidence(self):
        self.assertIn("circular evidence", qs._SYSTEM_PROMPT)
        self.assertIn("must not affect the verdict", qs._SYSTEM_PROMPT)

    def test_extracts_topmost_received_header_only(self):
        raw = (
            "Received: from evil.example (unknown [203.0.113.9])\r\n"
            "\tby mail.example with ESMTP id 1;\r\n"
            "\tMon, 1 Jan 2026 00:00:00 +0000\r\n"
            "Received: from inner.example by evil.example;\r\n"
            "\tMon, 1 Jan 2026 00:00:00 +0000\r\n"
            "Subject: fake invoice\r\n\r\nHello"
        )
        infra = qs.extract_sending_infra(raw)
        self.assertIn("evil.example", infra)
        self.assertIn("unknown [203.0.113.9]", infra)
        self.assertNotIn("inner.example", infra)

    def test_prompt_includes_sending_infra_section(self):
        prompt = qs._build_prompt(
            {"subject": "SPAM: order confirmation"},
            "Expected invoice",
            sending_infra="from throwaway.example (unknown [198.51.100.1])",
        )
        self.assertIn("cannot be forged by the sender", prompt)
        self.assertIn("throwaway.example", prompt)

    def test_system_prompt_covers_impersonation_and_score_magnitude(self):
        self.assertIn("Impersonated organization", qs._SYSTEM_PROMPT)
        self.assertIn("fake-invoice / thread-hijack spam", qs._SYSTEM_PROMPT)
        self.assertIn("own domain", qs._SYSTEM_PROMPT)
        self.assertIn("north of ~15", qs._SYSTEM_PROMPT)


class LLMResponseParsingTests(unittest.TestCase):
    def test_accepts_explanation_after_json_object(self):
        result = qs._parse_llm_json(
            '{"verdict":"ham","confidence":0.91,"reason":"expected mail"}\n'
            "This message appears legitimate."
        )
        self.assertEqual(result["verdict"], "ham")
        self.assertEqual(result["confidence"], 0.91)

    def test_accepts_text_before_json_object(self):
        result = qs._parse_llm_json(
            'Analysis:\n{"verdict":"spam","confidence":0.8,"reason":"phishing"}'
        )
        self.assertEqual(result["verdict"], "spam")

    def test_rejects_response_without_json_object(self):
        with self.assertRaises(ValueError):
            qs._parse_llm_json("This looks legitimate.")


class LLMPacingTests(unittest.TestCase):
    def setUp(self):
        # Give each test a worker with no recorded call history.
        qs._llm_pacing = threading.local()

    def _pace(self, interval, calls, clock_readings):
        """Run *calls* paced calls against a fake clock, returning the sleep mock.

        A worker's first call reads the clock once (to record it); every later
        call reads it twice (measure, then record).
        """
        clock = iter(clock_readings)
        with patch.object(qs.time, "monotonic", side_effect=lambda: next(clock)), \
                patch.object(qs.time, "sleep") as sleep:
            for _ in range(calls):
                qs._pace_llm_call(interval)
        return sleep

    def test_first_call_on_a_worker_does_not_wait(self):
        sleep = self._pace(0.5, calls=1, clock_readings=[100.0])
        sleep.assert_not_called()

    def test_burst_call_waits_for_the_remaining_interval(self):
        # Second call starts 0.2s after the first, so 0.3s of the 0.5s is left.
        sleep = self._pace(0.5, calls=2, clock_readings=[100.0, 100.2, 100.5])
        sleep.assert_called_once()
        self.assertAlmostEqual(sleep.call_args[0][0], 0.3)

    def test_call_slower_than_the_interval_needs_no_extra_delay(self):
        sleep = self._pace(0.5, calls=2, clock_readings=[100.0, 103.0, 103.0])
        sleep.assert_not_called()

    def test_zero_interval_disables_pacing(self):
        with patch.object(qs.time, "sleep") as sleep:
            qs._pace_llm_call(0.0)
            qs._pace_llm_call(0.0)
        sleep.assert_not_called()


def _config(**overrides):
    """Build a Config in memory, without reading a file from disk."""
    fields = {
        "pmg_url": "https://pmg.example.com:8006",
        "pmg_username": "u@pam",
        "pmg_password": "p",
        "pmg_verify_ssl": True,
        "llm_backend": "ollama",
        "llm_model": "m",
        "llm_ollama_url": "http://localhost:11434",
        "llm_api_key": "",
        "db_path": Path("unused.db"),
        "lookback_days": 7,
        "confidence_threshold": 0.70,
        "body_max_chars": 3000,
        "max_mails_per_run": 200,
        "max_workers": 5,
        "sleep_between_requests": 0.0,
        "rcpt_ignore": (),
    }
    fields.update(overrides)
    return qs.Config(**fields)


class TerminalSafetyTests(unittest.TestCase):
    def test_removes_escape_but_leaves_the_attempt_visible(self):
        # Deleting only ESC keeps "[32m" as literal text, so a reader can see
        # that the field was tampered with.
        self.assertEqual(qs._scrub("Invoice\x1b[32m PAID"), "Invoice[32m PAID")

    def test_removes_eight_bit_c1_control(self):
        # U+009B is an 8-bit CSI — stripping ESC alone would miss it entirely.
        self.assertEqual(qs._scrub("a\u009b31mb"), "a31mb")

    def test_neutralises_osc_hyperlink(self):
        link = "\x1b]8;;https://evil.example\x07Bank\x1b]8;;\x07"
        scrubbed = qs._scrub(link)
        self.assertNotIn("\x1b", scrubbed)
        self.assertNotIn("\x07", scrubbed)
        # The URL stays readable instead of hiding behind the word "Bank".
        self.assertIn("evil.example", scrubbed)

    def test_removes_bidi_override(self):
        self.assertEqual(
            qs._scrub("Rechnung \u202eanhang.exe"), "Rechnung anhang.exe"
        )

    def test_folds_whitespace_controls_into_spaces(self):
        # Deleting them outright would glue the words together.
        self.assertEqual(qs._scrub("line one\nline two"), "line one line two")
        self.assertEqual(qs._scrub("a\tb"), "a b")

    def test_preserves_legitimate_unicode(self):
        text = "Grüße — Müller & Co. 日本語 €"
        self.assertEqual(qs._scrub(text), text)

    def test_accepts_non_string_values(self):
        self.assertEqual(qs._scrub(None), "")
        self.assertEqual(qs._scrub(5.0), "5.0")

    def test_digest_emits_no_control_sequences_from_mail_data(self):
        """End-to-end: hostile sender/subject/reason must not reach the terminal."""
        with TemporaryDirectory() as directory:
            db = qs.StateDB(Path(directory) / "state.db")
            # Above threshold -> rendered in the "likely false positives" block.
            db.store(
                mail_id="id-1\x1b[2J",
                verdict="ham",
                confidence=0.95,
                reason="looks fine\x1b]0;window retitled\x07",
                spam_score=3.0,
                from_addr="\x1b[32mtrusted@example.com\x1b[0m",
                subject="Invoice \u202eexe.tnemucod",
                rcpt_addr=None,
            )
            # Below threshold -> rendered in the "uncertain" block.
            db.store(
                mail_id="id-2\x9b2J",
                verdict="ham",
                confidence=0.40,
                reason="unsure\r\nsecond line",
                spam_score=9.0,
                from_addr="odd\x07@example.com",
                subject="\x1b[31mURGENT\x1b[0m",
                rcpt_addr=None,
            )
            rows = list(db.get_all_since(datetime(2000, 1, 1, tzinfo=timezone.utc)))
            db.close()

        cfg = _config()
        above = [r for r in rows if r["confidence"] >= cfg.confidence_threshold]
        buffer = io.StringIO()
        # Pin colour off: the digest legitimately emits ESC of its own when
        # attached to a tty, which would mask what this test is checking.
        with patch.object(qs, "_COLOR", False), redirect_stdout(buffer):
            qs.print_digest(above, rows, 2, 0, cfg)
        output = buffer.getvalue()

        for forbidden in ("\x1b", "\x07", "\x9b", "\u202e", "\r"):
            self.assertNotIn(forbidden, output)
        # The data itself is still reported, just inert.
        self.assertIn("trusted@example.com", output)
        self.assertIn("URGENT", output)
        self.assertIn("second line", output)


class StateDBCacheTests(unittest.TestCase):
    def test_stored_mail_is_cached(self):
        with TemporaryDirectory() as directory:
            db = qs.StateDB(Path(directory) / "state.db")
            db.store(
                mail_id="mail-1",
                verdict="ham",
                confidence=0.9,
                reason="authentication-only gateway score",
                spam_score=5.0,
                from_addr="sender@example.com",
                subject="invoice",
                rcpt_addr=None,
            )
            self.assertTrue(db.is_cached("mail-1"))
            db.close()

    def test_unknown_mail_is_not_cached(self):
        with TemporaryDirectory() as directory:
            db = qs.StateDB(Path(directory) / "state.db")
            self.assertFalse(db.is_cached("mail-1"))
            db.close()


class _FakePMG:
    """Minimal stand-in for PMGClient: one user with two quarantined mails."""

    def __init__(self, mails):
        self._mails = mails

    def list_quarantine_users(self, since):
        return ["user@example.com"]

    def list_quarantined_mails(self, user, since):
        return self._mails

    def get_mail_content(self, mail_id):
        return "Subject: test\n\nbody"


class RunExitCodeTests(unittest.TestCase):
    CONFIG = (
        "max_workers = 1\n"  # deterministic ordering for the consecutive-failure path
        '[pmg]\nurl = "https://pmg.example.com:8006"\n'
        'username = "u@pam"\npassword = "p"\n'
        '[llm]\nbackend = "ollama"\nmodel = "m"\n'
    )

    def _run_with(self, score_mail, mail_count=2):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(self.CONFIG, encoding="utf-8")
            cfg = qs.load_config(str(path))
            db = qs.StateDB(Path(directory) / "state.db")
            pmg = _FakePMG([{"id": f"mail-{i}"} for i in range(mail_count)])
            since = datetime.now(timezone.utc)
            try:
                with patch.object(qs, "score_mail", score_mail), \
                        redirect_stdout(io.StringIO()):
                    return qs._run(cfg, db, threading.Lock(), pmg, since)
            finally:
                db.close()

    def test_successful_run_exits_zero(self):
        def score(*args, **kwargs):
            return {"verdict": "spam", "confidence": 0.9, "reason": "ok"}

        self.assertEqual(self._run_with(score), 0)

    def test_fatal_llm_error_exits_nonzero(self):
        # A run that aborted mid-queue must not look successful to cron.
        def score(*args, **kwargs):
            raise qs.FatalLLMError("invalid api key")

        self.assertEqual(self._run_with(score), 1)

    def test_consecutive_llm_errors_exit_nonzero(self):
        # Three consecutive non-fatal failures trip the same abort path.
        def score(*args, **kwargs):
            raise RuntimeError("connection reset")

        self.assertEqual(self._run_with(score, mail_count=3), 1)


if __name__ == "__main__":
    unittest.main()
