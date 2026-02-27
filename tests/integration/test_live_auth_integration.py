import os
import unittest
from pathlib import Path
from unittest.mock import patch

from destinelab.config import DEFAULT_TIMEOUT_SECONDS
from destinelab.dedl_auth import DEDLAuth
from destinelab.de_token import AuthHandler
from destinelab.desp_auth import DESPAuth
from destinelab.errors import InvalidCredentialsError, OTPRequiredError, TokenExchangeError


ENV_ALLOWLIST = {
    "DESP_USERNAME",
    "DESP_PASSWORD",
    "DESP_BAD_PASSWORD",
    "DESP_OTP_CODE",
    "RUN_LIVE_AUTH_TESTS",
    "RUN_LIVE_NEGATIVE_TESTS",
    "RUN_LIVE_AUTH_TESTS_IN_CI",
    "LIVE_AUTH_TIMEOUT_SECONDS",
    "CI",
}


def _is_truthy(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _parse_dotenv(dotenv_path):
    values = {}
    if not dotenv_path.exists():
        return values

    for raw_line in dotenv_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        if key in ENV_ALLOWLIST:
            values[key] = value

    return values


def _load_live_env():
    repo_root = Path(__file__).resolve().parents[2]
    dotenv_values = _parse_dotenv(repo_root / ".env")

    merged = {}
    for key in ENV_ALLOWLIST:
        env_value = os.getenv(key)
        merged[key] = env_value if env_value is not None else dotenv_values.get(key)

    return merged


class TestLiveAuthIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.live_env = _load_live_env()

        run_live = _is_truthy(cls.live_env.get("RUN_LIVE_AUTH_TESTS"))
        if not run_live:
            raise unittest.SkipTest("Set RUN_LIVE_AUTH_TESTS=1 to run live integration tests.")

        running_ci = _is_truthy(cls.live_env.get("CI"))
        allow_ci = _is_truthy(cls.live_env.get("RUN_LIVE_AUTH_TESTS_IN_CI"))
        if running_ci and not allow_ci:
            raise unittest.SkipTest("Live auth tests are disabled in CI by default.")

        cls.username = cls.live_env.get("DESP_USERNAME")
        cls.password = cls.live_env.get("DESP_PASSWORD")
        cls.bad_password = cls.live_env.get("DESP_BAD_PASSWORD")
        cls.otp_code = cls.live_env.get("DESP_OTP_CODE")
        cls.run_negative_tests = _is_truthy(cls.live_env.get("RUN_LIVE_NEGATIVE_TESTS"))

        if not cls.username or not cls.password:
            raise unittest.SkipTest("DESP_USERNAME and DESP_PASSWORD are required for live tests.")

        timeout_value = cls.live_env.get("LIVE_AUTH_TIMEOUT_SECONDS")
        cls.timeout = int(timeout_value) if timeout_value else DEFAULT_TIMEOUT_SECONDS

    def _input_fallback(self):
        return self.otp_code or ""

    def test_auth_handler_e2e_token_flow(self):
        handler = AuthHandler(self.username, self.password)

        with patch("builtins.input", return_value=self._input_fallback()):
            token = handler.get_token()

        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 20)
        self.assertEqual(token.count("."), 2)

        roles = handler.get_roles(token)
        self.assertTrue(roles is None or isinstance(roles, list))

    def test_staged_desp_to_dedl_exchange(self):
        desp_auth = DESPAuth(self.username, self.password, timeout=self.timeout, otp_provider=lambda: self._input_fallback())

        desp_token = desp_auth.get_token_otp(otp_code=self.otp_code)
        self.assertIsInstance(desp_token, str)
        self.assertEqual(desp_token.count("."), 2)

        dedl_token = DEDLAuth(desp_token, timeout=self.timeout, strict=True).get_token()
        self.assertIsInstance(dedl_token, str)
        self.assertEqual(dedl_token.count("."), 2)

    def test_negative_paths_optional(self):
        if not self.run_negative_tests:
            self.skipTest("Set RUN_LIVE_NEGATIVE_TESTS=1 to run live negative tests.")

        if not self.bad_password:
            self.skipTest("Set DESP_BAD_PASSWORD to run invalid-credentials live test.")

        invalid_auth = DESPAuth(
            self.username,
            self.bad_password,
            timeout=self.timeout,
            otp_provider=lambda: self._input_fallback(),
        )
        with self.assertRaises(InvalidCredentialsError):
            invalid_auth.get_token_otp(otp_code=self.otp_code)

        with self.assertRaises(TokenExchangeError):
            DEDLAuth("not-a-valid-desp-token", timeout=self.timeout, strict=True).get_token()

    def test_otp_requirement_is_explicit_when_no_code_available(self):
        if self.otp_code:
            self.skipTest("OTP code is configured; this explicit OTP-required path is not applicable.")

        auth = DESPAuth(self.username, self.password, timeout=self.timeout, otp_provider=lambda: "")

        try:
            token = auth.get_token_otp()
            self.assertIsInstance(token, str)
        except OTPRequiredError:
            self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()