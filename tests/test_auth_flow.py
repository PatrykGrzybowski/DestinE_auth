import unittest

import jwt
import requests

from destinelab.dedl_auth import DEDLAuth, DEDLServiceAccountAuth
from destinelab.de_token import AuthHandler
from destinelab.desp_auth import DESPAuth
from destinelab.errors import AuthNetworkError, InvalidCredentialsError, TokenExchangeError


class FakeResponse:
    def __init__(self, status_code=200, content="", headers=None, json_data=None):
        self.status_code = status_code
        self.content = content.encode() if isinstance(content, str) else content
        self.headers = headers or {}
        self._json_data = json_data or {}

    def json(self):
        return self._json_data


class FakeSession:
    def __init__(self, get_responses=None, post_responses=None):
        self._get_responses = list(get_responses or [])
        self._post_responses = list(post_responses or [])

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, *args, **kwargs):
        return self._get_responses.pop(0)

    def post(self, *args, **kwargs):
        return self._post_responses.pop(0)


class TestDESPAuth(unittest.TestCase):
    def test_get_token_without_otp_success(self):
        session = FakeSession(
            get_responses=[
                FakeResponse(content='<html><body><form action="https://auth.example/login"></form></body></html>')
            ],
            post_responses=[
                FakeResponse(status_code=302, headers={"Location": "https://service/callback?code=AUTHCODE"}),
                FakeResponse(status_code=200, json_data={"access_token": "desp-token"}),
            ],
        )

        auth = DESPAuth("user", "pass", session_factory=lambda: session)
        self.assertEqual(auth.get_desp_token(), "desp-token")

    def test_get_token_with_otp_success(self):
        session = FakeSession(
            get_responses=[
                FakeResponse(content='<html><body><form action="https://auth.example/login"></form></body></html>')
            ],
            post_responses=[
                FakeResponse(
                    status_code=200,
                    content='<html><body><form action="https://auth.example/otp"><input name="otp"/></form></body></html>',
                ),
                FakeResponse(status_code=302, headers={"Location": "https://service/callback?code=OTP_CODE"}),
                FakeResponse(status_code=200, json_data={"access_token": "desp-token-otp"}),
            ],
        )

        auth = DESPAuth("user", "pass", session_factory=lambda: session)
        self.assertEqual(auth.get_desp_token(otp_code="123456"), "desp-token-otp")

    def test_invalid_credentials_raise_specific_error(self):
        session = FakeSession(
            get_responses=[
                FakeResponse(content='<html><body><form action="https://auth.example/login"></form></body></html>')
            ],
            post_responses=[
                FakeResponse(
                    status_code=200,
                    content='<html><span id="input-error">Invalid username or password.</span></html>',
                )
            ],
        )

        auth = DESPAuth("user", "bad-pass", session_factory=lambda: session)
        with self.assertRaises(InvalidCredentialsError):
            auth.get_desp_token()


class TestDEDLAuth(unittest.TestCase):
    def test_non_200_returns_none_by_default(self):
        def fake_post(*args, **kwargs):
            return FakeResponse(status_code=500, json_data={"error": "server_error"})

        auth = DEDLAuth("desp-token", request_post=fake_post)
        with self.assertLogs("destinelab.dedl_auth", level="WARNING"):
            self.assertIsNone(auth.get_token())

    def test_non_200_can_raise_in_strict_mode(self):
        def fake_post(*args, **kwargs):
            return FakeResponse(status_code=500, json_data={"error": "server_error"})

        auth = DEDLAuth("desp-token", strict=True, request_post=fake_post)
        with self.assertRaises(TokenExchangeError):
            auth.get_token()


class TestDEDLServiceAccountAuth(unittest.TestCase):
    def test_service_account_success(self):
        def fake_post(*args, **kwargs):
            return FakeResponse(status_code=200, json_data={"access_token": "dedl-sa-token"})

        auth = DEDLServiceAccountAuth("client-id", "client-secret", request_post=fake_post)
        self.assertEqual(auth.get_token(), "dedl-sa-token")

    def test_non_200_returns_none_by_default(self):
        def fake_post(*args, **kwargs):
            return FakeResponse(status_code=500, json_data={"error": "server_error"})

        auth = DEDLServiceAccountAuth("client-id", "client-secret", request_post=fake_post)
        with self.assertLogs("destinelab.dedl_auth", level="WARNING"):
            self.assertIsNone(auth.get_token())

    def test_invalid_credentials_raise_specific_error_in_strict_mode(self):
        def fake_post(*args, **kwargs):
            return FakeResponse(status_code=401, json_data={"error": "invalid_client"})

        auth = DEDLServiceAccountAuth(
            "client-id",
            "wrong-secret",
            strict=True,
            request_post=fake_post,
        )
        with self.assertRaises(InvalidCredentialsError):
            auth.get_token()

    def test_network_error_can_raise_in_strict_mode(self):
        def fake_post(*args, **kwargs):
            raise requests.RequestException("network down")

        auth = DEDLServiceAccountAuth(
            "client-id",
            "client-secret",
            strict=True,
            request_post=fake_post,
        )
        with self.assertRaises(AuthNetworkError):
            auth.get_token()

    def test_missing_access_token_can_raise_in_strict_mode(self):
        def fake_post(*args, **kwargs):
            return FakeResponse(status_code=200, json_data={"token_type": "Bearer"})

        auth = DEDLServiceAccountAuth(
            "client-id",
            "client-secret",
            strict=True,
            request_post=fake_post,
        )
        with self.assertRaises(TokenExchangeError):
            auth.get_token()


class TestAuthHandler(unittest.TestCase):
    def test_get_token_composes_auth_steps(self):
        class FakeDESPAuth:
            def __init__(self, username, password):
                self.username = username
                self.password = password

            def get_desp_token(self):
                return "desp-token"

        class FakeDEDLAuth:
            def __init__(self, desp_access_token):
                self.desp_access_token = desp_access_token

            def get_token(self):
                return "dedl-token"

        handler = AuthHandler(
            "user",
            "pass",
            desp_auth_class=FakeDESPAuth,
            dedl_auth_class=FakeDEDLAuth,
        )
        self.assertEqual(handler.get_token(), "dedl-token")

    def test_get_token_uses_service_account_when_credentials_provided(self):
        class FakeDESPAuth:
            def __init__(self, username, password):
                raise AssertionError("DESP auth should not run in service-account mode")

        class FakeDEDLServiceAccountAuth:
            def __init__(self, client_id, client_secret):
                self.client_id = client_id
                self.client_secret = client_secret

            def get_token(self):
                return "dedl-sa-token"

        handler = AuthHandler(
            "user",
            "pass",
            client_id="client-id",
            client_secret="client-secret",
            desp_auth_class=FakeDESPAuth,
            dedl_service_account_auth_class=FakeDEDLServiceAccountAuth,
        )
        self.assertEqual(handler.get_token(), "dedl-sa-token")

    def test_roles_and_access_checks(self):
        handler = AuthHandler("user", "pass")

        token = jwt.encode(
            {"realm_access": {"roles": ["DPAD_Direct_Access", "OtherRole"]}},
            "test-key-should-be-longer-than-thirty-two-bytes",
            algorithm="HS256",
        )

        self.assertIn("DPAD_Direct_Access", handler.get_roles(token))
        self.assertTrue(handler.is_DTaccess_allowed(token))

    def test_invalid_token_returns_none_roles_and_denies_access(self):
        handler = AuthHandler("user", "pass")
        self.assertIsNone(handler.get_roles("not-a-jwt"))
        self.assertFalse(handler.is_DTaccess_allowed("not-a-jwt"))


if __name__ == "__main__":
    unittest.main()