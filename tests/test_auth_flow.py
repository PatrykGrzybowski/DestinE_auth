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
    def test_non_200_raises_token_exchange_error(self):
        def fake_post(*args, **kwargs):
            return FakeResponse(status_code=500, json_data={"error": "server_error"})

        auth = DEDLAuth("desp-token", request_post=fake_post)
        with self.assertRaises(TokenExchangeError) as context:
            auth.get_token()

        self.assertIn("HTTP 500", str(context.exception))
        self.assertIn("Verify DESP token validity", str(context.exception))

    def test_network_error_raises_auth_network_error(self):
        def fake_post(*args, **kwargs):
            raise requests.RequestException("network down")

        auth = DEDLAuth("desp-token", request_post=fake_post)
        with self.assertRaises(AuthNetworkError):
            auth.get_token()

    def test_missing_access_token_raises_token_exchange_error(self):
        def fake_post(*args, **kwargs):
            return FakeResponse(status_code=200, json_data={"token_type": "Bearer"})

        auth = DEDLAuth("desp-token", request_post=fake_post)
        with self.assertRaises(TokenExchangeError):
            auth.get_token()


class TestDEDLServiceAccountAuth(unittest.TestCase):
    def test_service_account_success(self):
        def fake_post(*args, **kwargs):
            return FakeResponse(status_code=200, json_data={"access_token": "dedl-sa-token"})

        auth = DEDLServiceAccountAuth("client-id", "client-secret", request_post=fake_post)
        self.assertEqual(auth.get_token(), "dedl-sa-token")

    def test_non_200_raises_token_exchange_error(self):
        def fake_post(*args, **kwargs):
            return FakeResponse(status_code=500, json_data={"error": "server_error"})

        auth = DEDLServiceAccountAuth("client-id", "client-secret", request_post=fake_post)
        with self.assertRaises(TokenExchangeError) as context:
            auth.get_token()

        self.assertIn("HTTP 500", str(context.exception))

    def test_invalid_credentials_raise_specific_error(self):
        def fake_post(*args, **kwargs):
            return FakeResponse(status_code=401, json_data={"error": "invalid_client"})

        auth = DEDLServiceAccountAuth(
            "client-id",
            "wrong-secret",
            request_post=fake_post,
        )
        with self.assertRaises(InvalidCredentialsError) as context:
            auth.get_token()

        self.assertIn("Verify DEDL client credentials", str(context.exception))

    def test_network_error_raises_auth_network_error(self):
        def fake_post(*args, **kwargs):
            raise requests.RequestException("network down")

        auth = DEDLServiceAccountAuth(
            "client-id",
            "client-secret",
            request_post=fake_post,
        )
        with self.assertRaises(AuthNetworkError):
            auth.get_token()

    def test_missing_access_token_raises_token_exchange_error(self):
        def fake_post(*args, **kwargs):
            return FakeResponse(status_code=200, json_data={"token_type": "Bearer"})

        auth = DEDLServiceAccountAuth(
            "client-id",
            "client-secret",
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