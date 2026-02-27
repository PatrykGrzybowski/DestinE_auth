import logging

import requests
from lxml import html
from urllib.parse import parse_qs, urlparse

from .config import CLIENT_ID, DEFAULT_TIMEOUT_SECONDS, IAM_URL, REALM, SERVICE_URL
from .errors import (
    AuthError,
    AuthNetworkError,
    InvalidCredentialsError,
    OTPRequiredError,
    TokenExchangeError,
)

logger = logging.getLogger(__name__)


class DESPAuth:
    def __init__(self, username, password, timeout=DEFAULT_TIMEOUT_SECONDS, session_factory=requests.Session, otp_provider=None):
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session_factory = session_factory
        self.otp_provider = otp_provider

    def _extract_auth_code_from_location(self, location_header):
        if not location_header:
            raise AuthError("Login failed: missing redirect location from identity provider.")

        code_values = parse_qs(urlparse(location_header).query).get("code")
        if not code_values:
            raise AuthError("Login failed: missing authorization code in identity provider redirect.")

        return code_values[0]

    def _contains_otp_form(self, tree):
        otp_keywords = ["otp", "one-time password", "verification code"]
        for keyword in otp_keywords:
            if tree.xpath(
                f"//input[contains(translate(@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{keyword}') "
                f"or contains(translate(@id, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{keyword}') "
                f"or contains(translate(@placeholder, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{keyword}') "
                f"or contains(translate(@type, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{keyword}')]"
            ):
                return True
        return False

    def _get_otp_code(self, explicit_otp):
        if explicit_otp:
            return explicit_otp

        if self.otp_provider:
            return self.otp_provider()

        return input("Please insert OTP code: ")
        
    def get_token_otp(self, otp_code=None):
        with self.session_factory() as s:

            authorize_url = f"{IAM_URL}/realms/{REALM}/protocol/openid-connect/auth"
            token_url = f"{IAM_URL}/realms/{REALM}/protocol/openid-connect/token"

            # Get the auth url
            try:
                auth_response = s.get(
                    url=authorize_url,
                    params={
                        "client_id": CLIENT_ID,
                        "redirect_uri": SERVICE_URL,
                        "scope": "openid",
                        "response_type": "code",
                    },
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                raise AuthNetworkError("Unable to contact DESP identity provider.") from exc

            try:
                auth_tree = html.fromstring(auth_response.content.decode())
                auth_url = auth_tree.forms[0].action
            except (IndexError, ValueError) as exc:
                raise AuthError("Unable to load DESP login form from identity provider.") from exc
            
            # Login and get auth code (Test if OTP with redirect)
            try:
                login = s.post(
                    auth_url,
                    data={
                        "username": self.username,
                        "password": self.password,
                    },
                    allow_redirects=False,
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                raise AuthNetworkError("Unable to submit DESP credentials to identity provider.") from exc
            
            # Parse the response content and check for the presence of OTP-related keywords
            if login.status_code == 302:
                auth_code = self._extract_auth_code_from_location(login.headers.get("Location"))
            elif login.status_code == 200:
                tree = html.fromstring(login.content.decode())

                error_message_element = tree.xpath('//span[@id="input-error"]/text()')
                if error_message_element:
                    error_message = error_message_element[0].strip() or "Invalid DESP credentials."
                    raise InvalidCredentialsError(error_message)

                if not self._contains_otp_form(tree):
                    raise AuthError("Login failed. Unexpected response from DESP identity provider.")

                if not tree.forms:
                    raise OTPRequiredError("OTP authentication required but OTP form is not available.")

                otp_action = tree.forms[0].action
                resolved_otp_code = self._get_otp_code(otp_code)
                if not resolved_otp_code:
                    raise OTPRequiredError("OTP authentication required. Provide an OTP code and retry.")

                try:
                    otp_login = s.post(
                        otp_action,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        data={"otp": resolved_otp_code, "login": "Sign In"},
                        allow_redirects=False,
                        timeout=self.timeout,
                    )
                except requests.RequestException as exc:
                    raise AuthNetworkError("Unable to submit OTP code to identity provider.") from exc

                if otp_login.status_code != 302:
                    raise OTPRequiredError("OTP verification failed. Check your OTP code and retry.")

                auth_code = self._extract_auth_code_from_location(otp_login.headers.get("Location"))
            else:
                raise AuthError(f"Login failed with HTTP {login.status_code}. Please retry later.")
                                

            # Use the auth code to get the token
            try:
                response = s.post(
                    token_url,
                    data={
                        "client_id": CLIENT_ID,
                        "redirect_uri": SERVICE_URL,
                        "code": auth_code,
                        "grant_type": "authorization_code",
                        "scope": "",
                    },
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                raise AuthNetworkError("Unable to exchange authorization code for DESP token.") from exc
            
            if response.status_code != 200:
                raise TokenExchangeError(f"Failed to get DESP token (HTTP {response.status_code}).")

            token = response.json().get("access_token")
            if not token:
                raise TokenExchangeError("DESP token response did not contain an access token.")

            logger.debug("DESP token successfully acquired.")
        

            return token        