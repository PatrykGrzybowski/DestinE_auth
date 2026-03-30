import logging
from urllib.parse import parse_qs, urlparse

import requests
from lxml import html

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
    def __init__(
        self,
        username,
        password,
        timeout=DEFAULT_TIMEOUT_SECONDS,
        session_factory=requests.Session,
        otp_provider=None,
    ):
        """
        Handles authentication with the DESP identity provider, including OTP flows when required.

        The introduction of session_factory and otp_provider allows for greater flexibility and testability.
        session_factory can be used to inject mock sessions during testing, while otp_provider allows for custom OTP handling logic (e.g., fetching from an environment variable) instead of relying solely on interactive input.

        :param username: DESP username
        :param password: DESP password
        :param timeout: Timeout for network requests in seconds (default: 30)
        :param session_factory: Factory function for creating HTTP sessions (default: requests.Session)
        :param otp_provider: Optional function to provide OTP codes when required. If not provided, will fall back to prompting the user via input().
        """
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session_factory = session_factory
        self.otp_provider = otp_provider

    def _extract_auth_code_from_location(self, location_header):
        """
        Extracts the authorization code from the redirect location header.
        Testable in isolation to ensure correct parsing of the auth code from the redirect URL.
        :param location_header: The value of the Location header from the HTTP response
        :return: The extracted authorization code
        :raises AuthError: If the location header is missing or does not contain the expected authorization code
        """
        if not location_header:
            raise AuthError(
                "Login failed: missing redirect location from identity provider."
            )

        code_values = parse_qs(urlparse(location_header).query).get("code")
        if not code_values:
            raise AuthError(
                "Login failed: missing authorization code in identity provider redirect."
            )

        return code_values[0]

    def _contains_otp_form(self, tree):
        """
        Checks if the HTML tree contains an OTP input form.
        Testable in isolation to verify that the correct heuristics are being applied to detect OTP forms based on common input field attributes.

        Answers the question: Does the provided HTML tree contain an OTP form based on common input field attributes that indicate OTP requirement?

        :param tree: The parsed HTML tree
        :return: True if an OTP form is detected, False otherwise
        """
        otp_keywords = ["otp", "one-time password", "verification code"]
        for keyword in otp_keywords:

            # Note: Need a case-insensitive search for OTP-related keywords in the input field attributes to make this more robust against variations in the identity provider's implementation.
            # XPath 1.0 does not support case-insensitive contains, so we use translate to convert attributes to lowercase for comparison. 
            # We check common attributes like name, id, placeholder, and type for indicators of OTP fields.
            if tree.xpath(
                f"//input[contains(translate(@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{keyword}') "
                f"or contains(translate(@id, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{keyword}') "
                f"or contains(translate(@placeholder, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{keyword}') "
                f"or contains(translate(@type, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{keyword}')]"
            ):
                return True
        return False

    def _get_otp_code(self, explicit_otp):
        """
        Retrieves the OTP code either from the explicit parameter, the otp_provider, or by prompting the user.
        :param explicit_otp: An explicitly provided OTP code
        :return: The OTP code to use for authentication
        """
        if explicit_otp:
            return explicit_otp

        if self.otp_provider:
            return self.otp_provider()

        return input("Please insert OTP code: ")

    def get_desp_token(self, otp_code=None):
        """
        Performs the full authentication flow to obtain a DESP access token, including handling OTP if required.

        :param otp_code: Optional explicit OTP code to use for authentication. If not provided, will be obtained via otp_provider or user input.
        :return: The acquired DESP access token
        :raises AuthError: For various authentication failures, including network issues, invalid credentials, missing OTP, and token exchange failures.

        """

        # Use a session context to ensure proper resource management and to allow for session reuse if needed. The session_factory allows for injecting mock sessions during testing.
        with self.session_factory() as s:

            authorize_url = f"{IAM_URL}/realms/{REALM}/protocol/openid-connect/auth"
            token_url = f"{IAM_URL}/realms/{REALM}/protocol/openid-connect/token"

            # Step 1: Get the login page to establish a session and get any necessary cookies, then parse the login form
            # This is based on the standard OpenID Connect authorization code flow, but with added handling for OTP if the identity provider requires it.
            # The logic is designed to be robust against variations in the identity provider's responses, such as different ways of indicating that OTP is required.
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
                raise AuthNetworkError(
                    "Unable to contact DESP identity provider."
                ) from exc

            try:
                auth_tree = html.fromstring(auth_response.content.decode())
                auth_url = auth_tree.forms[0].action
            except (IndexError, ValueError) as exc:
                raise AuthError(
                    "Unable to load DESP login form from identity provider."
                ) from exc

            # Step 2: Login and get auth code (Test if OTP with redirect)
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
                raise AuthNetworkError(
                    "Unable to submit DESP credentials to identity provider."
                ) from exc

            # Parse the response content and check for the presence of OTP-related keywords
            if login.status_code == 302:

                # If we get a redirect, we can assume credentials were accepted and we can try to extract the auth code directly. This is the simpler flow when OTP is not required.
                auth_code = self._extract_auth_code_from_location(
                    login.headers.get("Location")
                )

            elif login.status_code == 200:

                # If we get a 200 OK, it means the login page is being re-rendered, possibly due to OTP requirement or invalid credentials.
                # We need to parse the HTML to determine if OTP is required or if there was an error with the credentials.
                # This is a more complex flow that requires careful handling of the identity provider's response.
                tree = html.fromstring(login.content.decode())

                # First check for explicit error messages that indicate invalid credentials, as this is a common failure mode that we want to provide clear feedback on.
                error_message_element = tree.xpath('//span[@id="input-error"]/text()')
                if error_message_element:
                    error_message = (
                        error_message_element[0].strip() or "Invalid DESP credentials."
                    )
                    raise InvalidCredentialsError(error_message)

                # If there are no explicit error messages, check if the page contains an OTP form, which would indicate that OTP is required for this account.
                # This heuristic allows us to handle cases where the identity provider does not provide clear indicators of OTP requirement.
                if not self._contains_otp_form(tree):
                    raise AuthError(
                        "Login failed. Unexpected response from DESP identity provider."
                    )

                # If we detect an OTP form, we need to handle the OTP flow. This involves prompting the user for the OTP code (or using the otp_provider),
                # submitting it to the identity provider, and then extracting the auth code from the redirect if the OTP verification is successful.
                if not tree.forms:
                    raise OTPRequiredError(
                        "OTP authentication required but OTP form is not available."
                    )

                # Assuming the first form is the OTP form, we extract the action URL and submit the OTP code.
                # We then check for a redirect to confirm that the OTP was accepted, and extract the auth code from that redirect.
                otp_action = tree.forms[0].action
                resolved_otp_code = self._get_otp_code(otp_code)
                if not resolved_otp_code:
                    raise OTPRequiredError(
                        "OTP authentication required. Provide an OTP code and retry."
                    )

                # Submit the OTP code to the identity provider and check for a redirect response, which indicates successful OTP verification. If we don't get a redirect,
                # we assume the OTP verification failed and raise an appropriate error.
                try:
                    otp_login = s.post(
                        otp_action,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        data={"otp": resolved_otp_code, "login": "Sign In"},
                        allow_redirects=False,
                        timeout=self.timeout,
                    )
                except requests.RequestException as exc:
                    raise AuthNetworkError(
                        "Unable to submit OTP code to identity provider."
                    ) from exc

                # If the OTP submission does not result in a redirect, it likely means the OTP was incorrect or there was some other issue with the OTP verification.
                # We raise an error in this case to inform the user.
                if otp_login.status_code != 302:
                    raise OTPRequiredError(
                        "OTP verification failed. Check your OTP code and retry."
                    )

                # If we get a redirect after submitting the OTP, we can assume the OTP was accepted and we can try to extract the auth code from the redirect URL.
                auth_code = self._extract_auth_code_from_location(
                    otp_login.headers.get("Location")
                )

            else:
                raise AuthError(
                    f"Login failed with HTTP {login.status_code}. Please retry later."
                )

            # At this point, we should have successfully obtained an authorization code, either through the initial login or through the OTP flow.
            # We can now exchange this authorization code for a DESP access token by making a POST request to the token endpoint of the identity provider.
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
                raise AuthNetworkError(
                    "Unable to exchange authorization code for DESP token."
                ) from exc

            if response.status_code != 200:
                raise TokenExchangeError(
                    f"Failed to get DESP token (HTTP {response.status_code})."
                )

            # Finally, we parse the token response to extract the access token.
            # We also include error handling to ensure that if the expected access token is not present in the response, we raise an appropriate error.
            try:
                response_payload = response.json()
            except ValueError as exc:
                raise TokenExchangeError(
                    "DESP token response could not be parsed. Retry later or verify identity provider availability."
                ) from exc

            token = response_payload.get("access_token")
            if not token:
                raise TokenExchangeError(
                    "DESP token response did not contain an access token."
                )

            logger.debug("DESP token successfully acquired.")

            return token
