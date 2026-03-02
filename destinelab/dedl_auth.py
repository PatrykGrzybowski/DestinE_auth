import requests

from .config import DEDL_AUDIENCE, DEDL_CLIENT_ID, DEDL_TOKEN_URL, DEFAULT_TIMEOUT_SECONDS
from .errors import AuthNetworkError, InvalidCredentialsError, TokenExchangeError


class DEDLAuth:
    def __init__(self, desp_access_token, timeout=DEFAULT_TIMEOUT_SECONDS, request_post=requests.post):
        self.desp_access_token = desp_access_token
        self.timeout = timeout
        self.request_post = request_post

    def get_token(self):
        data = { 
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", 
            "subject_token": self.desp_access_token,
            "subject_issuer": "desp-oidc",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "client_id": DEDL_CLIENT_ID,
            "audience": DEDL_AUDIENCE,
        }

        try:
            response = self.request_post(DEDL_TOKEN_URL, data=data, timeout=self.timeout)
        except requests.RequestException:
            raise AuthNetworkError("Unable to reach DEDL identity provider for token exchange.")

        if response.status_code == 200: 
            dedl_token = response.json().get("access_token")
            if not dedl_token:
                raise TokenExchangeError("DEDL token response did not include an access token.")

            return dedl_token

        raise TokenExchangeError(
            f"Error obtaining DEDL access token (HTTP {response.status_code}). Verify DESP token validity and DEDL availability.",
        )


class DEDLServiceAccountAuth:
    def __init__(self, client_id, client_secret, timeout=DEFAULT_TIMEOUT_SECONDS, request_post=requests.post):
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.request_post = request_post

    def _map_http_error(self, status_code):
        if status_code in (400, 401, 403):
            return (
                f"Service account authentication failed (HTTP {status_code}). Verify DEDL client credentials and scope.",
                InvalidCredentialsError,
            )

        return (
            f"Error obtaining DEDL access token via service account (HTTP {status_code}).",
            TokenExchangeError,
        )

    def get_token(self):
        data = {
            "client_id": self.client_id,
            "grant_type": "client_credentials",
            "client_secret": self.client_secret,
            "scope": "openid",
        }

        try:
            response = self.request_post(DEDL_TOKEN_URL, data=data, timeout=self.timeout)
        except requests.RequestException:
            raise AuthNetworkError(
                "Unable to reach DEDL identity provider for service account authentication.",
            )

        if response.status_code == 200:
            dedl_token = response.json().get("access_token")
            if not dedl_token:
                raise TokenExchangeError(
                    "DEDL token response did not include an access token.",
                )

            return dedl_token

        message, error_class = self._map_http_error(response.status_code)
        raise error_class(message)