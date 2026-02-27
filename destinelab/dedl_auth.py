import logging

import requests

from .config import DEDL_AUDIENCE, DEDL_CLIENT_ID, DEDL_TOKEN_URL, DEFAULT_TIMEOUT_SECONDS
from .errors import AuthNetworkError, TokenExchangeError

logger = logging.getLogger(__name__)

class DEDLAuth:
    def __init__(self, desp_access_token, timeout=DEFAULT_TIMEOUT_SECONDS, strict=False, request_post=requests.post):
        self.desp_access_token = desp_access_token
        self.timeout = timeout
        self.strict = strict
        self.request_post = request_post

    def _handle_error(self, message, error_class):
        if self.strict:
            raise error_class(message)

        logger.warning(message)
        return None

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
        except requests.RequestException as exc:
            return self._handle_error("Unable to reach DEDL identity provider for token exchange.", AuthNetworkError)

        if response.status_code == 200: 
            dedl_token = response.json().get("access_token")
            if not dedl_token:
                return self._handle_error("DEDL token response did not include an access token.", TokenExchangeError)

            return dedl_token

        return self._handle_error(
            f"Error obtaining DEDL access token (HTTP {response.status_code}).",
            TokenExchangeError,
        )