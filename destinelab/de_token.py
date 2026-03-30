import logging

import jwt

from .dedl_auth import DEDLAuth

# Import DESPAuth and DEDLAuth here to ensure they are available
from .desp_auth import DESPAuth
from .tools.token_tools import is_dedl_token_valid

logger = logging.getLogger(__name__)


class AuthHandler:
    def __init__(
        self,
        username,
        password,
        desp_auth_class=DESPAuth,
        dedl_auth_class=DEDLAuth,
        token_validator=is_dedl_token_valid,
    ):
        """
        Handles the overall authentication flow to obtain a DEDL token using DESP credentials.

        Note: the DESP and DEDL auth classes can be overridden for testing or custom implementations.

        :param username: DESP username
        :param password: DESP password
        :param desp_auth_class: Class to use for DESP authentication (default: DESPAuth)
        :param dedl_auth_class: Class to use for DEDL authentication (default: DEDLAuth)
        :param token_validator: Function to validate DEDL tokens (default: is_dedl_token_valid)
        """
        self.username = username
        self.password = password
        self.desp_access_token = None
        self.dedl_access_token = None
        self.desp_auth_class = desp_auth_class
        self.dedl_auth_class = dedl_auth_class
        self.token_validator = token_validator

    def get_token(self):
        """Performs the full authentication flow to retrieve a DEDL token."""

        if self.dedl_access_token:
            try:
                if self.token_validator(self.dedl_access_token):
                    return self.dedl_access_token
            except Exception as exc:
                logger.warning(
                    "Cached DEDL token validation failed due to validator backend issue; continuing with refresh flow (%s).",
                    type(exc).__name__,
                )

        # Get DESP auth token
        desp_auth = self.desp_auth_class(self.username, self.password)
        self.desp_access_token = desp_auth.get_desp_token()

        # Get DEDL auth token
        dedl_auth = self.dedl_auth_class(self.desp_access_token)
        self.dedl_access_token = dedl_auth.get_token()

        return self.dedl_access_token

    def get_roles(self, token):
        """
        Extracts roles from a DEDL token.
        :param token: DEDL JWT token
        :return: List of roles or None if not found/invalid token"""

        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
        except (jwt.PyJWTError, TypeError, ValueError):
            return None

        realm_access = decoded_token.get("realm_access") or {}
        roles = realm_access.get("roles")

        if isinstance(roles, list):
            return roles

        return None

    def is_DTaccess_allowed(self, token):
        """
        Checks if the DEDL token has the 'DPAD_Direct_Access' role.
        :param token: DEDL JWT token
        :return: True if access is allowed, False otherwise
        """

        roles = self.get_roles(token) or []

        is_allowed = "DPAD_Direct_Access" in roles
        logger.debug("DT output access check result: %s", is_allowed)

        return is_allowed
    

    def get_decoded_token(self, token):
        """
        Useful function for debugging and support.
        Token is provided as an argument which can be helpful for troubleshooting token-related issues.
        JWT Tokens are encoded not encrypted, this is normally not a security risk as long as the token is handled securely and not exposed to unauthorized parties.

        :param token: DEDL or DESP JWT token
        :return: Decoded token as a dictionary or raises ValueError if the token is invalid or not available.
        """

        if token:

            try:
                decoded_token = jwt.decode(token, options={"verify_signature": False})
                logger.debug("Decoded token successfully: %s", decoded_token)
                return decoded_token
            
            except (jwt.PyJWTError, TypeError, ValueError):
                raise ValueError("Failed to decode token. The token may be invalid or malformed.")
        
        else:
            raise ValueError("No token provided to decode.")

