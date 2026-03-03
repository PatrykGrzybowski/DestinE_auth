import jwt
from jwt import PyJWKClient
from keycloak import KeycloakOpenID

from ..config import (
    DEDL_CLIENT_ID,
    DEDL_KEYCLOAK_REALM,
    DEDL_KEYCLOAK_SERVER_URL,
    DEFAULT_TIMEOUT_SECONDS,
)


def is_dedl_token_valid(
    token,
    timeout=DEFAULT_TIMEOUT_SECONDS,
    keycloak_openid_class=KeycloakOpenID,
    jwk_client_class=PyJWKClient,
):
    """Validate a DEDL access token against DEDL Keycloak JWKS metadata."""

    if not isinstance(token, str) or not token.strip():
        return False

    try:
        # Initialize KeycloakOpenID to fetch JWKS metadata
        keycloak_openid = keycloak_openid_class(
            server_url=DEDL_KEYCLOAK_SERVER_URL,
            client_id=DEDL_CLIENT_ID,
            realm_name=DEDL_KEYCLOAK_REALM,
            timeout=timeout,
        )

        # Fetch JWKS URI from Keycloak metadata and get the signing key for the token
        well_known = keycloak_openid.well_known()
        jwks_uri = well_known["jwks_uri"]

        # Get the signing key for the token using the JWKS URI
        signing_key = jwk_client_class(jwks_uri).get_signing_key_from_jwt(token)

        # Decode and validate the token using the signing key
        # This will raise an exception if the token is invalid or expired
        jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )

        return True

    except jwt.ExpiredSignatureError as e:
        print(f"Token expired: {e}")
        return False

    except jwt.PyJWTError as e:
        print(f"JWT validation error: {type(e).__name__}: {e}")
        return False

    except (KeyError, TypeError, ValueError) as e:
        print(f"Keycloak metadata error: {e}")
        return False
