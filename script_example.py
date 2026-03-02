#!/usr/bin/env python3
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Optional

from dotenv import load_dotenv
import jwt

from destinelab import AuthHandler, DEDLServiceAccountAuth, DESPAuth, DEDLAuth

load_dotenv()  # loads .env into os.environ


def _token_preview(token: str) -> str:
    if not token:
        return "<empty>"
    if len(token) <= 12:
        return "*" * len(token)
    return f"{token[:6]}...{token[-6:]}"


def _display_token(token: str, show_full: bool) -> str:
    if show_full:
        return token
    return _token_preview(token)


def _decode_token_payload(token: str):
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except (jwt.PyJWTError, TypeError, ValueError):
        return None


def _file_safe_user_string(user_string: str) -> str:
    normalized = (user_string or "").strip().lower()
    normalized = re.sub(r"[^a-z0-9._-]+", "_", normalized)
    normalized = normalized.strip("._-")
    return normalized or "unknown_user"


def _build_token_dump_path(
    user_string: str, token_kind: str, timestamp: datetime = None
) -> Path:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    safe_user = _file_safe_user_string(user_string)
    stamp = timestamp.strftime("%Y%m%d_%H%M%S")
    return Path("tokens") / safe_user / f"{stamp}_{token_kind}.json"


def _write_full_token_dump(token: str, user_string: str, token_kind: str) -> None:
    decoded_payload = _decode_token_payload(token)
    output_payload = {
        "original_token": token,
        "decoded_token": decoded_payload,
    }
    if decoded_payload is None:
        output_payload["decode_error"] = "unable to decode token"

    output_path = _build_token_dump_path(user_string=user_string, token_kind=token_kind)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file_obj:
        json.dump(output_payload, file_obj, indent=2, sort_keys=True)
        file_obj.write("\n")

    print(f"{token_kind.upper()} token dump saved to: {output_path}")


def _print_decoded_token(token: str, label: str) -> None:
    decoded_token = _decode_token_payload(token)
    if decoded_token is None:
        print(f"{label} decoded payload: <unable to decode token>")
        return

    print(f"{label} decoded payload:")
    print(json.dumps(decoded_token, indent=2, sort_keys=True))


def _print_token_expiry(token: str, label: str) -> None:
    decoded_token = _decode_token_payload(token)
    if decoded_token is None:
        print(f"{label} expiry (UTC): <unable to decode token>")
        return

    expiry_unix = decoded_token.get("exp")
    if expiry_unix is None:
        print(f"{label} expiry (UTC): <no exp claim>")
        return

    try:
        expiry_dt = datetime.fromtimestamp(int(expiry_unix), tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        print(f"{label} expiry (UTC): <invalid exp claim>")
        return

    print(f"{label} expiry (UTC): {expiry_dt.strftime('%Y-%m-%d %H:%M:%S %Z')}")

    now_utc = datetime.now(timezone.utc)
    remaining_seconds = int((expiry_dt - now_utc).total_seconds())
    if remaining_seconds <= 0:
        print(f"{label} time remaining: expired ({abs(remaining_seconds)}s ago)")
        return

    hours, remainder = divmod(remaining_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    print(f"{label} time remaining: {hours}h {minutes}m {seconds}s")


def _print_dt_access_allowed(token: str, label: str) -> None:
    """
    This function could in principle be used on Both DESP and DEDL tokens, but in practice the DPAD_Direct_Access role is only relevant for DEDL tokens since that's what controls access to DT output.
    """
    handler = AuthHandler(username="", password="")
    is_allowed = handler.is_DTaccess_allowed(token)
    print(f"{label} DT access allowed: {is_allowed}")


def _print_roles(token: str, label: str) -> None:
    """
    Print the roles of the provided token.
    """

    handler = AuthHandler(username="", password="")
    roles = handler.get_roles(token) or []
    print("Roles:")
    for role in roles:
        print(f"- {role}")
    if not roles:
        print("(none)")


def _print_banner(message: str) -> None:
    print("\n" + "=" * 60)
    print(message)
    print("=" * 60 + "\n")


def _print_info_token(
    token: str, token_label: str, username: str, is_print_full_token: bool
) -> None:

    # Token expiry
    _print_token_expiry(token, token_label)
    # DTAccess allowed
    _print_dt_access_allowed(token, token_label)
    # Roles
    _print_roles(token, token_label)

    if is_print_full_token:
        print("Warning: printing full token to console.")
        _print_decoded_token(token, token_label)
        _write_full_token_dump(token, username, "dedl")

    print(f"Standard success. DEDL token: {_display_token(token, is_print_full_token)}")


def run_standard_authentication(
    username: str,
    password: str,
    otp_code: Optional[str] = None,
    is_print_full_token: bool = False,
) -> None:
    """
    Standard authentication flow using AuthHandler, which abstracts the full process of obtaining a DEDL token from DESP credentials.
    """

    _print_banner("START: Running standard authentication flow")

    # Standard flow with AuthHandler, which abstracts the steps and returns a DEDL token directly.
    handler = AuthHandler(username, password)
    dedl_token = handler.get_token()
    if not dedl_token:
        raise ValueError("Failed to obtain DEDL token in standard authentication flow.")

    _print_info_token(
        dedl_token, "DEDL token", username, is_print_full_token=is_print_full_token
    )

    _print_banner("END: Running standard authentication flow")


def run_staged_authentication(
    username: str,
    password: str,
    otp_code: Optional[str] = None,
    is_print_full_token: bool = False,
) -> None:
    """
    Staged authentication flow:
    run DESPAuth to get a DESP token, then use that token with DEDLAuth to get a DEDL token.
    This demonstrates how to use the individual auth classes separately,
    which is useful for clients that need more control or want to handle the DESP and DEDL steps independently (e.g. caching the DESP token).
    """

    _print_banner("START: Running staged authentication flow")

    ##################################################

    desp = DESPAuth(username, password)
    desp_token = desp.get_desp_token(otp_code=otp_code or None)

    _print_info_token(
        desp_token, "DESP token", username, is_print_full_token=is_print_full_token
    )

    ##################################################

    dedl = DEDLAuth(desp_token, strict=True)
    dedl_token = dedl.get_token()
    if not dedl_token:
        raise ValueError("Failed to obtain DEDL token in staged authentication flow.")

    _print_info_token(
        dedl_token, "DEDL token", username, is_print_full_token=is_print_full_token
    )

    ##################################################

    _print_banner("END: Running staged authentication flow")


def run_service_account_authentication(
    client_id: str, client_secret: str, is_print_full_token: bool = False
) -> None:
    """
    Service-account authentication flow:
    use DEDL client credentials grant to obtain a DEDL token directly.
    """
    _print_banner("START: Running service-account authentication flow")

    dedl_token = DEDLServiceAccountAuth(
        client_id=client_id,
        client_secret=client_secret,
        strict=True,
    ).get_token()
    if not dedl_token:
        raise ValueError(
            "Failed to obtain DEDL token in service-account authentication flow."
        )

    _print_info_token(
        dedl_token, "DEDL token", client_id, is_print_full_token=is_print_full_token
    )

    _print_banner("END: Running service-account authentication flow")


if __name__ == "__main__":

    RUN_MODE = "staged"  # "standard" | "staged" | "service-account"
    FULL_TOKEN_OUTPUT = True

    # If we are running in standard mode we need DESP credentials.
    if RUN_MODE in ("standard", "staged"):

        desp_username = os.getenv("DESP_USERNAME")
        desp_password = os.getenv("DESP_PASSWORD")
        desp_otp_code = os.getenv(
            "DESP_OTP_CODE"
        )  # optional OTP code for accounts with MFA

        if not desp_username or not desp_password:
            raise ValueError(
                "Error: DESP_USERNAME and DESP_PASSWORD must be set in the .env file to run this script."
            )

        if RUN_MODE == "standard":

            run_standard_authentication(
                username=desp_username,
                password=desp_password,
                is_print_full_token=FULL_TOKEN_OUTPUT,
            )

        else:  # RUN_MODE == "staged"

            run_staged_authentication(
                username=desp_username,
                password=desp_password,
                otp_code=desp_otp_code,
                is_print_full_token=FULL_TOKEN_OUTPUT,
            )

    elif RUN_MODE == "service-account":

        client_id = os.getenv("DEDL_CLIENT_ID")
        client_secret = os.getenv("DEDL_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise ValueError(
                "Error: DEDL_CLIENT_ID and DEDL_CLIENT_SECRET must be set in the .env file to run this script in service-account mode."
            )

        run_service_account_authentication(
            client_id=client_id,
            client_secret=client_secret,
            is_print_full_token=FULL_TOKEN_OUTPUT,
        )

    else:

        print(
            f"Error: invalid RUN_MODE '{RUN_MODE}' in script. Must be 'standard', 'staged', or 'service-account'."
        )
