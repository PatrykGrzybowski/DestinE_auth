#!/usr/bin/env python3
import argparse
from datetime import datetime, timezone
import json
import getpass
import os
import sys

import jwt

from destinelab import AuthHandler, DESPAuth, DEDLAuth
from destinelab.errors import AuthError, TokenExchangeError


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


def _print_decoded_token(token: str, label: str) -> None:
    try:
        decoded_token = jwt.decode(token, options={"verify_signature": False})
    except (jwt.PyJWTError, TypeError, ValueError):
        print(f"{label} decoded payload: <unable to decode token>")
        return

    print(f"{label} decoded payload:")
    print(json.dumps(decoded_token, indent=2, sort_keys=True))


def _print_token_expiry(token: str, label: str) -> None:
    try:
        decoded_token = jwt.decode(token, options={"verify_signature": False})
    except (jwt.PyJWTError, TypeError, ValueError):
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
    handler = AuthHandler(username="", password="")
    is_allowed = handler.is_DTaccess_allowed(token)
    print(f"{label} DT access allowed: {is_allowed}")


def _pick_value(cli_value: str, env_key: str, prompt: str, secret: bool = False) -> str:
    if cli_value:
        return cli_value
    env_val = os.getenv(env_key)
    if env_val:
        return env_val
    if secret:
        return getpass.getpass(prompt)
    return input(prompt).strip()


def cmd_e2e(args: argparse.Namespace) -> int:
    """
    End-to-end authentication flow: DESP credentials -> DEDL token.
    This demonstrates the simplest usage pattern via AuthHandler, which abstracts away the individual steps.

    A user gets a handler using their DESP credentials, then calls get_token() to perform the full flow and retrieve a DEDL token.
    This is the most common usage pattern for clients that just want to get a DEDL token and don't care about the intermediate steps or tokens.
    """
    username = _pick_value(args.username, "DESP_USERNAME", "DESP username: ")
    password = _pick_value(args.password, "DESP_PASSWORD", "DESP password: ", secret=True)

    handler = AuthHandler(username, password)
    dedl_token = handler.get_token()
    if not dedl_token:
        print("E2E auth did not return a DEDL token.")
        return 1

    _print_token_expiry(dedl_token, "DEDL token")
    _print_dt_access_allowed(dedl_token, "DEDL token")

    if args.full_token:
        print("Warning: printing full token to console.")
    print(f"E2E success. DEDL token: {_display_token(dedl_token, args.full_token)}")
    if args.full_token:
        _print_decoded_token(dedl_token, "DEDL token")
    return 0


def cmd_staged(args: argparse.Namespace) -> int:
    """
    Staged authentication flow: 
    run DESPAuth to get a DESP token, then use that token with DEDLAuth to get a DEDL token.
    This demonstrates how to use the individual auth classes separately, 
    which is useful for clients that need more control or want to handle the DESP and DEDL steps independently (e.g. caching the DESP token).
    """

    username = _pick_value(args.username, "DESP_USERNAME", "DESP username: ")
    password = _pick_value(args.password, "DESP_PASSWORD", "DESP password: ", secret=True)
    otp_code = _pick_value(args.otp, "DESP_OTP_CODE", "OTP (leave blank if not needed): ")

    desp = DESPAuth(username, password)
    desp_token = desp.get_token_otp(otp_code=otp_code or None)
    _print_token_expiry(desp_token, "DESP token")

    if args.full_token:
        print("Warning: printing full tokens to console.")
    print(f"DESP token acquired: {_display_token(desp_token, args.full_token)}")
    if args.full_token:
        _print_decoded_token(desp_token, "DESP token")

    dedl = DEDLAuth(desp_token, strict=True)
    dedl_token = dedl.get_token()
    _print_token_expiry(dedl_token, "DEDL token")
    _print_dt_access_allowed(dedl_token, "DEDL token")

    print(f"DEDL token acquired: {_display_token(dedl_token, args.full_token)}")
    if args.full_token:
        _print_decoded_token(dedl_token, "DEDL token")
    return 0


def cmd_roles(args: argparse.Namespace) -> int:
    """
    Inspect roles from a token using AuthHandler.get_roles.
    This is a utility command to help users understand the contents of their tokens and verify what roles they have.
    The user provides a token (either via CLI arg or env var), and the command decodes it and prints the roles it contains."""
    token = _pick_value(args.token, "DEDL_TOKEN", "Token to inspect roles: ")
    _print_token_expiry(token, "Input token")
    _print_dt_access_allowed(token, "Input token")

    handler = AuthHandler(username="", password="")
    roles = handler.get_roles(token) or []
    print("Roles:")
    for role in roles:
        print(f"- {role}")
    if not roles:
        print("(none)")
    return 0


def cmd_dt_access(args: argparse.Namespace) -> int:
    token = _pick_value(args.token, "DEDL_TOKEN", "Token to check DT access: ")
    _print_token_expiry(token, "Input token")

    handler = AuthHandler(username="", password="")
    allowed = handler.is_DTaccess_allowed(token)
    print(f"DT access allowed: {allowed}")
    return 0


def _print_quick_start() -> None:
    print("\nDestinE Auth Example")
    print("-" * 24)
    print("This script demonstrates the most common library usage patterns:")
    print("  1) End-to-end: DESP credentials -> DEDL token")
    print("  2) Staged flow: DESP token, then DEDL exchange")
    print("  3) Inspect roles from a token")
    print("  4) Check DT access from a token")
    print("\nTip: you can set DESP_USERNAME and DESP_PASSWORD env vars.\n")


def _interactive_choice() -> str:
    print("Choose an option:")
    print("  1) End-to-end token flow")
    print("  2) Staged DESP -> DEDL flow")
    print("  3) Decode roles from token")
    print("  4) Check DT access")
    print("  q) Quit")
    choice = input("Selection: ").strip().lower()
    mapping = {
        "1": "e2e",
        "2": "staged",
        "3": "roles",
        "4": "dt-access",
        "q": "quit",
    }
    return mapping.get(choice, "")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Practical destinelab auth CLI demo (DESP -> DEDL)."
    )
    subparsers = parser.add_subparsers(dest="command", required=False)

    common_auth = argparse.ArgumentParser(add_help=False)
    common_auth.add_argument("-u", "--username", help="DESP username (or DESP_USERNAME)")
    common_auth.add_argument("-p", "--password", help="DESP password (or DESP_PASSWORD)")

    token_output = argparse.ArgumentParser(add_help=False)
    token_output.add_argument(
        "--full-token",
        action="store_true",
        default=False, #Normally we would default to False for safety, but setting to True here for easier testing and demonstration. Use with caution.
        help="Print the full token value instead of a redacted preview.",
    )

    p_e2e = subparsers.add_parser(
        "e2e",
        parents=[common_auth, token_output],
        help="Run full DESP login + DEDL exchange via AuthHandler.",
    )
    p_e2e.set_defaults(func=cmd_e2e)

    p_staged = subparsers.add_parser(
        "staged",
        parents=[common_auth, token_output],
        help="Run DESPAuth then DEDLAuth as separate steps.",
    )
    p_staged.add_argument("--otp", help="OTP code (or DESP_OTP_CODE)")
    p_staged.set_defaults(func=cmd_staged)

    p_roles = subparsers.add_parser(
        "roles",
        help="Decode token roles using AuthHandler.get_roles.",
    )
    p_roles.add_argument("--token", help="JWT token (or DEDL_TOKEN)")
    p_roles.set_defaults(func=cmd_roles)

    p_dt = subparsers.add_parser(
        "dt-access",
        help="Check DPAD_Direct_Access role with AuthHandler.is_DTaccess_allowed.",
    )
    p_dt.add_argument("--token", help="JWT token (or DEDL_TOKEN)")
    p_dt.set_defaults(func=cmd_dt_access)

    return parser


def main() -> int:
    parser = build_parser()

    if len(sys.argv) == 1:
        _print_quick_start()
        chosen = _interactive_choice()
        if chosen == "quit":
            print("Bye.")
            return 0
        if not chosen:
            print("Invalid selection.")
            return 1
        args = parser.parse_args([chosen])
    else:
        args = parser.parse_args()

    if not getattr(args, "command", None):
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except (AuthError, TokenExchangeError) as exc:
        print(f"Auth error: {exc}")
        return 2
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130
    except Exception as exc:
        print(f"Unexpected error: {exc}")
        return 99


if __name__ == "__main__":
    sys.exit(main())