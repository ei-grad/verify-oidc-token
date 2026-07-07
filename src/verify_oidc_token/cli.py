import argparse
import json
import logging
import sys

from jwt.exceptions import InvalidTokenError

from . import UNSAFE_FROM_TOKEN, verify_token


def main():
    parser = argparse.ArgumentParser(description="Verify OIDC token.")
    parser.add_argument(
        "--token-file",
        help="File containing the OIDC token (if not specified, token is read from stdin).",
    )
    parser.add_argument(
        "--issuer",
        help="Expected issuer of the token. Required unless --unsafe is given.",
    )
    parser.add_argument(
        "--client-id",
        help="Expected client ID (audience) of the token. Required unless --unsafe is given.",
    )
    parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Allow a missing --issuer / --client-id to be taken from the unverified"
        " token payload. The corresponding check becomes self-referential: the token"
        " is verified against whatever issuer/audience it claims itself. Debugging only.",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose logging for debugging."
    )

    args = parser.parse_args()

    # Empty strings are treated the same as missing values.
    if not args.unsafe and (not args.issuer or not args.client_id):
        parser.error("--issuer and --client-id are required (or pass --unsafe)")

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    if args.token_file:
        try:
            with open(args.token_file) as f:
                token = f.read().strip()
        # Any I/O or decoding error must surface as a JSON error message on stdout.
        except Exception as e:
            print(json.dumps({"error": f"Failed to read token file: {e}"}))
            sys.exit(1)
    else:
        token = sys.stdin.read().strip()

    issuer = args.issuer if args.issuer else UNSAFE_FROM_TOKEN
    client_id = args.client_id if args.client_id else UNSAFE_FROM_TOKEN

    try:
        claims = verify_token(token, issuer, client_id)
        print(json.dumps(claims, indent=2))
    except InvalidTokenError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
