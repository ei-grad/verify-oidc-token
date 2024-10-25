import argparse
import json
import logging
import sys

from jwt.exceptions import InvalidTokenError

from . import verify_token


def main():
    parser = argparse.ArgumentParser(description="Verify OIDC token.")
    parser.add_argument(
        "--token-file",
        help="File containing the OIDC token (if not specified, token is read from stdin).",
    )
    parser.add_argument("--issuer", required=True, help="Expected issuer of the token.")
    parser.add_argument(
        "--client-id", required=True, help="Expected client ID (audience) of the token."
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose logging for debugging."
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    if args.token_file:
        try:
            with open(args.token_file) as f:
                token = f.read().strip()
        except Exception as e:
            print(json.dumps({"error": f"Failed to read token file: {e}"}))
            sys.exit(1)
    else:
        token = sys.stdin.read().strip()

    try:
        claims = verify_token(token, args.issuer, args.client_id)
        print(json.dumps(claims, indent=2))
    except InvalidTokenError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
