import argparse
import json
import logging
import sys

import jwt
from jwt.exceptions import InvalidTokenError

from . import UNSAFE_FROM_TOKEN, verify_token


def main():
    parser = argparse.ArgumentParser(description="Verify an OpenID Connect ID Token.")
    parser.add_argument(
        "--token-file",
        help="File containing the OIDC ID Token (if omitted, the token is read from stdin).",
    )
    parser.add_argument(
        "--issuer",
        help="Expected OIDC issuer. Required unless --unsafe is given.",
    )
    parser.add_argument(
        "--client-id",
        help="Expected OIDC client ID (the ID Token audience). Required unless --unsafe is given.",
    )
    parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Take a missing expected issuer or client audience from the unverified ID Token"
        " payload, making those checks self-referential. Signature verification and other token"
        " validation still run. Debugging only.",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose logging for debugging."
    )
    parser.add_argument(
        "--with-header",
        action="store_true",
        help="Include the decoded JWT header alongside the verified claims.",
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
            sys.exit(2)
    else:
        token = sys.stdin.read().strip()

    issuer = args.issuer if args.issuer else UNSAFE_FROM_TOKEN
    client_id = args.client_id if args.client_id else UNSAFE_FROM_TOKEN

    try:
        claims = verify_token(token, issuer, client_id)
        output = (
            {"header": jwt.get_unverified_header(token), "claims": claims}
            if args.with_header
            else claims
        )
        print(json.dumps(output, indent=2))
    except InvalidTokenError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
