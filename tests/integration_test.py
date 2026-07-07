import json
import subprocess
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import base64url_encode

from verify_oidc_token import verify_token

# Generate RSA keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

kid = "test-key-id"


# Convert the RSA public numbers (n, e) to base64url encoded strings
def int_to_base64url(n):
    byte_length = (n.bit_length() + 7) // 8
    return base64url_encode(n.to_bytes(byte_length, byteorder="big")).decode("utf-8")


jwks = {
    "keys": [
        {
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": int_to_base64url(public_key.public_numbers().n),
            "e": int_to_base64url(public_key.public_numbers().e),
        }
    ]
}


class OIDCServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            config = {
                "issuer": ISSUER,
                "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
            }
            self.wfile.write(json.dumps(config).encode("utf-8"))

        elif self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(jwks).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()


# Port 0 lets the OS pick a free port; binding happens in the HTTPServer constructor,
# so the server is ready to accept connections before the tests start.
_server = HTTPServer(("localhost", 0), OIDCServerHandler)
ISSUER = f"http://localhost:{_server.server_address[1]}"
threading.Thread(target=_server.serve_forever, daemon=True).start()


class IntegrationTestVerifyToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Generate a valid token with the private key
        cls.token = jwt.encode(
            {
                "iss": ISSUER,
                "sub": "user-123",
                "aud": "test-client-id",
                "iat": int(time.time()),
                "exp": int(time.time()) + 600,  # Expires in 10 minutes
            },
            private_key,
            algorithm="RS256",
            headers={"kid": kid},
        )

    def test_verify_token_success(self):
        # Test successful verification of a valid token
        claims = verify_token(token=self.token, issuer=ISSUER, client_id="test-client-id")
        self.assertEqual(claims["iss"], ISSUER)
        self.assertEqual(claims["aud"], "test-client-id")
        self.assertEqual(claims["sub"], "user-123")

    def test_verify_token_invalid_audience(self):
        # Test verification fails for an invalid audience
        with self.assertRaises(jwt.InvalidTokenError) as context:
            verify_token(token=self.token, issuer=ISSUER, client_id="invalid-client-id")
        self.assertIn("audience", str(context.exception).lower())

    def test_verify_token_expired(self):
        # Create an expired token and test that it fails verification
        expired_token = jwt.encode(
            {
                "iss": ISSUER,
                "sub": "user-123",
                "aud": "test-client-id",
                "iat": int(time.time()) - 600,
                "exp": int(time.time()) - 300,  # Expired 5 minutes ago
            },
            private_key,
            algorithm="RS256",
            headers={"kid": kid},
        )
        with self.assertRaises(jwt.InvalidTokenError) as context:
            verify_token(token=expired_token, issuer=ISSUER, client_id="test-client-id")
        self.assertIn("expired", str(context.exception))

    def test_cli_verify_token_success(self):
        result = subprocess.run(
            [
                "verify-oidc-token",
                "--issuer",
                ISSUER,
                "--client-id",
                "test-client-id",
            ],
            input=self.token,
            text=True,
            capture_output=True,
            check=True,
        )

        output = json.loads(result.stdout)
        self.assertEqual(output["iss"], ISSUER)
        self.assertEqual(output["aud"], "test-client-id")
        self.assertEqual(output["sub"], "user-123")

    def test_cli_verify_token_auto_discovery(self):
        # With --unsafe and no --issuer/--client-id the CLI falls back to the
        # take-it-from-the-token mode
        result = subprocess.run(
            ["verify-oidc-token", "--unsafe"],
            input=self.token,
            text=True,
            capture_output=True,
            check=True,
        )

        output = json.loads(result.stdout)
        self.assertEqual(output["iss"], ISSUER)
        self.assertEqual(output["sub"], "user-123")

    def test_cli_missing_issuer_without_unsafe(self):
        result = subprocess.run(
            ["verify-oidc-token"],
            input=self.token,
            text=True,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("--issuer and --client-id are required", result.stderr)

    def test_cli_verify_token_expired(self):
        expired_token = jwt.encode(
            {
                "iss": ISSUER,
                "aud": "test-client-id",
                "sub": "user-123",
                "iat": int(time.time()) - 1200,  # Issued 20 minutes ago
                "exp": int(time.time()) - 600,  # Expired 10 minutes ago
            },
            private_key,
            algorithm="RS256",
            headers={"kid": kid},
        )

        result = subprocess.run(
            [
                "verify-oidc-token",
                "--issuer",
                ISSUER,
                "--client-id",
                "test-client-id",
            ],
            input=expired_token,
            text=True,
            capture_output=True,
        )

        # The CLI must exit with a non-zero code and report the error as JSON on stdout
        self.assertNotEqual(result.returncode, 0)
        try:
            error_output = json.loads(result.stdout)
            self.assertIn("error", error_output)
            self.assertIn("expired", error_output["error"])
        except json.JSONDecodeError:
            self.fail("Error output is not valid JSON")


if __name__ == "__main__":
    unittest.main()
