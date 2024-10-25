import json
import subprocess
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import base64url_encode

from verify_oidc_token import verify_token

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
public_key = private_key.public_key()

# Serialize the public key to JWK format
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
            config = {"jwks_uri": "http://localhost:5001/.well-known/jwks.json"}
            self.wfile.write(json.dumps(config).encode("utf-8"))

        elif self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(jwks).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()


def run_server():
    server = HTTPServer(("localhost", 5001), OIDCServerHandler)
    server.serve_forever()


server_thread = threading.Thread(target=run_server)
server_thread.daemon = True
server_thread.start()

# Wait for the server to start
time.sleep(1)


class IntegrationTestVerifyToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Generate a valid token with the private key
        cls.token = jwt.encode(
            {
                "iss": "http://localhost:5001",
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
        claims = verify_token(
            token=self.token, issuer="http://localhost:5001", client_id="test-client-id"
        )
        self.assertEqual(claims["iss"], "http://localhost:5001")
        self.assertEqual(claims["aud"], "test-client-id")
        self.assertEqual(claims["sub"], "user-123")

    def test_verify_token_invalid_audience(self):
        # Test verification fails for an invalid audience
        with self.assertRaises(jwt.InvalidTokenError) as context:
            verify_token(
                token=self.token,
                issuer="http://localhost:5001",
                client_id="invalid-client-id",
            )
        self.assertIn("Invalid token audience", str(context.exception))

    def test_verify_token_expired(self):
        # Create an expired token and test that it fails verification
        expired_token = jwt.encode(
            {
                "iss": "http://localhost:5001",
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
            verify_token(
                token=expired_token,
                issuer="http://localhost:5001",
                client_id="test-client-id",
            )
        self.assertIn("Token has expired", str(context.exception))

    def test_cli_verify_token_success(self):
        # Генерируем токен с использованием приватного ключа
        valid_token = jwt.encode(
            {
                "iss": "http://localhost:5001",
                "aud": "test-client-id",
                "sub": "user-123",
                "iat": int(time.time()),
                "exp": int(time.time()) + 600,  # Expires in 10 minutes
            },
            private_key,
            algorithm="RS256",
            headers={"kid": kid},
        )

        # Запускаем CLI команду через subprocess
        result = subprocess.run(
            [
                "verify-oidc-token",
                "--issuer",
                "http://localhost:5001",
                "--client-id",
                "test-client-id",
            ],
            input=valid_token,
            text=True,
            capture_output=True,
            check=True,
        )

        # Парсим выходные данные и проверяем, что они соответствуют ожидаемым claims
        output = json.loads(result.stdout)
        self.assertEqual(output["iss"], "http://localhost:5001")
        self.assertEqual(output["aud"], "test-client-id")
        self.assertEqual(output["sub"], "user-123")

    def test_cli_verify_token_expired(self):
        # Генерируем истёкший токен
        expired_token = jwt.encode(
            {
                "iss": "http://localhost:5001",
                "aud": "test-client-id",
                "sub": "user-123",
                "iat": int(time.time()) - 1200,  # Issued 20 minutes ago
                "exp": int(time.time()) - 600,  # Expired 10 minutes ago
            },
            private_key,
            algorithm="RS256",
            headers={"kid": kid},
        )

        # Запускаем CLI команду через subprocess, проверяя, что она завершается с ненулевым кодом
        result = subprocess.run(
            [
                "verify-oidc-token",
                "--issuer",
                "http://localhost:5001",
                "--client-id",
                "test-client-id",
            ],
            input=expired_token,
            text=True,
            capture_output=True,
        )

        # Проверяем, что код завершения ненулевой (ошибка)
        self.assertNotEqual(result.returncode, 0)

        # Парсим вывод как JSON и проверяем сообщение об истечении токена
        try:
            error_output = json.loads(result.stdout)  # Теперь используем stdout
            self.assertIn("error", error_output)
            self.assertIn("Token has expired", error_output["error"])
        except json.JSONDecodeError:
            self.fail("Error output is not valid JSON")


if __name__ == "__main__":
    unittest.main()
