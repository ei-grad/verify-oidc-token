import sys
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import jwt
from jwt import InvalidTokenError

from verify_oidc_token import verify_token

# Fix deprecation warnings in tests:
# * datetime.utcnow is deprecated in Python 3.12+
# * datetime.UTC is available in Python 3.11+
if sys.version_info < (3, 11):
    utcnow = datetime.utcnow
else:
    from datetime import UTC

    def utcnow():
        return datetime.now(UTC)


class TestVerifyToken(unittest.TestCase):
    def setUp(self):
        # Патчим requests.get и PyJWKClient.get_signing_key_from_jwt для всех тестов
        self.patcher_requests_get = patch("verify_oidc_token.requests.get")
        self.patcher_get_signing_key = patch("jwt.PyJWKClient.get_signing_key_from_jwt")

        # Старт патчей
        self.mock_requests_get = self.patcher_requests_get.start()
        self.mock_get_signing_key = self.patcher_get_signing_key.start()

        # Настраиваем mock ответа для OIDC конфигурации
        mock_oidc_config_response = MagicMock()
        mock_oidc_config_response.json.return_value = {
            "jwks_uri": "https://example.com/.well-known/jwks.json",
            "id_token_signing_alg_values_supported": ["HS256"],
        }
        self.mock_requests_get.return_value = mock_oidc_config_response

        # Настраиваем mock ключа подписи
        self.mock_signing_key = MagicMock()
        self.mock_signing_key.key = "mock_key"
        self.mock_get_signing_key.return_value = self.mock_signing_key

    def tearDown(self):
        # Останавливаем патчи после каждого теста
        self.patcher_requests_get.stop()
        self.patcher_get_signing_key.stop()

    def test_verify_token_success(self):
        valid_token = jwt.encode(
            {
                "iss": "https://example.com",
                "aud": "test-client-id",
                "sub": "user-123",
                "iat": utcnow(),
                "exp": utcnow() + timedelta(hours=1),
            },
            "mock_key",
            algorithm="HS256",
        )

        expected_claims = {
            "iss": "https://example.com",
            "aud": "test-client-id",
            "sub": "user-123",
            "iat": utcnow(),
            "exp": utcnow() + timedelta(hours=1),
        }

        with patch("jwt.decode", return_value=expected_claims):
            claims = verify_token(
                token=valid_token,
                issuer="https://example.com",
                client_id="test-client-id",
            )

        self.assertEqual(claims, expected_claims)
        self.mock_requests_get.assert_called_once_with(
            "https://example.com/.well-known/openid-configuration"
        )
        self.mock_get_signing_key.assert_called_once_with(valid_token)

    def test_invalid_issuer_error(self):
        invalid_issuer_token = jwt.encode(
            {
                "iss": "https://wrong-issuer.com",
                "aud": "test-client-id",
                "sub": "user-123",
                "iat": utcnow(),
                "exp": utcnow() + timedelta(hours=1),
            },
            "mock_key",
            algorithm="HS256",
        )

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(
                token=invalid_issuer_token,
                issuer="https://example.com",
                client_id="test-client-id",
            )

        self.assertIn("Invalid token issuer", str(context.exception))

    def test_expired_token_error(self):
        expired_token = jwt.encode(
            {
                "iss": "https://example.com",
                "aud": "test-client-id",
                "sub": "user-123",
                "iat": utcnow() - timedelta(hours=2),
                "exp": utcnow() - timedelta(hours=1),
            },
            "mock_key",
            algorithm="HS256",
        )

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(
                token=expired_token,
                issuer="https://example.com",
                client_id="test-client-id",
            )

        self.assertIn("Token has expired", str(context.exception))

    def test_invalid_audience_error(self):
        wrong_audience_token = jwt.encode(
            {
                "iss": "https://example.com",
                "aud": "wrong-client-id",
                "sub": "user-123",
                "iat": utcnow(),
                "exp": utcnow() + timedelta(hours=1),
            },
            "mock_key",
            algorithm="HS256",
        )

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(
                token=wrong_audience_token,
                issuer="https://example.com",
                client_id="test-client-id",
            )

        self.assertIn("Invalid token audience", str(context.exception))


if __name__ == "__main__":
    unittest.main()
