import json
import sys
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt import InvalidTokenError
from jwt.exceptions import PyJWKClientError

from verify_oidc_token import REQUEST_TIMEOUT, UNSAFE_FROM_TOKEN, verify_token

# Fix deprecation warnings in tests:
# * datetime.utcnow is deprecated in Python 3.12+
# * datetime.UTC is available in Python 3.11+
if sys.version_info < (3, 11):
    utcnow = datetime.utcnow
else:
    from datetime import UTC

    def utcnow():
        return datetime.now(UTC)


ISSUER = "https://example.com"
CLIENT_ID = "test-client-id"

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()


def make_token(**overrides):
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-123",
        "iat": utcnow(),
        "exp": utcnow() + timedelta(hours=1),
    }
    for claim, value in overrides.items():
        if value is None:
            payload.pop(claim, None)
        else:
            payload[claim] = value
    return jwt.encode(payload, private_key, algorithm="RS256")


class TestVerifyToken(unittest.TestCase):
    def setUp(self):
        # Patch requests.get and PyJWKClient.get_signing_key_from_jwt for all tests
        self.patcher_requests_get = patch("verify_oidc_token.requests.get")
        self.patcher_get_signing_key = patch("jwt.PyJWKClient.get_signing_key_from_jwt")

        self.mock_requests_get = self.patcher_requests_get.start()
        self.addCleanup(self.patcher_requests_get.stop)
        self.mock_get_signing_key = self.patcher_get_signing_key.start()
        self.addCleanup(self.patcher_get_signing_key.stop)

        # Mutable per-test OIDC configuration returned by the mocked discovery request
        self.oidc_config = {
            "issuer": ISSUER,
            "jwks_uri": "https://example.com/.well-known/jwks.json",
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        mock_oidc_config_response = MagicMock()
        mock_oidc_config_response.json.side_effect = lambda: self.oidc_config
        self.mock_requests_get.return_value = mock_oidc_config_response

        self.mock_signing_key = MagicMock()
        self.mock_signing_key.key = public_key
        self.mock_get_signing_key.return_value = self.mock_signing_key

    def test_sentinel_repr(self):
        self.assertEqual(repr(UNSAFE_FROM_TOKEN), "UNSAFE_FROM_TOKEN")

    def test_verify_token_success(self):
        valid_token = make_token()

        claims = verify_token(token=valid_token, issuer=ISSUER, client_id=CLIENT_ID)

        self.assertEqual(claims["iss"], ISSUER)
        self.assertEqual(claims["aud"], CLIENT_ID)
        self.assertEqual(claims["sub"], "user-123")
        self.mock_requests_get.assert_called_once_with(
            "https://example.com/.well-known/openid-configuration",
            timeout=REQUEST_TIMEOUT,
        )
        self.mock_get_signing_key.assert_called_once_with(valid_token)

    def test_issuer_and_client_id_from_token(self):
        claims = verify_token(
            token=make_token(),
            issuer=UNSAFE_FROM_TOKEN,
            client_id=UNSAFE_FROM_TOKEN,
        )
        self.assertEqual(claims["sub"], "user-123")

    def test_none_issuer_rejected(self):
        with self.assertRaises(TypeError):
            verify_token(token=make_token(), issuer=None, client_id=CLIENT_ID)

    def test_none_client_id_rejected(self):
        with self.assertRaises(TypeError):
            verify_token(token=make_token(), issuer=ISSUER, client_id=None)

    def test_non_str_argument_types_rejected(self):
        for issuer, client_id in [
            (42, CLIENT_ID),
            (b"https://example.com", CLIENT_ID),
            (ISSUER, 42),
            (ISSUER, [CLIENT_ID]),
        ]:
            with self.subTest(issuer=issuer, client_id=client_id):
                with self.assertRaises(TypeError):
                    verify_token(token=make_token(), issuer=issuer, client_id=client_id)

    def test_unsafe_mode_missing_iss_claim(self):
        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(iss=None), issuer=UNSAFE_FROM_TOKEN, client_id=CLIENT_ID)
        self.assertIn("iss", str(context.exception))

    def test_unsafe_mode_missing_aud_claim(self):
        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(aud=None), issuer=ISSUER, client_id=UNSAFE_FROM_TOKEN)
        self.assertIn("aud", str(context.exception))

    def test_unsafe_mode_non_string_iss_rejected(self):
        # jwt.encode itself refuses to create a token with a non-string iss (PyJWT 2.11+),
        # so sign the raw payload via PyJWS to bypass the encode-time validation.
        payload = {
            "iss": 123,
            "aud": CLIENT_ID,
            "sub": "user-123",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        token = jwt.PyJWS().encode(json.dumps(payload).encode(), private_key, algorithm="RS256")

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=token, issuer=UNSAFE_FROM_TOKEN, client_id=CLIENT_ID)
        self.assertIn("not a string", str(context.exception))

    def test_unsafe_mode_non_string_aud_rejected(self):
        for aud in (123, [123]):
            with self.subTest(aud=aud):
                with self.assertRaises(InvalidTokenError) as context:
                    verify_token(
                        token=make_token(aud=aud),
                        issuer=ISSUER,
                        client_id=UNSAFE_FROM_TOKEN,
                    )
                self.assertIn("not a string", str(context.exception))

    def test_unsafe_mode_single_element_audience_list(self):
        claims = verify_token(
            token=make_token(aud=[CLIENT_ID]),
            issuer=ISSUER,
            client_id=UNSAFE_FROM_TOKEN,
        )
        self.assertEqual(claims["aud"], [CLIENT_ID])

    def test_invalid_issuer_error(self):
        invalid_issuer_token = make_token(iss="https://wrong-issuer.com")

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=invalid_issuer_token, issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("issuer", str(context.exception).lower())

    def test_expired_token_error(self):
        expired_token = make_token(
            iat=utcnow() - timedelta(hours=2),
            exp=utcnow() - timedelta(hours=1),
        )

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=expired_token, issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("expired", str(context.exception))

    def test_invalid_audience_error(self):
        wrong_audience_token = make_token(aud="wrong-client-id")

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=wrong_audience_token, issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("audience", str(context.exception).lower())

    def test_missing_required_claims_rejected(self):
        for claim in ("exp", "iat"):
            with self.subTest(claim=claim):
                with self.assertRaises(InvalidTokenError) as context:
                    verify_token(
                        token=make_token(**{claim: None}),
                        issuer=ISSUER,
                        client_id=CLIENT_ID,
                    )
                self.assertIn(claim, str(context.exception).lower())

    def test_discovery_request_failure_wrapped(self):
        self.mock_requests_get.side_effect = requests.RequestException("connection refused")

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("Unable to retrieve OIDC configuration", str(context.exception))

    def test_discovery_http_error_wrapped(self):
        self.mock_requests_get.return_value.raise_for_status.side_effect = requests.HTTPError(
            "404 Client Error"
        )

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("Unable to retrieve OIDC configuration", str(context.exception))

    def test_discovery_invalid_json_wrapped(self):
        self.mock_requests_get.return_value.json.side_effect = ValueError("No JSON")

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("Unable to retrieve OIDC configuration", str(context.exception))

    def test_missing_or_invalid_jwks_uri(self):
        for jwks_uri in (None, 12345):
            with self.subTest(jwks_uri=jwks_uri):
                if jwks_uri is None:
                    del self.oidc_config["jwks_uri"]
                else:
                    self.oidc_config["jwks_uri"] = jwks_uri

                with self.assertRaises(InvalidTokenError) as context:
                    verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

                self.assertIn("jwks_uri", str(context.exception))

    def test_non_list_supported_algorithms_rejected(self):
        self.oidc_config["id_token_signing_alg_values_supported"] = "RS256"

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("expected a list", str(context.exception))

    def test_jwks_client_gets_timeout(self):
        with patch("verify_oidc_token.PyJWKClient") as mock_client_cls:
            mock_client_cls.return_value.get_signing_key_from_jwt.return_value = (
                self.mock_signing_key
            )
            claims = verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        mock_client_cls.assert_called_once_with(
            "https://example.com/.well-known/jwks.json", timeout=REQUEST_TIMEOUT
        )
        self.assertEqual(claims["sub"], "user-123")

    def test_signing_key_retrieval_failure_wrapped(self):
        self.mock_get_signing_key.side_effect = PyJWKClientError("Unable to find a signing key")

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("Unable to retrieve signing key", str(context.exception))

    def test_default_algorithms_when_not_announced(self):
        del self.oidc_config["id_token_signing_alg_values_supported"]

        claims = verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertEqual(claims["sub"], "user-123")

    def test_multi_audience_requires_explicit_client_id(self):
        multi_audience_token = make_token(aud=[CLIENT_ID, "other-client"])

        with self.assertRaises(InvalidTokenError):
            verify_token(
                token=multi_audience_token,
                issuer=ISSUER,
                client_id=UNSAFE_FROM_TOKEN,
            )

    def test_config_issuer_mismatch(self):
        self.oidc_config["issuer"] = "https://evil.example.org"

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("mismatch", str(context.exception).lower())

    def test_alg_key_type_mismatch_raises_invalid_token_error(self):
        # A forged token declaring an alg from a different key family than the resolved
        # signing key must surface as InvalidTokenError, not a raw TypeError from the
        # cryptography layer.
        self.oidc_config["id_token_signing_alg_values_supported"] = ["RS256", "ES256"]
        ec_key = ec.generate_private_key(ec.SECP256R1())
        forged_token = jwt.encode(
            {
                "iss": ISSUER,
                "aud": CLIENT_ID,
                "sub": "user-123",
                "iat": utcnow(),
                "exp": utcnow() + timedelta(hours=1),
            },
            ec_key,
            algorithm="ES256",
        )

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=forged_token, issuer=ISSUER, client_id=CLIENT_ID)

        # Pin the wrapper path: the raw TypeError from the cryptography layer must have
        # been converted, not raised as some earlier InvalidTokenError subclass.
        self.assertIn("Token verification failed", str(context.exception))

    def test_non_object_oidc_config_rejected(self):
        self.oidc_config = ["not", "a", "dict"]

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("not a JSON object", str(context.exception))

    def test_unacceptable_algorithms_rejected(self):
        for algs in (["HS256", "none"], [["RS256"]], [123]):
            with self.subTest(algs=algs):
                self.oidc_config["id_token_signing_alg_values_supported"] = algs

                with self.assertRaises(InvalidTokenError) as context:
                    verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

                self.assertIn("algorithms", str(context.exception).lower())


if __name__ == "__main__":
    unittest.main()
