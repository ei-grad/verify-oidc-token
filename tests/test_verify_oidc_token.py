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
from jwt.utils import base64url_encode

from verify_oidc_token import (
    DEFAULT_CACHE_TTL,
    MAX_RESPONSE_BYTES,
    REQUEST_TIMEOUT,
    UNSAFE_FROM_TOKEN,
    OIDCVerifier,
    verify_token,
)

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


def make_token(headers=None, signing_key=private_key, **overrides):
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
    return jwt.encode(payload, signing_key, algorithm="RS256", headers=headers)


def make_json_response(document, *, status_code=200, headers=None):
    response = MagicMock()
    response.status_code = status_code
    response.headers = {} if headers is None else headers

    def iter_content(*, chunk_size):
        del chunk_size
        current_document = document() if callable(document) else document
        body = (
            current_document
            if isinstance(current_document, bytes)
            else json.dumps(current_document).encode()
        )
        return iter([body])

    response.iter_content.side_effect = iter_content
    return response


def make_jwks():
    numbers = public_key.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "key-1",
                "use": "sig",
                "alg": "RS256",
                "n": base64url_encode(
                    numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
                ).decode(),
                "e": base64url_encode(
                    numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
                ).decode(),
            }
        ]
    }


class TestVerifyToken(unittest.TestCase):
    def setUp(self):
        # Patch discovery requests and signing-key lookup for tests that exercise
        # validation independently of real network and JWKS parsing.
        self.patcher_requests_get = patch("verify_oidc_token.requests.get")
        self.patcher_get_signing_key = patch(
            "verify_oidc_token._BoundedPyJWKClient.get_signing_key_from_jwt"
        )

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
        self.mock_requests_get.return_value = make_json_response(lambda: self.oidc_config)

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
            allow_redirects=False,
            stream=True,
        )
        self.mock_get_signing_key.assert_called_once_with(valid_token)

    def test_oauth_access_token_types_rejected(self):
        for token_type in (
            "at+jwt",
            "at+JWT",
            "application/at+jwt",
            "Application/AT+JWT",
        ):
            with self.subTest(token_type=token_type):
                with self.assertRaises(InvalidTokenError) as context:
                    verify_token(
                        token=make_token(headers={"typ": token_type}),
                        issuer=ISSUER,
                        client_id=CLIENT_ID,
                    )

                self.assertIn("OAuth 2.0 access tokens are not supported", str(context.exception))

        self.mock_requests_get.assert_not_called()
        self.mock_get_signing_key.assert_not_called()

    def test_issuer_and_client_id_from_token(self):
        claims = verify_token(
            token=make_token(),
            issuer=UNSAFE_FROM_TOKEN,
            client_id=UNSAFE_FROM_TOKEN,
        )
        self.assertEqual(claims["sub"], "user-123")

    def test_unsafe_mode_still_rejects_invalid_signature(self):
        wrong_signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = make_token(signing_key=wrong_signing_key)

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(
                token=token,
                issuer=UNSAFE_FROM_TOKEN,
                client_id=UNSAFE_FROM_TOKEN,
                leeway=30,
            )

        self.assertIn("Signature verification failed", str(context.exception))
        self.mock_requests_get.assert_called_once_with(
            "https://example.com/.well-known/openid-configuration",
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
        )
        self.mock_get_signing_key.assert_called_once_with(token)

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

    def test_expiration_leeway(self):
        now = int(time.time())
        recently_expired_token = make_token(iat=now - 3600, exp=now - 30)

        with self.assertRaises(InvalidTokenError):
            verify_token(
                token=recently_expired_token,
                issuer=ISSUER,
                client_id=CLIENT_ID,
            )

        with self.assertRaises(InvalidTokenError):
            verify_token(
                token=recently_expired_token,
                issuer=ISSUER,
                client_id=CLIENT_ID,
                leeway=10,
            )

        claims = verify_token(
            token=recently_expired_token,
            issuer=ISSUER,
            client_id=CLIENT_ID,
            leeway=60,
        )
        self.assertEqual(claims["sub"], "user-123")

    def test_negative_leeway_rejected_before_discovery(self):
        with self.assertRaisesRegex(ValueError, "leeway must be non-negative"):
            verify_token(
                token=make_token(),
                issuer=ISSUER,
                client_id=CLIENT_ID,
                leeway=-1,
            )

        self.mock_requests_get.assert_not_called()
        self.mock_get_signing_key.assert_not_called()

    def test_unrepresentable_leeway_rejected_before_discovery(self):
        with self.assertRaisesRegex(ValueError, "leeway must be representable"):
            verify_token(
                token=make_token(),
                issuer=ISSUER,
                client_id=CLIENT_ID,
                leeway=10**1000,
            )

        self.mock_requests_get.assert_not_called()
        self.mock_get_signing_key.assert_not_called()

    def test_invalid_audience_error(self):
        wrong_audience_token = make_token(aud="wrong-client-id")

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=wrong_audience_token, issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("audience", str(context.exception).lower())

    def test_missing_required_claims_rejected(self):
        for claim in ("exp", "iat", "sub"):
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
        response = make_json_response({}, status_code=404)
        response.raise_for_status.side_effect = requests.HTTPError("404 Client Error")
        self.mock_requests_get.return_value = response

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("Unable to retrieve OIDC configuration", str(context.exception))

    def test_discovery_invalid_json_wrapped(self):
        self.mock_requests_get.return_value = make_json_response(b"not JSON")

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("Unable to retrieve OIDC configuration", str(context.exception))

    def test_discovery_redirect_rejected(self):
        self.mock_requests_get.return_value = make_json_response({}, status_code=302)

        with self.assertRaisesRegex(InvalidTokenError, "redirects are refused"):
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.mock_requests_get.assert_called_once_with(
            "https://example.com/.well-known/openid-configuration",
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
        )

    def test_discovery_body_size_is_bounded(self):
        self.mock_requests_get.return_value = make_json_response(
            {}, headers={"Content-Length": str(MAX_RESPONSE_BYTES + 1)}
        )

        with self.assertRaisesRegex(InvalidTokenError, "response exceeds"):
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

    def test_discovery_stream_size_is_bounded_without_content_length(self):
        self.mock_requests_get.return_value = make_json_response(b"x" * (MAX_RESPONSE_BYTES + 1))

        with self.assertRaisesRegex(InvalidTokenError, "response exceeds"):
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

    def test_https_issuer_required_before_network(self):
        invalid_issuers = (
            "http://example.com",
            "https:///missing-host",
            "https://user@example.com",
            "https://example.com?tenant=one",
            "https://example.com?",
            "https://example.com#fragment",
            "https://example.com#",
            " https://example.com",
            "https://example.com\\@attacker.example",
        )
        for issuer in invalid_issuers:
            with self.subTest(issuer=issuer):
                with self.assertRaises(InvalidTokenError):
                    verify_token(token=make_token(), issuer=issuer, client_id=CLIENT_ID)

        self.mock_requests_get.assert_not_called()

    def test_unsafe_token_derived_issuer_still_requires_https(self):
        with self.assertRaisesRegex(InvalidTokenError, "HTTPS"):
            verify_token(
                token=make_token(iss="http://internal.example"),
                issuer=UNSAFE_FROM_TOKEN,
                client_id=CLIENT_ID,
            )

        self.mock_requests_get.assert_not_called()

    def test_trailing_issuer_slash_does_not_duplicate_discovery_slash(self):
        issuer = f"{ISSUER}/"
        self.oidc_config["issuer"] = issuer

        claims = verify_token(
            token=make_token(iss=issuer),
            issuer=issuer,
            client_id=CLIENT_ID,
        )

        self.assertEqual(claims["iss"], issuer)
        self.mock_requests_get.assert_called_once_with(
            "https://example.com/.well-known/openid-configuration",
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
        )

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

    def test_jwks_uri_requires_https_host_without_userinfo(self):
        for jwks_uri in (
            "http://example.com/jwks",
            "https:///jwks",
            "https://user@example.com/jwks",
            "https://example.com/jwks#fragment",
        ):
            with self.subTest(jwks_uri=jwks_uri):
                self.oidc_config["jwks_uri"] = jwks_uri
                with self.assertRaisesRegex(InvalidTokenError, "jwks_uri"):
                    verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)
                self.mock_requests_get.reset_mock()

    def test_jwks_uri_may_contain_query(self):
        self.oidc_config["jwks_uri"] = "https://example.com/jwks?version=1"

        claims = verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertEqual(claims["sub"], "user-123")

    def test_non_list_supported_algorithms_rejected(self):
        self.oidc_config["id_token_signing_alg_values_supported"] = "RS256"

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("expected a list", str(context.exception))

    def test_jwks_client_gets_cache_ttl(self):
        with patch("verify_oidc_token._BoundedPyJWKClient") as mock_client_cls:
            mock_client_cls.return_value.get_signing_key_from_jwt.return_value = (
                self.mock_signing_key
            )
            claims = verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        mock_client_cls.assert_called_once_with(
            "https://example.com/.well-known/jwks.json", lifespan=DEFAULT_CACHE_TTL
        )
        self.assertEqual(claims["sub"], "user-123")

    def test_jwks_client_initialization_failure_is_wrapped(self):
        with patch(
            "verify_oidc_token._BoundedPyJWKClient",
            side_effect=PyJWKClientError("invalid client configuration"),
        ):
            with self.assertRaisesRegex(InvalidTokenError, "initialize JWKS client"):
                verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

    def test_signing_key_retrieval_failure_wrapped(self):
        self.mock_get_signing_key.side_effect = PyJWKClientError("Unable to find a signing key")

        with self.assertRaises(InvalidTokenError) as context:
            verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertIn("Unable to retrieve signing key", str(context.exception))

    def test_jwks_redirect_rejected(self):
        self.patcher_get_signing_key.stop()
        self.mock_requests_get.side_effect = [
            make_json_response(lambda: self.oidc_config),
            make_json_response({}, status_code=302),
        ]

        with self.assertRaisesRegex(InvalidTokenError, "redirects are refused"):
            verify_token(
                token=make_token(headers={"kid": "key-1"}),
                issuer=ISSUER,
                client_id=CLIENT_ID,
            )

    def test_jwks_body_size_is_bounded(self):
        self.patcher_get_signing_key.stop()
        self.mock_requests_get.side_effect = [
            make_json_response(lambda: self.oidc_config),
            make_json_response(b"x" * (MAX_RESPONSE_BYTES + 1)),
        ]

        with self.assertRaisesRegex(InvalidTokenError, "response exceeds"):
            verify_token(
                token=make_token(headers={"kid": "key-1"}),
                issuer=ISSUER,
                client_id=CLIENT_ID,
            )

    def test_non_object_jwks_is_rejected(self):
        self.patcher_get_signing_key.stop()
        self.mock_requests_get.side_effect = [
            make_json_response(lambda: self.oidc_config),
            make_json_response(["not", "an", "object"]),
        ]

        with self.assertRaisesRegex(InvalidTokenError, "JSON object"):
            verify_token(
                token=make_token(headers={"kid": "key-1"}),
                issuer=ISSUER,
                client_id=CLIENT_ID,
            )

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

    def test_multi_audience_rejects_mismatched_azp(self):
        token = make_token(aud=["attacker-client", CLIENT_ID], azp="attacker-client")

        with self.assertRaisesRegex(InvalidTokenError, "azp"):
            verify_token(token=token, issuer=ISSUER, client_id=CLIENT_ID)

    def test_multi_audience_requires_azp(self):
        token = make_token(aud=[CLIENT_ID, "other-client"])

        with self.assertRaisesRegex(InvalidTokenError, "azp"):
            verify_token(token=token, issuer=ISSUER, client_id=CLIENT_ID)

    def test_multi_audience_rejects_untrusted_additional_audience(self):
        token = make_token(aud=[CLIENT_ID, "other-client"], azp=CLIENT_ID)

        with self.assertRaisesRegex(InvalidTokenError, "untrusted additional"):
            verify_token(token=token, issuer=ISSUER, client_id=CLIENT_ID)

    def test_trusted_additional_audience_is_accepted_with_matching_azp(self):
        token = make_token(aud=[CLIENT_ID, "other-client"], azp=CLIENT_ID)

        claims = verify_token(
            token=token,
            issuer=ISSUER,
            client_id=CLIENT_ID,
            trusted_audiences=["other-client"],
        )

        self.assertEqual(claims["aud"], [CLIENT_ID, "other-client"])

    def test_azp_is_validated_for_single_audience(self):
        for azp in ("other-client", 123, [CLIENT_ID]):
            with self.subTest(azp=azp):
                with self.assertRaisesRegex(InvalidTokenError, "azp"):
                    verify_token(
                        token=make_token(azp=azp),
                        issuer=ISSUER,
                        client_id=CLIENT_ID,
                    )

    def test_trusted_audiences_argument_is_validated_before_network(self):
        for trusted_audiences in ("other-client", [""], [123], None):
            with self.subTest(trusted_audiences=trusted_audiences):
                with self.assertRaises(TypeError):
                    verify_token(
                        token=make_token(),
                        issuer=ISSUER,
                        client_id=CLIENT_ID,
                        trusted_audiences=trusted_audiences,
                    )

        self.mock_requests_get.assert_not_called()

    def test_safe_path_does_not_decode_the_unverified_payload(self):
        original_decode = jwt.decode
        with patch("verify_oidc_token.jwt.decode", wraps=original_decode) as mock_decode:
            claims = verify_token(token=make_token(), issuer=ISSUER, client_id=CLIENT_ID)

        self.assertEqual(claims["sub"], "user-123")
        self.assertEqual(mock_decode.call_count, 1)
        self.assertNotEqual(mock_decode.call_args.kwargs["options"], {"verify_signature": False})

    def test_reusable_verifier_caches_discovery_and_jwks(self):
        self.patcher_get_signing_key.stop()
        self.mock_requests_get.side_effect = [
            make_json_response(lambda: self.oidc_config),
            make_json_response(make_jwks()),
        ]
        verifier = OIDCVerifier(ISSUER, CLIENT_ID)
        token = make_token(headers={"kid": "key-1"})

        first_claims = verifier.verify(token)
        second_claims = verifier.verify(token)

        self.assertEqual(first_claims["sub"], "user-123")
        self.assertEqual(second_claims["sub"], "user-123")
        self.assertEqual(self.mock_requests_get.call_count, 2)

    def test_reusable_verifier_refreshes_discovery_after_ttl(self):
        verifier = OIDCVerifier(ISSUER, CLIENT_ID, cache_ttl=10)
        with patch(
            "verify_oidc_token.time.monotonic",
            side_effect=[0, 5, 11],
        ):
            verifier.verify(make_token())
            verifier.verify(make_token())
            verifier.verify(make_token())

        self.assertEqual(self.mock_requests_get.call_count, 2)

    def test_reusable_verifier_requires_explicit_trust_and_positive_ttl(self):
        with self.assertRaises(TypeError):
            OIDCVerifier(UNSAFE_FROM_TOKEN, CLIENT_ID)
        for cache_ttl in (0, -1, float("inf")):
            with self.subTest(cache_ttl=cache_ttl):
                with self.assertRaises(ValueError):
                    OIDCVerifier(ISSUER, CLIENT_ID, cache_ttl=cache_ttl)

    def test_reusable_verifier_trust_configuration_is_immutable(self):
        verifier = OIDCVerifier(ISSUER, CLIENT_ID)
        replacements = {
            "issuer": "https://other.example",
            "client_id": "other-client",
            "leeway": 60,
            "trusted_audiences": frozenset({"other-audience"}),
            "cache_ttl": 60,
        }

        for attribute, replacement in replacements.items():
            with self.subTest(attribute=attribute):
                with self.assertRaises(AttributeError):
                    setattr(verifier, attribute, replacement)

    def test_reassigning_issuer_cannot_reuse_cached_keys_for_another_issuer(self):
        verifier = OIDCVerifier(ISSUER, CLIENT_ID)
        verifier.verify(make_token())

        with self.assertRaises(AttributeError):
            verifier.issuer = "https://other.example"
        with self.assertRaises(InvalidTokenError):
            verifier.verify(make_token(iss="https://other.example"))

        self.mock_requests_get.assert_called_once()

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
