from __future__ import annotations

import json
import logging
import math
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Union, cast
from urllib.parse import urlsplit

import jwt
import requests
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError, PyJWKClientError, PyJWTError

logger = logging.getLogger(__name__)

# Timeout in seconds for HTTP requests to the OIDC provider.
REQUEST_TIMEOUT = 10

# Discovery and JWKS documents are small JSON metadata documents. A hard response cap
# prevents a provider from consuming unbounded memory even when it streams the body.
MAX_RESPONSE_BYTES = 1024 * 1024
DEFAULT_CACHE_TTL = 300.0
_RESPONSE_CHUNK_BYTES = 64 * 1024
_MISSING = object()

# Only asymmetric signature algorithms are acceptable for OIDC ID tokens. Accepting
# symmetric algorithms (HS*) announced by the discovery document would enable
# algorithm-confusion attacks, where a token is HMAC-signed using the public key
# material as the shared secret.
ALLOWED_SIGNING_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES256K",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
    }
)

# RFC 9068 uses these media types to identify OAuth 2.0 JWT access tokens.
# RFC 7515 defines media type and subtype matching for ``typ`` as case-insensitive.
_OAUTH_ACCESS_TOKEN_TYPES = frozenset({"at+jwt", "application/at+jwt"})


class _UnsafeFromToken:
    def __repr__(self) -> str:
        return "UNSAFE_FROM_TOKEN"


# Sentinel opting into deriving the expected ``issuer`` / ``client_id`` from the
# unverified ID Token payload. Signature verification and the remaining validation still
# run, but the issuer and audience checks become self-referential: the token is checked
# against whatever issuer/audience it claims itself. Deriving the issuer also makes HTTPS
# discovery and JWKS requests to a host selected by the untrusted token. Only use it for
# debugging or when the caller applies its own trust decision to the returned claims.
UNSAFE_FROM_TOKEN = _UnsafeFromToken()


def _normalize_leeway(leeway: float) -> float:
    if isinstance(leeway, bool) or not isinstance(leeway, (int, float)):
        raise TypeError("leeway must be a number of seconds")
    try:
        normalized = float(leeway)
    except OverflowError as e:
        raise ValueError("leeway must be representable as a finite float") from e
    if not math.isfinite(normalized):
        raise ValueError("leeway must be finite")
    if normalized < 0:
        raise ValueError("leeway must be non-negative")
    return normalized


def _normalize_cache_ttl(cache_ttl: float) -> float:
    if isinstance(cache_ttl, bool) or not isinstance(cache_ttl, (int, float)):
        raise TypeError("cache_ttl must be a number of seconds")
    try:
        normalized = float(cache_ttl)
    except OverflowError as e:
        raise ValueError("cache_ttl must be representable as a finite float") from e
    if not math.isfinite(normalized):
        raise ValueError("cache_ttl must be finite")
    if normalized <= 0:
        raise ValueError("cache_ttl must be greater than zero")
    return normalized


def _normalize_trusted_audiences(trusted_audiences: Iterable[str]) -> frozenset[str]:
    if isinstance(trusted_audiences, (str, bytes)):
        raise TypeError("trusted_audiences must be an iterable of strings, not a string")
    try:
        audiences = tuple(trusted_audiences)
    except TypeError as e:
        raise TypeError("trusted_audiences must be an iterable of strings") from e
    if any(not isinstance(audience, str) or not audience for audience in audiences):
        raise TypeError("trusted_audiences must contain only non-empty strings")
    return frozenset(audiences)


def _validate_https_url(url: str, name: str, *, allow_query: bool) -> None:
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in url):
        raise InvalidTokenError(
            f"Invalid {name}: whitespace and control characters are not allowed"
        )
    if "#" in url:
        raise InvalidTokenError(f"Invalid {name}: fragments are not allowed")
    if not allow_query and "?" in url:
        raise InvalidTokenError(f"Invalid {name}: query parameters are not allowed")

    try:
        parsed = urlsplit(url)
        parsed.port
    except (TypeError, ValueError) as e:
        raise InvalidTokenError(f"Invalid {name}: {e}") from e

    if parsed.scheme.lower() != "https":
        raise InvalidTokenError(f"Invalid {name}: HTTPS is required")
    if not parsed.hostname or any(character.isspace() for character in parsed.hostname):
        raise InvalidTokenError(f"Invalid {name}: a valid host is required")
    if parsed.username is not None or parsed.password is not None:
        raise InvalidTokenError(f"Invalid {name}: user information is not allowed")
    if "\\" in parsed.netloc:
        raise InvalidTokenError(f"Invalid {name}: backslashes are not allowed in the authority")


def _fetch_json_document(url: str, name: str) -> Any:
    response = None
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True,
        )
        if 300 <= response.status_code < 400:
            raise InvalidTokenError(
                f"Unable to retrieve {name} from '{url}': redirects are refused"
            )
        response.raise_for_status()
        if response.status_code != 200:
            raise InvalidTokenError(
                f"Unable to retrieve {name} from '{url}': "
                f"unexpected HTTP status {response.status_code}"
            )

        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except (TypeError, ValueError):
                declared_length = None
            if declared_length is not None and declared_length < 0:
                raise InvalidTokenError(
                    f"Unable to retrieve {name} from '{url}': invalid Content-Length"
                )
            if declared_length is not None and declared_length > MAX_RESPONSE_BYTES:
                raise InvalidTokenError(
                    f"Unable to retrieve {name} from '{url}': response exceeds "
                    f"{MAX_RESPONSE_BYTES} bytes"
                )

        body = bytearray()
        for chunk in response.iter_content(chunk_size=_RESPONSE_CHUNK_BYTES):
            if not chunk:
                continue
            if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                raise InvalidTokenError(
                    f"Unable to retrieve {name} from '{url}': response exceeds "
                    f"{MAX_RESPONSE_BYTES} bytes"
                )
            body.extend(chunk)
    except InvalidTokenError:
        raise
    except requests.RequestException as e:
        raise InvalidTokenError(f"Unable to retrieve {name} from '{url}': {e}") from e
    finally:
        if response is not None:
            response.close()

    try:
        document = json.loads(body)
    except (UnicodeDecodeError, ValueError) as e:
        raise InvalidTokenError(f"Unable to retrieve {name} from '{url}': invalid JSON: {e}") from e

    logger.debug("Retrieved %s bytes of %s from '%s'", len(body), name, url)
    return document


class _BoundedPyJWKClient(PyJWKClient):
    def fetch_data(self) -> Any:
        try:
            jwk_set = _fetch_json_document(self.uri, "JWKS")
        except InvalidTokenError as e:
            raise PyJWKClientError(str(e)) from e

        if not isinstance(jwk_set, dict):
            raise PyJWKClientError("The JWKS endpoint did not return a JSON object")
        if self.jwk_set_cache is not None:
            # PyJWT consumes a raw mapping here despite its PyJWKSet type annotation.
            self.jwk_set_cache.put(cast(Any, jwk_set))
        return jwk_set


def _reject_explicit_access_token(token: str) -> None:
    unverified_header = jwt.get_unverified_header(token)
    token_type = unverified_header.get("typ")
    if isinstance(token_type, str) and token_type.lower() in _OAUTH_ACCESS_TOKEN_TYPES:
        raise InvalidTokenError(
            "OAuth 2.0 access tokens are not supported; expected an OpenID Connect ID Token"
        )


def _validate_authorized_party(
    claims: dict[str, Any],
    client_id: str,
    trusted_audiences: frozenset[str],
) -> None:
    audience_claim = claims["aud"]
    audiences = [audience_claim] if isinstance(audience_claim, str) else audience_claim

    azp = claims.get("azp", _MISSING)
    if azp is not _MISSING and not isinstance(azp, str):
        raise InvalidTokenError("The 'azp' claim must be a string")
    if azp is not _MISSING and azp != client_id:
        raise InvalidTokenError("The 'azp' claim does not match the expected client_id")
    if len(audiences) > 1 and azp is _MISSING:
        raise InvalidTokenError("Token has multiple audiences but the 'azp' claim is missing")

    untrusted_audiences = set(audiences) - {client_id} - trusted_audiences
    if untrusted_audiences:
        raise InvalidTokenError("Token has an untrusted additional audience")


@dataclass(frozen=True)
class _VerifierConfig:
    issuer: str
    client_id: str
    leeway: float
    trusted_audiences: frozenset[str]
    cache_ttl: float


class OIDCVerifier:
    """Reusable verifier for OIDC ID Tokens from one trusted issuer and client.

    The verifier lazily retrieves discovery metadata and JWKS, then reuses both for
    ``cache_ttl`` seconds. Instances should be retained by long-running applications.
    ``issuer`` and ``client_id`` must be explicit trusted strings; unsafe token-derived
    expectations are available only through the one-shot :func:`verify_token` helper. The
    trust configuration and cache TTL are read-only after construction.
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        *,
        leeway: float = 0.0,
        trusted_audiences: Iterable[str] = (),
        cache_ttl: float = DEFAULT_CACHE_TTL,
    ) -> None:
        if not isinstance(issuer, str):
            raise TypeError("issuer must be a str")
        if not isinstance(client_id, str):
            raise TypeError("client_id must be a str")
        _validate_https_url(issuer, "issuer", allow_query=False)

        self._config = _VerifierConfig(
            issuer=issuer,
            client_id=client_id,
            leeway=_normalize_leeway(leeway),
            trusted_audiences=_normalize_trusted_audiences(trusted_audiences),
            cache_ttl=_normalize_cache_ttl(cache_ttl),
        )
        self._configuration: dict[str, Any] | None = None
        self._configuration_expires_at = 0.0
        self._jwks_client: _BoundedPyJWKClient | None = None
        self._cache_lock = threading.Lock()

    @property
    def issuer(self) -> str:
        return self._config.issuer

    @property
    def client_id(self) -> str:
        return self._config.client_id

    @property
    def leeway(self) -> float:
        return self._config.leeway

    @property
    def trusted_audiences(self) -> frozenset[str]:
        return self._config.trusted_audiences

    @property
    def cache_ttl(self) -> float:
        return self._config.cache_ttl

    def verify(self, token: str) -> dict[str, Any]:
        """Verify one OIDC ID Token and return its claims."""

        _reject_explicit_access_token(token)
        configuration, signing_key = self._signing_material(token)

        supported_algs = configuration.get("id_token_signing_alg_values_supported", ["RS256"])
        if not isinstance(supported_algs, list):
            raise InvalidTokenError(
                "Invalid 'id_token_signing_alg_values_supported' in OIDC configuration:"
                f" expected a list, got {type(supported_algs).__name__}"
            )
        algorithms = [
            alg
            for alg in supported_algs
            if isinstance(alg, str) and alg in ALLOWED_SIGNING_ALGORITHMS
        ]
        if not algorithms:
            raise InvalidTokenError(
                "The OIDC configuration does not announce any acceptable signing algorithms"
                f" (got: {supported_algs!r})"
            )

        try:
            claims = jwt.decode(
                token,
                key=signing_key.key,
                algorithms=algorithms,
                audience=self.client_id,
                issuer=self.issuer,
                leeway=self.leeway,
                options={"require": ["exp", "iat", "iss", "sub", "aud"]},
            )
        except InvalidTokenError:
            raise
        # PyJWT leaks raw TypeError/ValueError from the cryptography layer when the alg
        # declared in the token header does not match the resolved signing key type.
        except (PyJWTError, TypeError, ValueError) as e:
            raise InvalidTokenError(f"Token verification failed: {e}") from e

        _validate_authorized_party(claims, self.client_id, self.trusted_audiences)
        return claims

    def _signing_material(self, token: str) -> tuple[dict[str, Any], Any]:
        with self._cache_lock:
            configuration, jwks_client = self._provider_state_locked()
            try:
                signing_key = jwks_client.get_signing_key_from_jwt(token)
            except PyJWTError as e:
                raise InvalidTokenError(f"Unable to retrieve signing key: {e}") from e
            return configuration, signing_key

    def _provider_state_locked(self) -> tuple[dict[str, Any], _BoundedPyJWKClient]:
        now = time.monotonic()
        if (
            self._configuration is not None
            and self._jwks_client is not None
            and now < self._configuration_expires_at
        ):
            return self._configuration, self._jwks_client

        configuration_url = f"{self.issuer.rstrip('/')}/.well-known/openid-configuration"
        configuration = _fetch_json_document(configuration_url, "OIDC configuration")
        if not isinstance(configuration, dict):
            raise InvalidTokenError(
                f"OIDC configuration from '{configuration_url}' is not a JSON object"
            )

        config_issuer = configuration.get("issuer")
        if config_issuer != self.issuer:
            raise InvalidTokenError(
                "OIDC configuration issuer mismatch: "
                f"expected '{self.issuer}', got '{config_issuer}'"
            )

        jwks_uri = configuration.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri:
            raise InvalidTokenError("Missing or invalid 'jwks_uri' in OIDC configuration.")
        _validate_https_url(jwks_uri, "jwks_uri", allow_query=True)

        if self._jwks_client is None or self._jwks_client.uri != jwks_uri:
            try:
                self._jwks_client = _BoundedPyJWKClient(
                    jwks_uri,
                    lifespan=self.cache_ttl,
                )
            except PyJWTError as e:
                raise InvalidTokenError(f"Unable to initialize JWKS client: {e}") from e
        self._configuration = configuration
        self._configuration_expires_at = now + self.cache_ttl
        return configuration, self._jwks_client


def verify_token(
    token: str,
    issuer: Union[str, _UnsafeFromToken],
    client_id: Union[str, _UnsafeFromToken],
    *,
    leeway: float = 0.0,
    trusted_audiences: Iterable[str] = (),
) -> dict[str, Any]:
    """Verify an OpenID Connect ID Token.

    This one-shot convenience function retrieves OIDC discovery metadata and JWKS for
    each call. Long-running applications should retain an :class:`OIDCVerifier` instance
    so discovery metadata and signing keys can be reused.

    OAuth 2.0 access tokens explicitly typed according to RFC 9068 are rejected. The
    signature, required claims, issuer, client audience and authorized-party claim are
    validated. Additional audiences are rejected by default. To accept a known additional
    audience, list it in ``trusted_audiences``; multi-audience tokens must also contain an
    ``azp`` claim equal to ``client_id``.

    Passing :data:`UNSAFE_FROM_TOKEN` derives only the corresponding issuer or client ID
    from the unverified payload. Signature verification and all other checks still run.
    A token-derived issuer controls the HTTPS discovery and JWKS hosts, so this mode is for
    debugging only.

    :param token: Encoded OIDC ID Token to verify.
    :param issuer: Expected HTTPS OIDC issuer, or :data:`UNSAFE_FROM_TOKEN`.
    :param client_id: Expected OIDC client ID, or :data:`UNSAFE_FROM_TOKEN`.
    :param leeway: Non-negative finite seconds allowed for temporal claim validation.
    :param trusted_audiences: Explicitly trusted additional ``aud`` values.
    :return: Decoded ID Token claims.
    :raises TypeError: If an argument has an invalid type.
    :raises ValueError: If ``leeway`` is invalid.
    :raises jwt.InvalidTokenError: If the token or provider metadata is invalid.
    """

    if not isinstance(issuer, str) and issuer is not UNSAFE_FROM_TOKEN:
        raise TypeError("issuer must be a str or the UNSAFE_FROM_TOKEN sentinel")
    if not isinstance(client_id, str) and client_id is not UNSAFE_FROM_TOKEN:
        raise TypeError("client_id must be a str or the UNSAFE_FROM_TOKEN sentinel")

    normalized_leeway = _normalize_leeway(leeway)
    normalized_trusted_audiences = _normalize_trusted_audiences(trusted_audiences)

    if issuer is UNSAFE_FROM_TOKEN or client_id is UNSAFE_FROM_TOKEN:
        _reject_explicit_access_token(token)
        unverified_payload = jwt.decode(token, options={"verify_signature": False})

        if issuer is UNSAFE_FROM_TOKEN:
            try:
                issuer = unverified_payload["iss"]
            except KeyError:
                raise InvalidTokenError("Unable to retrieve issuer from token: no 'iss' claim")
            if not isinstance(issuer, str):
                raise InvalidTokenError("The 'iss' claim is not a string")

        if client_id is UNSAFE_FROM_TOKEN:
            try:
                audience_claim = unverified_payload["aud"]
            except KeyError:
                raise InvalidTokenError("Unable to retrieve client ID from token: no 'aud' claim")
            if isinstance(audience_claim, list):
                if len(audience_claim) != 1:
                    raise InvalidTokenError(
                        "Token has multiple audiences, pass client_id explicitly"
                    )
                client_id = audience_claim[0]
            else:
                client_id = audience_claim
            if not isinstance(client_id, str):
                raise InvalidTokenError("The 'aud' claim is not a string")

    verifier = OIDCVerifier(
        cast(str, issuer),
        cast(str, client_id),
        leeway=normalized_leeway,
        trusted_audiences=normalized_trusted_audiences,
    )
    return verifier.verify(token)
