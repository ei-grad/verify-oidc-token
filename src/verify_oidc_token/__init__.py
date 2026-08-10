import logging
from typing import Union

import jwt
import requests
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError, PyJWTError

logger = logging.getLogger(__name__)

# Timeout in seconds for HTTP requests to the OIDC provider.
REQUEST_TIMEOUT = 10

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
# against whatever issuer/audience it claims itself. Any party able to host an OIDC
# discovery document can therefore mint a token that passes those two checks. Only use it
# for debugging or when the caller applies its own trust decision to the returned claims.
UNSAFE_FROM_TOKEN = _UnsafeFromToken()


def verify_token(
    token: str,
    issuer: Union[str, _UnsafeFromToken],
    client_id: Union[str, _UnsafeFromToken],
) -> dict:
    """
    Verifies an OpenID Connect (OIDC) ID Token.

    This function verifies the authenticity and integrity of an OIDC ID Token. It does not verify
    OAuth 2.0 access tokens. It performs the following steps:

    1. Reads the unverified JWT header and rejects tokens explicitly typed as OAuth 2.0 access
       tokens according to RFC 9068.

    2. Decodes the token without signature verification to extract the payload.

    3. If :data:`UNSAFE_FROM_TOKEN` is passed as ``issuer`` or ``client_id``, takes only the
       corresponding expected value from the unverified payload (see the sentinel's warning).
       Signature verification and the remaining token validation still run.

    4. Retrieves the OIDC configuration from the issuer's well-known configuration URL and
       validates that the ``issuer`` it announces matches the expected issuer.

    5. Initializes a PyJWKClient with the JWKS URI from the OIDC configuration and retrieves the
       signing key for the token.

    6. Verifies the token's signature and decodes the token, accepting only asymmetric signing
       algorithms announced by the provider and requiring the ``exp``, ``iat``, ``iss`` and
       ``aud`` claims to be present.

    This verifier is intentionally limited to OIDC ID Tokens. JWTs explicitly typed as OAuth 2.0
    access tokens are rejected. With an explicit ``client_id``, a multi-audience ID Token is
    accepted as long as ``client_id`` is among the audiences, while OIDC Core 3.1.3.7 also requires
    rejecting tokens with untrusted additional audiences and validating the ``azp`` claim.

    :param token: Encoded OIDC ID Token to verify.
    :param issuer: Expected OIDC issuer, or :data:`UNSAFE_FROM_TOKEN`.
    :param client_id: Expected OIDC client ID (the ID Token audience), or
                      :data:`UNSAFE_FROM_TOKEN`.
    :return: Decoded ID Token claims as a dictionary.
    :raises TypeError: If issuer or client_id is neither a string nor UNSAFE_FROM_TOKEN.
    :raises jwt.InvalidTokenError: If the token is invalid or fails verification.
    """

    if not isinstance(issuer, str) and issuer is not UNSAFE_FROM_TOKEN:
        raise TypeError("issuer must be a str or the UNSAFE_FROM_TOKEN sentinel")
    if not isinstance(client_id, str) and client_id is not UNSAFE_FROM_TOKEN:
        raise TypeError("client_id must be a str or the UNSAFE_FROM_TOKEN sentinel")

    unverified_header = jwt.get_unverified_header(token)
    token_type = unverified_header.get("typ")
    if isinstance(token_type, str) and token_type.lower() in _OAUTH_ACCESS_TOKEN_TYPES:
        raise InvalidTokenError(
            "OAuth 2.0 access tokens are not supported; expected an OpenID Connect ID Token"
        )

    unverified_payload = jwt.decode(token, options={"verify_signature": False})

    if isinstance(issuer, _UnsafeFromToken):
        try:
            issuer = unverified_payload["iss"]
        except KeyError:
            raise InvalidTokenError("Unable to retrieve issuer from token: no 'iss' claim")
        if not isinstance(issuer, str):
            raise InvalidTokenError("The 'iss' claim is not a string")

    if isinstance(client_id, _UnsafeFromToken):
        try:
            audience_claim = unverified_payload["aud"]
        except KeyError:
            raise InvalidTokenError("Unable to retrieve client ID from token: no 'aud' claim")
        if isinstance(audience_claim, list):
            # The aud claim MAY contain multiple audiences; deriving the expected audience
            # from such a token is ambiguous, so it must be passed explicitly then.
            if len(audience_claim) != 1:
                raise InvalidTokenError("Token has multiple audiences, pass client_id explicitly")
            client_id = audience_claim[0]
        else:
            client_id = audience_claim
        if not isinstance(client_id, str):
            raise InvalidTokenError("The 'aud' claim is not a string")

    # Retrieve OIDC configuration to obtain JWKS URI and supported algorithms
    oidc_config_url = f"{issuer}/.well-known/openid-configuration"
    try:
        resp = requests.get(oidc_config_url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        logger.debug(
            "OIDC configuration retrieved from '%s': %s",
            oidc_config_url,
            resp.text,
        )
        oidc_config = resp.json()
    except (requests.RequestException, ValueError) as e:
        raise InvalidTokenError(
            f"Unable to retrieve OIDC configuration from '{oidc_config_url}': {e}"
        )
    if not isinstance(oidc_config, dict):
        raise InvalidTokenError(f"OIDC configuration from '{oidc_config_url}' is not a JSON object")

    # OIDC Discovery 4.3 requires the issuer announced in the configuration to match the
    # issuer the configuration was retrieved for.
    config_issuer = oidc_config.get("issuer")
    if config_issuer != issuer:
        raise InvalidTokenError(
            f"OIDC configuration issuer mismatch: expected '{issuer}', got '{config_issuer}'"
        )

    jwks_uri = oidc_config.get("jwks_uri")
    if not jwks_uri or not isinstance(jwks_uri, str):
        raise InvalidTokenError("Missing or invalid 'jwks_uri' in OIDC configuration.")

    # Initialize PyJWKClient with the JWKS URI
    try:
        jwks_client = PyJWKClient(jwks_uri, timeout=REQUEST_TIMEOUT)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    except PyJWTError as e:
        raise InvalidTokenError(f"Unable to retrieve signing key: {e}")

    # RS256 is mandatory to implement for OIDC providers, so it is a safe default when
    # the configuration does not announce supported algorithms.
    supported_algs = oidc_config.get("id_token_signing_alg_values_supported", ["RS256"])
    if not isinstance(supported_algs, list):
        raise InvalidTokenError(
            "Invalid 'id_token_signing_alg_values_supported' in OIDC configuration:"
            f" expected a list, got {type(supported_algs).__name__}"
        )
    algorithms = [
        alg for alg in supported_algs if isinstance(alg, str) and alg in ALLOWED_SIGNING_ALGORITHMS
    ]
    if not algorithms:
        raise InvalidTokenError(
            "The OIDC configuration does not announce any acceptable signing algorithms"
            f" (got: {supported_algs!r})"
        )

    try:
        return jwt.decode(
            token,
            key=signing_key.key,
            algorithms=algorithms,
            audience=client_id,
            issuer=issuer,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except InvalidTokenError:
        raise
    # PyJWT leaks raw TypeError/ValueError from the cryptography layer when the alg
    # declared in the token header does not match the resolved signing key type.
    except (PyJWTError, TypeError, ValueError) as e:
        raise InvalidTokenError(f"Token verification failed: {e}")
