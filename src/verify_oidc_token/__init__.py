from typing import Optional
import logging

import jwt
import requests
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError


logger = logging.getLogger(__name__)


def verify_token(
    token: str,
    issuer: Optional[str] = None,
    client_id: Optional[str] = None,
) -> dict:
    """
    Verifies an OIDC token.

    This function verifies the authenticity and integrity of a given JWT using the OpenID Connect
    (OIDC) protocol. It performs the following steps:

    1. Decodes the token without signature verification to extract the payload.

    2. If the issuer is not provided, it retrieves the issuer from the token's payload.

    3. If the client ID (audience) is not provided, it retrieves the client ID from the token's
       payload.

    4. Retrieves the OIDC configuration from the issuer's well-known configuration URL.

    5. Extracts the JWKS URI and supported signing algorithms from the OIDC configuration.

    6. Initializes a PyJWKClient with the JWKS URI to fetch the JSON Web Key Set (JWKS).

    7. Retrieves the signing key from the JWKS using the token.

    8. Verifies the token's signature and decodes the token using the signing key and supported
       algorithms.

    Note: This implementation may not fully comply with the related RFC for verifying OIDC tokens.
    Additional checks and validations might be necessary for complete compliance.

    :param token: JWT token to verify.
    :param issuer: Expected issuer of the token.
    :param client_id: Expected client ID (audience).
    :return: Decoded claims of the token as a dictionary.
    :raises jwt.InvalidTokenError: If the token is invalid or fails verification.
    """

    unverified_payload = jwt.decode(token, options={"verify_signature": False})
    if issuer is None:
        try:
            issuer = unverified_payload["iss"]
        except Exception as e:
            raise InvalidTokenError(f"Unable to retrieve issuer from token: {e}")
    if client_id is None:
        try:
            # The Client MUST validate that the aud (audience) Claim contains its client_id value
            # registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud
            # (audience) Claim MAY contain an array with more than one element. The ID Token MUST be
            # rejected if the ID Token does not list the Client as a valid audience, or if it
            # contains additional audiences not trusted by the Client.
            audience_claim = unverified_payload["aud"]
            if isinstance(audience_claim, list):
                assert len(audience_claim) == 1
                client_id = audience_claim[0]
            else:
                client_id = audience_claim
        except Exception as e:
            raise InvalidTokenError(f"Unable to retrieve client ID from token: {e}")

    # Retrieve OIDC configuration to obtain JWKS URI and supported algorithms
    oidc_config_url = f"{issuer}/.well-known/openid-configuration"
    try:
        resp = requests.get(oidc_config_url)
        resp.raise_for_status()
        logger.debug(
            "OIDC configuration retrieved from '%s': %s",
            oidc_config_url,
            resp.text,
        )
        oidc_config = resp.json()
    except Exception as e:
        raise InvalidTokenError(
            f"Unable to retrieve OIDC configuration from '{oidc_config_url}': {e}"
        )

    jwks_uri = oidc_config.get("jwks_uri")
    if not jwks_uri:
        raise InvalidTokenError("Missing 'jwks_uri' in OIDC configuration.")

    # Initialize PyJWKClient with the JWKS URI
    try:
        jwks_client = PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    except Exception as e:
        raise InvalidTokenError(f"Unable to retrieve signing key: {e}")

    # Retrieve supported signing algorithms from the OIDC configuration, defaulting to RS256.
    # XXX: shouldn't it use a different default algorithm corresponding to the key type?
    supported_algs = oidc_config.get("id_token_signing_alg_values_supported", ["RS256"])
    if not supported_algs:
        raise InvalidTokenError(
            "The OIDC configuration contains an empty list of supported signing algorithms."
        )

    return jwt.decode(
        token,
        key=signing_key.key,
        algorithms=supported_algs,
        audience=client_id,
        issuer=issuer,
    )
