import jwt
import requests
from jwt import PyJWKClient
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidTokenError,
)


def verify_token(token: str, issuer: str, client_id: str) -> dict:
    """
    Verifies an OIDC token.

    :param token: JWT token to verify.
    :param issuer: Expected issuer of the token.
    :param client_id: Expected client ID (audience).
    :return: Decoded claims of the token as a dictionary.
    :raises jwt.InvalidTokenError: If the token is invalid or fails verification.
    """
    # Retrieve OIDC configuration to obtain JWKS URI and supported algorithms
    oidc_config_url = f"{issuer}/.well-known/openid-configuration"
    try:
        resp = requests.get(oidc_config_url)
        resp.raise_for_status()
        oidc_config = resp.json()
    except Exception as e:
        raise InvalidTokenError(
            f"Failed to retrieve OIDC configuration from '{oidc_config_url}': {e}"
        )

    jwks_uri = oidc_config.get("jwks_uri")
    if not jwks_uri:
        raise InvalidTokenError("OIDC configuration does not contain 'jwks_uri'.")

    # Get the supported algorithms from openid-configuration
    supported_algs = oidc_config.get("id_token_signing_alg_values_supported", ["RS256"])
    if not supported_algs:
        raise InvalidTokenError("No supported signing algorithms found in OIDC configuration.")

    # Initialize PyJWKClient with the JWKS URI
    try:
        jwks_client = PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    except Exception as e:
        raise InvalidTokenError(f"Failed to retrieve signing key: {e}")

    # Verify the token
    try:
        decoded = jwt.decode(
            token,
            key=signing_key.key,
            algorithms=supported_algs,
            audience=client_id,
            issuer=issuer,
            options={
                "strict_aud": True,
            },
        )
    except ExpiredSignatureError:
        raise InvalidTokenError("Token has expired.")
    except ImmatureSignatureError:
        raise InvalidTokenError("Token is not yet valid (nbf).")
    except InvalidIssuedAtError:
        raise InvalidTokenError("Invalid issued at time (iat).")
    except InvalidIssuerError:
        raise InvalidTokenError(f"Invalid token issuer. Expected '{issuer}'.")
    except InvalidAudienceError:
        raise InvalidTokenError(f"Invalid token audience. Expected '{client_id}'.")
    except DecodeError as e:
        raise InvalidTokenError(f"Token decode error: {e}")
    except Exception as e:
        raise InvalidTokenError(f"Token verification error: {e}")

    return decoded
