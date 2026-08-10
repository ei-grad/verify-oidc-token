# verify-oidc-token

Python tool for verifying OpenID Connect (OIDC) ID Tokens. OAuth 2.0 access tokens are not
supported; JWT access tokens explicitly identified by their `typ` header are rejected.

## Installation

Install via PyPI:

```bash
pip install verify-oidc-token
```

Or run the CLI without installing it:

```bash
echo "<ID_TOKEN>" | uvx verify-oidc-token \
  --issuer https://example-issuer.com \
  --client-id <CLIENT_ID>
```

Or, install from the source repository:

```bash
git clone https://github.com/ei-grad/verify-oidc-token
cd verify-oidc-token

# Optionally, create a virtual environment:
python3 -m venv venv
source venv/bin/activate  # Linux/MacOS
# venv\Scripts\activate  # Windows

pip install .
```

## CLI Usage

Verify an OIDC ID Token directly from the command line. Example:

```bash
echo "<ID_TOKEN>" | verify-oidc-token --issuer https://example-issuer.com --client-id <CLIENT_ID>
```

Or, specify a file with the token:

```bash
verify-oidc-token --token-file /path/to/token.txt --issuer https://example-issuer.com --client-id <CLIENT_ID>
```

### CLI Options:

- `--token-file` : The file containing the OIDC ID Token (can be omitted if passed via stdin).
- `--issuer` : The expected OIDC issuer. Required unless
  `--unsafe` is given; an empty value counts as missing.
- `--client-id` : The expected OIDC client ID, which is matched against the ID Token `aud` claim.
  Required unless `--unsafe` is given; an empty value counts as missing.
- `--trusted-audience AUDIENCE`: Explicitly trust an additional `aud` value. May be repeated.
  Multi-audience tokens must also have an `azp` claim equal to `--client-id`. Additional audiences
  are rejected by default.
- `--unsafe` : Take a missing expected issuer or client audience from the unverified ID Token
  payload, making those two checks self-referential. Signature verification is never disabled,
  and all other token validation still runs. When the issuer is taken from the token, that
  untrusted value controls which HTTPS hosts receive discovery and JWKS requests. Debugging only;
  HTTPS does not prevent access to an attacker-selected or internal HTTPS host.
- `--leeway SECONDS`: Allow a finite, non-negative number of seconds of clock skew when validating
  the `exp`, `nbf`, and `iat` claims. The default is `0`; signature, issuer, and audience validation
  are unaffected.
- `--with-header`: Include the decoded JWT header alongside the verified claims.
- `--verbose`: Enable verbose logging for debugging purposes.

Example:

```bash
verify-oidc-token --token-file token.txt --issuer https://accounts.google.com --client-id my-client-id
```

### Example Output:

For a valid token:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  ...
}
```

For an invalid token:

```json
{
  "error": "Invalid issuer"
}
```

### Output Format:

- Valid tokens return decoded claims as a JSON object.
- With `--with-header`, valid tokens return the decoded header and claims in a JSON object:

  ```json
  {
    "header": {
      "alg": "RS256",
      "kid": "key-id"
    },
    "claims": {
      "sub": "1234567890"
    }
  }
  ```

- If validation fails, an error message is returned as JSON:

  ```json
  {
    "error": "Description of the validation error"
  }
  ```

### Exit Codes:

- `0` — the token is valid; decoded claims were printed.
- `1` — token validation failed (a JSON `error` object is printed).
- `2` — invocation error: bad command-line usage (e.g. missing `--issuer` / `--client-id`
  without `--unsafe`) or an unreadable `--token-file`; the token was not verified.

## Library Usage

For a one-shot verification, use `verify_token`:

```python
from verify_oidc_token import verify_token
import jwt

token = "eyJhbGciOiJSUzI1NiIsInR5..."
issuer = "https://accounts.google.com"
client_id = "my-client-id"

try:
    claims = verify_token(token, issuer, client_id, leeway=30)
    print("Token is valid. Claims:", claims)
except jwt.InvalidTokenError as e:
    print({"error": str(e)})
```

Long-running applications should retain an `OIDCVerifier` instance. It caches the validated
discovery metadata and PyJWT JWKS client for five minutes by default, avoiding discovery and JWKS
network requests on every verification while still allowing key rotation:

```python
from verify_oidc_token import OIDCVerifier

verifier = OIDCVerifier(
    "https://accounts.google.com",
    "my-client-id",
    leeway=30,
)

claims = verifier.verify(token)
```

Verifier trust settings and cache TTL are read-only after construction; create separate verifier
instances for different issuer/client trust configurations. The package does not use a
module-global cross-issuer cache. Discovery and JWKS requests require HTTPS, refuse redirects, and
cap each response body at 1 MiB.

### Library API:

- `verify_token(token: str, issuer, client_id, *, leeway: float = 0.0,
  trusted_audiences=()) -> dict`
   Verifies an OIDC ID Token, ensuring it matches the expected issuer and OIDC client audience,
   and returns the claims if valid. Validation requires the `iss`, `sub`, `aud`, `exp`, and `iat`
   claims. Additional audiences are rejected unless explicitly trusted; a multi-audience token
   must also have `azp` equal to `client_id`. OAuth 2.0 access tokens are not supported.

   - **Parameters**:
     - `token` (str): The encoded OIDC ID Token to verify.
     - `issuer` (str or `UNSAFE_FROM_TOKEN`): Expected OIDC issuer.
     - `client_id` (str or `UNSAFE_FROM_TOKEN`): Expected OIDC client ID, matched against the ID
       Token `aud` claim.
     - `leeway` (float): Finite, non-negative number of seconds representable as a Python `float`,
       allowed when validating `exp`, `nbf`, and `iat`. Defaults to `0.0`; signature, issuer, and
       audience validation are unaffected.
     - `trusted_audiences` (iterable of str): Explicitly trusted additional `aud` values. Defaults
       to none.
   - **Returns**: Dictionary with the decoded claims.
   - **Raises**: `jwt.InvalidTokenError` if validation fails, `TypeError` if an argument has an
     invalid type, and `ValueError` if `leeway` is negative, not finite, or not representable as a
     Python `float`.

   Both `issuer` and `client_id` are required. Passing the `UNSAFE_FROM_TOKEN` sentinel
   (importable from `verify_oidc_token`) opts into deriving only that expected value from the
   unverified ID Token payload. Signature verification is never disabled and the other token
   validation still runs, but the corresponding issuer or audience check becomes self-referential.
   A token-derived issuer also controls the destination of HTTPS discovery and JWKS requests. Use
   this only for debugging, or when the caller applies its own trust and network-destination
   decisions to the returned claims.

- `OIDCVerifier(issuer: str, client_id: str, *, leeway: float = 0.0,
  trusted_audiences=(), cache_ttl: float = 300.0)`
  Creates a reusable verifier for one explicit issuer/client configuration. `verify(token)` returns
  verified claims using discovery metadata and JWKS cached for the configured positive TTL.
  `UNSAFE_FROM_TOKEN` is intentionally not accepted by this stateful API.

## Development

The project is managed with [uv](https://docs.astral.sh/uv/). Run the tests:

```bash
uv run -m pytest
```

Linters and type checking (installed as the `dev` dependency group):

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src
```

Use `tox` to run the tests against all supported Python versions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

Andrew Grigorev (<andrew@ei-grad.ru>)

Reach out with any questions or contribute to the project via the [GitHub repository](https://github.com/ei-grad/verify-oidc-token).
