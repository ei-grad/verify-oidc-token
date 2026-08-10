# verify-oidc-token

Python tool for verifying OpenID Connect (OIDC) ID Tokens. OAuth 2.0 access tokens are not
supported; JWT access tokens explicitly identified by their `typ` header are rejected.

## Installation

Install via PyPI:

```bash
pip install verify-oidc-token
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
- `--unsafe` : Take a missing expected issuer or client audience from the unverified ID Token
  payload, making those two checks self-referential. Signature verification and the other token
  validation still run. Debugging only.
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

Use this tool as a library in Python code:

```python
from verify_oidc_token import verify_token
import jwt

token = "eyJhbGciOiJSUzI1NiIsInR5..."
issuer = "https://accounts.google.com"
client_id = "my-client-id"

try:
    claims = verify_token(token, issuer, client_id)
    print("Token is valid. Claims:", claims)
except jwt.InvalidTokenError as e:
    print({"error": str(e)})
```

### Library API:

- `verify_token(token: str, issuer, client_id) -> dict`
   Verifies an OIDC ID Token, ensuring it matches the expected issuer and OIDC client audience,
   and returns the claims if valid. Validation requires the `iss`, `sub`, `aud`, `exp`, and `iat`
   claims. OAuth 2.0 access tokens are not supported.

   - **Parameters**:
     - `token` (str): The encoded OIDC ID Token to verify.
     - `issuer` (str or `UNSAFE_FROM_TOKEN`): Expected OIDC issuer.
     - `client_id` (str or `UNSAFE_FROM_TOKEN`): Expected OIDC client ID, matched against the ID
       Token `aud` claim.
   - **Returns**: Dictionary with the decoded claims.
   - **Raises**: `jwt.InvalidTokenError` if validation fails, `TypeError` if `issuer` or
     `client_id` is neither a string nor `UNSAFE_FROM_TOKEN`.

   Both `issuer` and `client_id` are required. Passing the `UNSAFE_FROM_TOKEN` sentinel
   (importable from `verify_oidc_token`) opts into deriving only that expected value from the
   unverified ID Token payload. Signature verification and the other token validation still run,
   but the corresponding issuer or audience check becomes self-referential. Use this only for
   debugging, or when the caller applies its own trust decision to the returned claims.

## Development

The project is managed with [uv](https://docs.astral.sh/uv/). Run the tests:

```bash
uv run -m pytest
```

Linters and type checking (installed as the `dev` dependency group):

```bash
uv run flake8 src tests
uv run black --check src tests
uv run isort --check-only src tests
uv run mypy src
```

Use `tox` to run the tests against all supported Python versions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

Andrew Grigorev (<andrew@ei-grad.ru>)

Reach out with any questions or contribute to the project via the [GitHub repository](https://github.com/ei-grad/verify-oidc-token).
