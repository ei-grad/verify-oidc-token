# verify-oidc-token

Python tool for verifying OpenID Connect (OIDC) tokens.

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

Verify an OIDC token directly from the command line. Example:

```bash
echo "<OIDC_TOKEN>" | verify-oidc-token --issuer https://example-issuer.com --client-id <CLIENT_ID>
```

Or, specify a file with the token:

```bash
verify-oidc-token --token-file /path/to/token.txt --issuer https://example-issuer.com --client-id <CLIENT_ID>
```

### CLI Options:

- `--token-file` : The file containing the OIDC token (can be omitted if passed via stdin).
- `--issuer` : The expected issuer of the token (authorization server).
- `--client-id` : The expected client ID (audience) of the token.
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
  "error": "Invalid issuer. Expected 'https://example-issuer.com', got 'https://wrong-issuer.com'"
}
```

### Output Format:

- Valid tokens return decoded claims as a JSON object.
- If validation fails, an error message is returned as JSON:

  ```json
  {
    "error": "Description of the validation error"
  }
  ```

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

- `verify_token(token: str, issuer: str, client_id: str) -> dict`
   Verifies the token, ensuring it matches the specified issuer and client ID, and returns the claims if valid.

   - **Parameters**:
     - `token` (str): The JWT to verify.
     - `issuer` (str): Expected issuer of the token.
     - `client_id` (str): Expected client ID (audience).
   - **Returns**: Dictionary with the decoded claims.
   - **Raises**: `jwt.InvalidTokenError` if validation fails.

## Testing

Run unit tests to ensure functionality:

```bash
python -m unittest discover tests
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

Andrew Grigorev (<andrew@ei-grad.ru>)

Reach out with any questions or contribute to the project via the [GitHub repository](https://github.com/ei-grad/verify-oidc-token).

