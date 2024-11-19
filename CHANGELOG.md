# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2024-11-19
### Added
- **Development Tools**:
  - Introduced `.flake8` configuration to enforce a maximum line length of 100 characters.
  - Added `requirements-dev.txt` with `mypy`, `types-requests`, `black`, `isort`, and `flake8` for
    static type checking, enhanced type annotations, code formatting, and import sorting.
- **Documentation**:
  - Added a "Notice" section in `README.md` to inform users about the current implementation's
    compliance with OIDC RFCs, advising them to review and adjust as necessary.

### Changed
- **OIDC Token Verification**:
  - Updated `verify_token` function to make `issuer` and `client_id` optional parameters, providing
    greater flexibility.
  - Enhanced error handling with more descriptive exception messages when retrieving `issuer` and
    `client_id` from tokens.
  - Improved docstrings to offer a detailed explanation of the verification process and its steps.
  - Simplified the token verification logic by removing redundant exception handling for specific
    JWT errors.
- **CLI Adjustments**:
  - Modified `cli.py` to make `--issuer` and `--client-id` arguments optional, aligning with changes
    in the `verify_token` function.
- **Continuous Integration**:
  - Simplified the test step in GitHub Actions workflow (`.github/workflows/release.yml`) by running
    `pytest` directly without changing directories, streamlining the CI process.
- **Testing Enhancements**:
  - Updated assertions in `integration_test.py` and `test_verify_oidc_token.py` to be more flexible
    and less dependent on exact error message strings, improving test robustness.
- **Project Structure**:
  - Refactored the project layout by moving `verify_oidc_token/__init__.py` to
    `src/verify_oidc_token/__init__.py` to adhere to best practices for Python project structures.

## [0.1.0] - 2024-10-25
### Added
- Initial release of `verify-oidc-token`.
