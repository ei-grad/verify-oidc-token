# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-07-07
### Security
- **Breaking**: `verify_token` now requires explicit `issuer` and `client_id` arguments. The
  previous behavior of deriving them from the unverified token payload made the corresponding
  checks self-referential (the token was verified against whatever issuer/audience it claimed
  itself); it is still available by explicitly passing the new `UNSAFE_FROM_TOKEN` sentinel.
  Passing `None` raises `TypeError`.
- The `issuer` announced in the OIDC discovery document is now validated to match the expected
  issuer, as required by OIDC Discovery 4.3.
- Only asymmetric signing algorithms (`RS*`/`ES*`/`PS*`/`EdDSA`) announced by the provider are
  accepted, preventing algorithm-confusion attacks via `HS*`/`none`.
- The `exp`, `iat`, `iss` and `aud` claims are now required to be present in the token.
- Replaced an `assert` on the audience list (a no-op under `python -O`) with a proper
  `InvalidTokenError`; deriving the client ID from a multi-audience token is rejected.
- HTTP requests to the OIDC provider (discovery document and JWKS) now use a 10-second timeout.

### Changed
- **Breaking**: the CLI now requires `--issuer` and `--client-id` (empty values count as
  missing); the previous take-them-from-the-token behavior is available via an explicit
  `--unsafe` flag.
- PyJWT requirement bumped to `>=2.6.0` (needed for the `PyJWKClient` timeout support).
- Dropped support for Python 3.8 (EOL); added Python 3.14 to the test matrix.
- CI: the workflow now runs only on pushes to `main`, `v*` tags, and pull requests; Test PyPI
  publishing is performed only for tags; GitHub releases are published immediately instead of
  being created as drafts; distributions are built with `uv build` and validated with
  `twine check --strict`.
- Development environment is now managed with `uv`: dev/test dependencies moved from
  `requirements-dev.txt`/`requirements-test.txt` to the PEP 735 `dev` dependency group in
  `pyproject.toml`, `uv.lock` committed.
- Build backend switched from `hatchling` to `uv_build`: distribution metadata is now
  Metadata-Version 2.4 with a valid PEP 639 license expression (hatchling 1.25 emitted
  `License-Expression` under Metadata-Version 2.3, which `twine check --strict` rejects);
  `license-files` migrated to the final PEP 639 array form. The sdist no longer bundles repo
  internals (CI config, dotfiles, `uv.lock`) but still includes the tests, changelog and tox
  config.
- CI actions are pinned to full commit SHAs; Dependabot configured to keep the pins and the
  `uv.lock` up to date.

### Fixed
- The GitHub release is now created for the pushed `v<version>` tag instead of creating a stray
  `<version>` tag at the default branch HEAD.
- Integration tests bind the mock OIDC server to a free port instead of hardcoded 5001 and no
  longer sleep at import time.

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
