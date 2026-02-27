# DestinE Auth Development Guide

## Packaging policy

Published artifacts must contain runtime code only.

- Included: `destinelab/` package code, `README.md`, `LICENSE`.
- Excluded: `tests/`, `.github/`, `README_DEVELOPMENT.md`, `script_example.py`, and local env files.

Validate locally before release:

```bash
python -m build
python -m twine check dist/*
tar -tf dist/*.tar.gz
python -m zipfile -l dist/*.whl
```

## CI and release flow

- `CI` workflow runs on every push and pull request.
- Unit tests run on Python `3.8`, `3.9`, `3.10`, `3.11`, and `3.12`.
- Build checks verify artifact metadata and fail if excluded dev/test files appear in distributions.
- Pushes to any non-`main`/non-`master` branch publish to TestPyPI.
- Version tags matching `v*` publish to PyPI.

Required repository secrets:

- `TEST_PYPI_TOKEN` for TestPyPI publishing.
- `PYPI_TOKEN` for production PyPI publishing.

## Local live integration tests

Live tests are available in `tests/integration/test_live_auth_integration.py` and are opt-in.

### 1) Configure local credentials

Create a local `.env` file (do not commit it) using `.env.example` as template:

- `DESP_USERNAME` (required)
- `DESP_PASSWORD` (required)
- `DESP_OTP_CODE` (optional, for accounts requiring OTP)
- `DESP_BAD_PASSWORD` (optional, only if running negative tests)
- `DEDL_CLIENT_ID` (optional, for service-account client credentials tests)
- `DEDL_CLIENT_SECRET` (optional, for service-account client credentials tests)

### 2) Run live tests explicitly

```bash
RUN_LIVE_AUTH_TESTS=1 python -m unittest -v tests.integration.test_live_auth_integration
```

Optional negative tests:

```bash
RUN_LIVE_AUTH_TESTS=1 RUN_LIVE_NEGATIVE_TESTS=1 python -m unittest -v tests.integration.test_live_auth_integration
```

Optional service-account live test (client credentials):

```bash
RUN_LIVE_AUTH_TESTS=1 DEDL_CLIENT_ID=... DEDL_CLIENT_SECRET=... python -m unittest -v tests.integration.test_live_auth_integration
```

### 3) CI safety

These tests are skipped by default in CI. To force them in CI, set:

- `RUN_LIVE_AUTH_TESTS=1`
- `RUN_LIVE_AUTH_TESTS_IN_CI=1`

## Security notes for contributors

- Never print credentials, OTP codes, or raw JWTs.
- Keep `.env` local only.
