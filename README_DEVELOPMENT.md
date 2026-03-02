# DestinE Auth Development Guide


## Setup environment for development

1. Clone the repository and navigate to the `DestinE_auth` package:

```bash
git clone <repository_url>
cd DestinE_auth
```

2. Create a virtual environment and activate it:

```bash

uv venv .venv --python=3.12
source .venv/bin/activate

```

3. Install the package in editable mode along with development dependencies:

```bash

uv pip install -e .[dev]

```



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

## Internal demo script usage

`script_example.py` is an internal debug/testing helper.
It uses simple variables in the `__main__` block to choose which flow to run.

How to use:

1. Set required credentials in `.env`:

```env
DESP_USERNAME=your_username
DESP_PASSWORD=your_password
DESP_OTP_CODE=optional_otp
DEDL_CLIENT_ID=optional_service_account_client_id
DEDL_CLIENT_SECRET=optional_service_account_client_secret
```

2. Open `script_example.py` and set:
- `RUN_MODE` to one of `standard`, `staged`, `service-account`.
- `FULL_TOKEN_OUTPUT` to `True` or `False`.

3. Run the script:

```bash
python script_example.py
```

`DESP_USERNAME` and `DESP_PASSWORD` are mandatory and must be provided via `.env` (or exported environment variables); the script raises an error if they are missing.
For each retrieved DEDL token, the script prints expiry, roles, and DT access status.
`FULL_TOKEN_OUTPUT` is `False` by default for safer local usage. When explicitly set to `True`, it also prints full tokens and writes decoded token dumps to `tokens/`.

## CI and release flow

- `CI` workflow runs on every push and pull request.
- Unit tests run on Python `3.8`, `3.9`, `3.10`, `3.11`, and `3.12`.
- Build checks verify artifact metadata and fail if excluded dev/test files appear in distributions.
- Pushes to any non-`main`/non-`master` branch publish to TestPyPI.
- Version tags matching `v*` run production publish validation, but the final upload to PyPI is intentionally disabled in the workflow.

Required repository secrets:

- `TEST_PYPI_TOKEN` for TestPyPI publishing.
- `PYPI_TOKEN` is only needed if production PyPI upload is re-enabled.

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

- Never print credentials or OTP codes.
- Raw JWT output is allowed only for explicit local debugging opt-in (`FULL_TOKEN_OUTPUT=True`) and must not be enabled by default.
- Keep `.env` local only.
