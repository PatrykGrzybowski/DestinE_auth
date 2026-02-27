# DestinE Auth Development Guide

## Local live integration tests

Live tests are available in `tests/integration/test_live_auth_integration.py` and are opt-in.

### 1) Configure local credentials

Create a local `.env` file (do not commit it) using `.env.example` as template:

- `DESP_USERNAME` (required)
- `DESP_PASSWORD` (required)
- `DESP_OTP_CODE` (optional, for accounts requiring OTP)
- `DESP_BAD_PASSWORD` (optional, only if running negative tests)

### 2) Run live tests explicitly

```bash
RUN_LIVE_AUTH_TESTS=1 python -m unittest -v tests.integration.test_live_auth_integration
```

Optional negative tests:

```bash
RUN_LIVE_AUTH_TESTS=1 RUN_LIVE_NEGATIVE_TESTS=1 python -m unittest -v tests.integration.test_live_auth_integration
```

### 3) CI safety

These tests are skipped by default in CI. To force them in CI, set:

- `RUN_LIVE_AUTH_TESTS=1`
- `RUN_LIVE_AUTH_TESTS_IN_CI=1`

## Security notes for contributors

- Never print credentials, OTP codes, or raw JWTs.
- Keep `.env` local only.
