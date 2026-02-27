# DestinE Auth

DestinE Auth is a helper package that simplifies authentication for DestinE workflows:

1. Authenticate with DESP credentials.
2. Get a DESP access token.
3. Exchange that token for a DEDL access token.

## Install

```bash
pip install destinelab
```

Python compatibility: 3.8+

## Quick usage

### End-to-end flow (recommended)

```python
from destinelab import AuthHandler

handler = AuthHandler("DESP_USERNAME", "DESP_PASSWORD")
dedl_token = handler.get_token()
```

### Check roles and DT access

```python
from destinelab import AuthHandler

handler = AuthHandler("DESP_USERNAME", "DESP_PASSWORD")
dedl_token = handler.get_token()
roles = handler.get_roles(dedl_token)
is_allowed = handler.is_DTaccess_allowed(dedl_token)
```

### Staged flow (advanced)

```python
from destinelab import DESPAuth, DEDLAuth

desp_token = DESPAuth("DESP_USERNAME", "DESP_PASSWORD").get_desp_token()
dedl_token = DEDLAuth(desp_token, strict=True).get_token()

## Error behavior

- `DESPAuth.get_desp_token()` raises explicit auth errors (for example invalid credentials, OTP required, network failures, and DESP token exchange failures).
- `DEDLAuth.get_token()` returns `None` by default when exchange fails and logs a warning.
- `DEDLAuth(..., strict=True).get_token()` raises explicit exceptions instead of returning `None`.
- `AuthHandler.get_token()` uses the default `DEDLAuth` mode and may therefore return `None` when DEDL exchange fails.
```

## Example script

For an interactive usage walkthrough, run:

```bash
python script_example.py
```

## Development and testing docs

Development and testing workflows are documented in `README_DEVELOPMENT.md`.

## License

This project is licensed under MIT. See `LICENSE`.

MIT License

Copyright (c) 2025 Patryk Grzybowski

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
