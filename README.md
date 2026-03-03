# DestinE Auth

DestinE Auth is a helper package that simplifies authentication for DestinE workflows:

1. Authenticate with DESP credentials.
2. Get a DESP access token. (Normally transparent for the user)
3. Exchange that token for a DEDL access token.

A `Destination Earth - Data Lake` access token is necessary to interact with `Destination Earth - Data Lake` APIs and services.

## Install

```bash
pip install destinelab
```

Note: Python compatibility: 3.8+

## Quick usage

Repository demo and contributor workflows (including the interactive demo script) are documented in `README_DEVELOPMENT.md`.

### Standard usage

```python
from destinelab import AuthHandler

handler = AuthHandler("DESP_USERNAME", "DESP_PASSWORD")
dedl_token = handler.get_token()

auth_headers = {"Authorization": f"Bearer {dedl_token}"} # Example of how to use the token in API requests

```

### Service account usage (client credentials)

```python

from destinelab import DEDLServiceAccountAuth

dedl_token = DEDLServiceAccountAuth(
	client_id="YOUR_CLIENT_ID",
	client_secret="YOUR_CLIENT_SECRET",
).get_token()

```

### Check roles and DT access

- `AuthHandler` also provides helper methods to check the roles associated with the token and whether DT access is allowed, which can be useful for debugging or conditional logic in your application.

```python

from destinelab import AuthHandler

handler = AuthHandler("DESP_USERNAME", "DESP_PASSWORD")
dedl_token = handler.get_token()
roles = handler.get_roles(dedl_token)
is_dt_access_allowed = handler.is_DTaccess_allowed(dedl_token)

```

### DESP and DEDL token exchange (i.e. breaking the process down into individual steps)

- This is not recommended or useful for typical users, but can be useful for debugging or if you need more control over the individual steps.

```python

from destinelab import DESPAuth, DEDLAuth

desp_token = DESPAuth("DESP_USERNAME", "DESP_PASSWORD").get_desp_token()
dedl_token = DEDLAuth(desp_token).get_token()

```

## Error behavior

- `DESPAuth.get_desp_token()` raises explicit auth errors (for example invalid credentials, OTP required, network failures, and DESP token exchange failures).
- `DEDLAuth.get_token()` raises explicit exceptions on exchange failure.
- `DEDLServiceAccountAuth.get_token()` raises explicit exceptions on service-account authentication failure.
- `AuthHandler.get_token()` first checks whether an already stored DEDL token is still valid (verified against DEDL Keycloak JWKS). If valid, it is returned immediately; otherwise it composes `DESPAuth -> DEDLAuth` using DESP user credentials.


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
