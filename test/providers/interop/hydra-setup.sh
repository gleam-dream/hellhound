#!/bin/sh
# Register the disposable Hydra client and start the headless consent app.
set -eu
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
CA="$ROOT/build/test-pki/ca.pem"
curl -s --cacert "$CA" -X DELETE https://localhost:14445/admin/clients/hellhound-rp >/dev/null || true
curl -sf --cacert "$CA" -X POST https://localhost:14445/admin/clients -H 'content-type: application/json' -d '{
  "client_id": "hellhound-rp",
  "client_secret": "hellhound-hydra-disposable-secret-0123456789",
  "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
  "response_types": ["code"],
  "scope": "openid offline_access email profile",
  "redirect_uris": ["https://localhost:1/callback"],
  "post_logout_redirect_uris": ["https://localhost:1/logged-out"],
  "token_endpoint_auth_method": "client_secret_basic"
}' >/dev/null
NODE_EXTRA_CA_CERTS="$CA" node "$ROOT/test/providers/fixture-control.mjs" up \
  "$ROOT/build/hydra-consent" "$ROOT/test/providers/interop/hydra-consent.mjs" 14446
