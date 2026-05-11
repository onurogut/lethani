# Playbook: Parameter Discovery

## Purpose
Discover hidden/undocumented parameters on endpoints using active fuzzing
and passive analysis. Identify high-value params for further vulnerability testing.
Input: URL list, single endpoint, or arjun/x8 output.

---

## Step 1 — Passive Parameter Collection

Before active fuzzing, collect params that already exist in the wild:

```bash
# From wayback/gau output (fastest)
cat urls_all.txt \
  | grep "?" \
  | sed 's/.*?\(.*\)/\1/' \
  | tr '&' '\n' \
  | sed 's/=.*//' \
  | sort -u > passive_params.txt

# From JS files (run after js_endpoint_extractor)
grep -rhoP "[\?&]([a-zA-Z_][a-zA-Z0-9_-]{1,30})=" js_files/ \
  | sed 's/[?&]//' | sed 's/=//' | sort -u >> passive_params.txt

sort -u passive_params.txt -o passive_params.txt
echo "Passive params collected: $(wc -l < passive_params.txt)"
```

---

## Step 2 — Active Parameter Fuzzing

```bash
# arjun — best for GET/POST parameter discovery
arjun -u "https://TARGET/endpoint" \
  -m GET POST \
  --stable \
  -t 10 \
  -o arjun_results.json

# Bulk mode against URL list
arjun -i interesting_endpoints.txt \
  -m GET \
  -t 5 \
  --stable \
  -o arjun_bulk.json

# x8 — faster alternative, good for headers too
x8 -u "https://TARGET/endpoint" \
  -w ~/wordlists/params/burp-parameter-names.txt \
  -X GET \
  --output-format json \
  -o x8_results.json

# ParamSpider — spider-based collection
paramspider -d TARGET -s -o paramspider_output.txt
```

---

## Step 3 — Header Parameter Fuzzing

Some parameters are accepted as headers, not query strings:

```bash
# Common headers worth testing on every endpoint
HEADERS=(
  "X-Forwarded-For"
  "X-Real-IP"
  "X-Forwarded-Host"
  "X-Original-URL"
  "X-Rewrite-URL"
  "X-Custom-IP-Authorization"
  "X-Originating-IP"
  "X-Remote-IP"
  "X-Client-IP"
  "X-Host"
  "X-Forwarded-Proto"
  "X-Override-URL"
  "X-HTTP-Method-Override"
  "X-Method-Override"
  "Content-Type"
  "Accept"
  "Origin"
  "Referer"
)

# Test each header with a canary value and look for reflection/behavior change
for header in "${HEADERS[@]}"; do
  response=$(curl -sk -H "$header: CANARY_12345" "https://TARGET/endpoint")
  echo "$response" | grep -q "CANARY_12345" && echo "[REFLECTED] $header"
done
```

---

## Step 4 — JSON Body Parameter Discovery

For API endpoints that accept JSON bodies:

```bash
# x8 with JSON mode
x8 -u "https://TARGET/api/endpoint" \
  -X POST \
  -H "Content-Type: application/json" \
  --body '{}' \
  -w ~/wordlists/params/api-params.txt \
  --output-format json \
  -o x8_json.json

# Mass assignment test — send all known params at once
# Build payload from all discovered params
python3 -c "
params = open('passive_params.txt').read().splitlines()
body = {p: 'test_' + p for p in params[:50]}
import json; print(json.dumps(body))
" > mass_assign_payload.json

curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/json" \
  -d @mass_assign_payload.json
```

---

## Step 5 — Categorize Discovered Parameters

After collecting all params, sort by vulnerability potential:

```bash
# Combine all discovered params
cat passive_params.txt arjun_results.json x8_results.json 2>/dev/null \
  | grep -oP '"[a-zA-Z_][a-zA-Z0-9_-]+"' | tr -d '"' | sort -u > all_params_final.txt

# SSRF candidates
grep -iE "^(url|uri|src|href|link|endpoint|host|domain|proxy|fetch|load|import|resource|feed|webhook|callback|service|backend|server|api|remote|dest|goto|open|redir)" \
  all_params_final.txt > params_ssrf.txt

# Open redirect candidates
grep -iE "^(redirect|return|next|continue|forward|to|goto|dest|destination|ref|return_url|success_url|cancel_url|callback_url|landing|redir|location|out|target|navigate|go)" \
  all_params_final.txt > params_redirect.txt

# LFI/path traversal candidates
grep -iE "^(file|path|page|template|view|document|dir|folder|include|require|load|read|module|layout|root|source|conf|config|type|format|lang|locale|theme)" \
  all_params_final.txt > params_lfi.txt

# SQLi candidates
grep -iE "^(id|user|uid|userid|user_id|account|account_id|order|order_id|product|product_id|cat|category|ref|reference|search|query|q|name|type|sort|filter|offset|limit|from|to|start|end|date|year|month|day)" \
  all_params_final.txt > params_sqli.txt

# IDOR candidates
grep -iE "^(id|uid|user_id|account_id|profile_id|customer_id|order_id|invoice_id|doc_id|file_id|message_id|token|key|guid|uuid|hash|ref|number|no|code|ticket)" \
  all_params_final.txt > params_idor.txt

echo "Parameter categories:"
echo "  SSRF candidates:     $(wc -l < params_ssrf.txt)"
echo "  Redirect candidates: $(wc -l < params_redirect.txt)"
echo "  LFI candidates:      $(wc -l < params_lfi.txt)"
echo "  SQLi candidates:     $(wc -l < params_sqli.txt)"
echo "  IDOR candidates:     $(wc -l < params_idor.txt)"
```

---

## Step 6 — Verify Parameter Reflection

```bash
# Quick reflection test for XSS/template injection surface
CANARY="XSSTEST$(date +%s)"
while read param; do
  url="https://TARGET/endpoint?${param}=${CANARY}"
  response=$(curl -sk "$url")
  echo "$response" | grep -q "$CANARY" && echo "[REFLECTED] $param → $url"
done < all_params_final.txt
```

---

## Output

```
TARGET            : https://target.com/api/v2/users
PASSIVE PARAMS    : 234
ARJUN DISCOVERED  : 12 new params (id, admin, debug, export, format...)
X8 DISCOVERED     : 8 new params
TOTAL UNIQUE      : 254
─────────────────────────────────────────────────────
HIGH-VALUE FINDINGS:
  [SSRF]     ?url= → discovered, passes URL to backend
  [REDIRECT] ?next= → reflected in Location header
  [IDOR]     ?user_id= → different users return different data
  [DEBUG]    ?debug=true → verbose error returned
─────────────────────────────────────────────────────
NEXT STEPS:
  1. Test params_ssrf.txt → load 02_vuln_testing/ssrf_playbook.md
  2. Test params_redirect.txt → open redirect testing
  3. Test params_idor.txt → load 02_vuln_testing/idor_framework.md
  4. Test params_sqli.txt → load 02_vuln_testing/sqli_methodology.md
```

---

## Wordlist Reference

```
~/wordlists/params/burp-parameter-names.txt   (Burp Suite built-in list)
~/wordlists/params/api-params.txt             (SecLists API-specific)
~/wordlists/params/ashok-param.txt            (Ashok param wordlist)
SecLists: Discovery/Web-Content/burp-parameter-names.txt
```
