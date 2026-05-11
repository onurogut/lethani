# Playbook: ffuf Fuzzing Recipes

## Purpose
Comprehensive ffuf fuzzing recipes for directory discovery, parameter fuzzing,
subdomain brute-force, authentication bypass, and API endpoint enumeration.
Covers filtering, rate limiting, recursive scanning, and output parsing.
Input: target URL, wordlist selection criteria.

---

## Step 1 — Directory and File Discovery

```bash
TARGET="https://TARGET"

# Basic directory brute-force
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,204,301,302,307,401,403,405 \
  -o dir_results.json -of json

# File discovery with extensions
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .php,.asp,.aspx,.jsp,.html,.js,.json,.xml,.txt,.bak,.old,.env,.config \
  -mc 200,204,301,302,307,401,403 \
  -o file_results.json -of json

# Recursive scanning (depth 2)
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt \
  -recursion -recursion-depth 2 \
  -mc 200,204,301,302,307 \
  -t 30

# Backup and config file hunting
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e .bak,.old,.swp,.save,.orig,.conf,.config,.ini,.env,.sql,.zip,.tar.gz,.log \
  -mc 200 \
  -o backup_results.json -of json
```

---

## Step 2 — Smart Filtering

```bash
# Auto-calibrate (filter out common response)
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -ac \
  -mc all

# Filter by response size
ffuf -u "$TARGET/FUZZ" \
  -w wordlist.txt \
  -fs 0,1234    # filter out 0 bytes and 1234 bytes

# Filter by word count
ffuf -u "$TARGET/FUZZ" \
  -w wordlist.txt \
  -fw 42        # filter responses with 42 words

# Filter by line count
ffuf -u "$TARGET/FUZZ" \
  -w wordlist.txt \
  -fl 10        # filter responses with 10 lines

# Filter by regex in response body
ffuf -u "$TARGET/FUZZ" \
  -w wordlist.txt \
  -fr "not found|error|404"

# Match by regex
ffuf -u "$TARGET/FUZZ" \
  -w wordlist.txt \
  -mr "admin|dashboard|login|secret"
```

---

## Step 3 — Parameter Fuzzing

```bash
# GET parameter name discovery
ffuf -u "$TARGET/page?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 \
  -fs 4242    # filter default response size

# GET parameter value fuzzing
ffuf -u "$TARGET/page?id=FUZZ" \
  -w /usr/share/seclists/Fuzzing/special-chars.txt \
  -mc all \
  -ac

# POST parameter discovery
ffuf -u "$TARGET/api/endpoint" \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc all \
  -ac

# JSON parameter fuzzing
ffuf -u "$TARGET/api/endpoint" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"FUZZ":"test"}' \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc all \
  -ac

# Header value fuzzing
ffuf -u "$TARGET/" \
  -H "X-Custom-Header: FUZZ" \
  -w wordlist.txt \
  -mc all \
  -ac
```

---

## Step 4 — Authentication Testing

```bash
COOKIE="session=AUTH_COOKIE"

# Authenticated directory scan
ffuf -u "$TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -b "$COOKIE" \
  -mc 200,204,301,302,307 \
  -o auth_dirs.json -of json

# Login brute-force (single user)
ffuf -u "$TARGET/login" \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=FUZZ" \
  -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  -fc 401,403 \
  -mc 200,302

# Username enumeration (different response for valid/invalid)
ffuf -u "$TARGET/login" \
  -X POST \
  -d "username=FUZZ&password=wrongpassword" \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -mc all \
  -ac

# Multi-wordlist (username:password)
ffuf -u "$TARGET/login" \
  -X POST \
  -d "username=USER&password=PASS" \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:USER \
  -w /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt:PASS \
  -mode clusterbomb \
  -fc 401
```

---

## Step 5 — API Endpoint Discovery

```bash
# REST API path fuzzing
ffuf -u "$TARGET/api/v1/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,204,301,302,401,403,405 \
  -o api_results.json -of json

# API versioning check
ffuf -u "$TARGET/api/FUZZ/users" \
  -w <(seq 1 10 | sed 's/^/v/') \
  -mc 200,301,302,401

# HTTP method fuzzing
ffuf -u "$TARGET/api/endpoint" \
  -X FUZZ \
  -w <(echo -e "GET\nPOST\nPUT\nDELETE\nPATCH\nOPTIONS\nHEAD\nTRACE") \
  -mc all \
  -ac

# GraphQL endpoint discovery
ffuf -u "$TARGET/FUZZ" \
  -w <(echo -e "graphql\ngraphiql\naltair\nplayground\nconsole\ngql\nquery\napi/graphql\nv1/graphql") \
  -mc 200,400,405
```

---

## Step 6 — Rate Limiting and Evasion

```bash
# Rate limiting
ffuf -u "$TARGET/FUZZ" \
  -w wordlist.txt \
  -rate 50           # 50 requests/second max

# Thread control
ffuf -u "$TARGET/FUZZ" \
  -w wordlist.txt \
  -t 10              # 10 concurrent threads (default: 40)

# Delay between requests
ffuf -u "$TARGET/FUZZ" \
  -w wordlist.txt \
  -p "0.5-1.5"       # random delay between 0.5-1.5s

# Custom User-Agent
ffuf -u "$TARGET/FUZZ" \
  -w wordlist.txt \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Through proxy (Burp)
ffuf -u "$TARGET/FUZZ" \
  -w wordlist.txt \
  -x http://127.0.0.1:8080 \
  -mc 200
```

---

## Step 7 — Output Parsing

```bash
# JSON output parsing
ffuf -u "$TARGET/FUZZ" -w wordlist.txt -o results.json -of json

# Extract URLs from results
python3 -c "
import json
with open('results.json') as f:
    data = json.load(f)
for r in data.get('results', []):
    print(f\"{r['status']} {r['length']}b {r['url']}\")
" | sort -t' ' -k1,1n

# CSV output
ffuf -u "$TARGET/FUZZ" -w wordlist.txt -o results.csv -of csv

# Pipe results to other tools
ffuf -u "$TARGET/FUZZ" -w wordlist.txt -of json -o - | \
  python3 -c "import sys,json; [print(r['url']) for r in json.load(sys.stdin).get('results',[])]" | \
  httpx -status-code -title

# Combine with nuclei
ffuf -u "$TARGET/FUZZ" -w wordlist.txt -of json -o results.json
python3 -c "import json; [print(r['url']) for r in json.load(open('results.json')).get('results',[])]" | \
  nuclei -t cves/ -t exposures/
```

---

## Step 8 — Advanced Patterns

```bash
# Two-position fuzzing (directory + file)
ffuf -u "$TARGET/FUZZDIR/FUZZFILE" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt:FUZZDIR \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt:FUZZFILE \
  -mode clusterbomb \
  -mc 200 \
  -t 20

# Wordlist from stdin
cat custom_paths.txt | ffuf -u "$TARGET/FUZZ" -w -

# Resume interrupted scan
ffuf -u "$TARGET/FUZZ" -w wordlist.txt -resume -o results.json

# Silent mode (for scripting)
ffuf -u "$TARGET/FUZZ" -w wordlist.txt -s | tee found_paths.txt
```

---

## Output

```
TARGET        : https://example.com
WORDLIST      : raft-medium-directories.txt (30000 entries)
RATE          : 100 req/s, 40 threads
FILTER        : auto-calibrate (filtered 4821 byte responses)
FOUND         :
  /admin       → 302 (0 bytes) — redirects to /admin/login
  /api         → 200 (48 bytes) — {"status":"ok"}
  /backup      → 403 (294 bytes) — forbidden but exists
  /config      → 401 (0 bytes) — requires auth
  /debug       → 200 (15234 bytes) — debug panel exposed!
SEVERITY      : VARIES
NEXT STEPS    : Test /debug for info disclosure, /admin for auth bypass,
                /backup for accessible files
```

---

## Tools Reference

```bash
# Install ffuf
go install github.com/ffuf/ffuf/v2@latest

# SecLists wordlists
git clone https://github.com/danielmiessler/SecLists.git

# Useful wordlist locations in SecLists:
# Discovery/Web-Content/raft-*.txt — general directories/files
# Discovery/Web-Content/common.txt — common paths
# Discovery/Web-Content/api/ — API-specific
# Discovery/DNS/ — subdomain/vhost
# Fuzzing/ — special characters, payloads
# Passwords/ — credential lists
```
