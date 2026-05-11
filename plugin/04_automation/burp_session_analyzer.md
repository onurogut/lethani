# Playbook: Burp Session Analyzer

## Purpose
Extract high-value findings from exported Burp Suite session files.
Identify interesting requests, authentication patterns, hidden endpoints,
and parameter surfaces without manual review of thousands of requests.
Input: Burp XML export file or Burp project file path.

---

## Step 1 — Export from Burp Suite

In Burp Suite:
```
Proxy → HTTP History → Select All (Ctrl+A) → Right-click → Save items
Export as XML format → burp_session.xml
```

Or for specific scope only:
```
Target → Site Map → Right-click target → Save selected items → XML
```

---

## Step 2 — Parse the XML Export

```python
# Parse Burp XML export
import xml.etree.ElementTree as ET
import base64
import re

tree = ET.parse('burp_session.xml')
root = tree.getroot()

items = []
for item in root.findall('item'):
    url = item.findtext('url', '')
    method = item.findtext('method', '')
    status = item.findtext('status', '')
    
    # Decode base64 request/response
    req_b64 = item.find('request')
    res_b64 = item.find('response')
    
    request = base64.b64decode(req_b64.text).decode('utf-8', errors='replace') \
              if req_b64 is not None and req_b64.text else ''
    response = base64.b64decode(res_b64.text).decode('utf-8', errors='replace') \
               if res_b64 is not None and res_b64.text else ''
    
    items.append({
        'url': url,
        'method': method,
        'status': status,
        'request': request,
        'response': response
    })

print(f"Total requests: {len(items)}")
```

Save as `/tmp/parse_burp.py` and run:
```bash
python3 /tmp/parse_burp.py
```

---

## Step 3 — Triage Requests by Category

```python
# Categorize all requests
categories = {
    'api': [], 'auth': [], 'admin': [], 'upload': [],
    'interesting_params': [], 'errors': [], 'redirects': []
}

api_pattern = re.compile(r'/(api|v\d+|graphql|gql|rest|rpc|swagger)', re.I)
auth_pattern = re.compile(r'/(login|signin|auth|oauth|token|session|logout|sso|saml)', re.I)
admin_pattern = re.compile(r'/(admin|manage|dashboard|console|backoffice|staff)', re.I)
upload_pattern = re.compile(r'/(upload|file|import|attachment|media)', re.I)
param_pattern = re.compile(r'[?&](url|redirect|src|file|path|id|user_id|token|key)=', re.I)

for item in items:
    url = item['url']
    status = item.get('status', '')
    
    if api_pattern.search(url):
        categories['api'].append(item)
    if auth_pattern.search(url):
        categories['auth'].append(item)
    if admin_pattern.search(url):
        categories['admin'].append(item)
    if upload_pattern.search(url):
        categories['upload'].append(item)
    if param_pattern.search(url):
        categories['interesting_params'].append(item)
    if status and status.startswith('5'):
        categories['errors'].append(item)
    if status in ('301', '302'):
        categories['redirects'].append(item)

for cat, reqs in categories.items():
    print(f"{cat}: {len(reqs)} requests")
```

---

## Step 4 — Extract Authorization Tokens & Headers

```bash
# From Burp XML export — find all auth headers
python3 -c "
import xml.etree.ElementTree as ET, base64, re

tree = ET.parse('burp_session.xml')
tokens = set()

for item in tree.getroot().findall('item'):
    req = item.find('request')
    if req is not None and req.text:
        try:
            decoded = base64.b64decode(req.text).decode('utf-8', errors='replace')
            # Find authorization headers
            for match in re.finditer(r'(Authorization|X-Auth-Token|X-API-Key|Bearer|Token): (.+)', decoded, re.I):
                tokens.add(match.group(0).strip())
        except:
            pass

for t in tokens:
    print(t)
" > extracted_tokens.txt

echo "Unique tokens/auth headers: $(wc -l < extracted_tokens.txt)"
```

---

## Step 5 — Find Secrets & Sensitive Data in Responses

```bash
python3 -c "
import xml.etree.ElementTree as ET, base64, re

tree = ET.parse('burp_session.xml')

secret_patterns = [
    r'(api[_-]?key|apikey|secret[_-]?key|access[_-]?key)\s*[=:]\s*['\''\"]\s*([a-zA-Z0-9_\-]{20,})',
    r'(password|passwd)\s*[=:]\s*['\''\"]\s*([^\s'\''\";]{6,})',
    r'aws[_-]?(access[_-]?key|secret)[_-]?id\s*[=:]\s*['\''\"]\s*([A-Z0-9]{20})',
    r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',  # JWT
    r'AKIA[0-9A-Z]{16}',  # AWS key
    r'ghp_[a-zA-Z0-9]{36}',  # GitHub PAT
    r'sk-[a-zA-Z0-9]{48}',  # OpenAI key
]

findings = []
for item in tree.getroot().findall('item'):
    url = item.findtext('url', '')
    for field in ['request', 'response']:
        el = item.find(field)
        if el is not None and el.text:
            try:
                decoded = base64.b64decode(el.text).decode('utf-8', errors='replace')
                for pattern in secret_patterns:
                    for match in re.finditer(pattern, decoded, re.I):
                        findings.append(f'[{field.upper()}] {url}: {match.group(0)[:100]}')
            except:
                pass

for f in set(findings):
    print(f)
" > response_secrets.txt

echo "Potential secrets found: $(wc -l < response_secrets.txt)"
```

---

## Step 6 — Extract All Unique Endpoints & Parameters

```bash
python3 -c "
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs

tree = ET.parse('burp_session.xml')
paths = set()
params = set()

for item in tree.getroot().findall('item'):
    url = item.findtext('url', '')
    if url:
        parsed = urlparse(url)
        paths.add(parsed.path)
        for param in parse_qs(parsed.query).keys():
            params.add(param)

print('=== UNIQUE PATHS ===')
for p in sorted(paths):
    print(p)

print('\n=== UNIQUE PARAMS ===')
for p in sorted(params):
    print(p)
" > endpoints_params.txt
```

---

## Step 7 — Flag Interesting Requests for Manual Review

```bash
python3 -c "
import xml.etree.ElementTree as ET, base64, re

tree = ET.parse('burp_session.xml')
flags = []

for item in tree.getroot().findall('item'):
    url = item.findtext('url', '')
    method = item.findtext('method', '')
    status = item.findtext('status', '')
    
    req_el = item.find('request')
    res_el = item.find('response')
    
    request = base64.b64decode(req_el.text).decode('utf-8', errors='replace') if req_el and req_el.text else ''
    response = base64.b64decode(res_el.text).decode('utf-8', errors='replace') if res_el and res_el.text else ''
    
    reasons = []
    
    # Auth issues
    if status == '200' and re.search(r'/(admin|manage|dashboard)', url, re.I):
        reasons.append('Admin path returned 200')
    if method in ('PUT','DELETE','PATCH') and status == '200':
        reasons.append(f'{method} method succeeded')
    if re.search(r'SQL syntax|ORA-\d+|pg_query|mysql_fetch', response, re.I):
        reasons.append('SQL error in response')
    if re.search(r'stack trace|exception in thread|traceback', response, re.I):
        reasons.append('Stack trace in response')
    if re.search(r'AWS_SECRET|AKIA[A-Z0-9]{16}', response):
        reasons.append('AWS credential in response')
    if status == '200' and 'content-length: 0' in response.lower() and 'api' in url.lower():
        reasons.append('Empty API response — try other methods')
    
    if reasons:
        flags.append({'url': url, 'method': method, 'status': status, 'reasons': reasons})

for f in flags:
    print(f\"[{f['status']}] {f['method']} {f['url']}\")
    for r in f['reasons']:
        print(f'  → {r}')
" > flagged_requests.txt

echo "Flagged for manual review: $(grep -c '^\[' flagged_requests.txt)"
```

---

## Output

```
SOURCE        : burp_session.xml (2,847 requests)
─────────────────────────────────────────────────────
CATEGORIES:
  API endpoints  : 412
  Auth requests  : 67
  Admin paths    : 23
  Upload paths   : 8
  Interesting params: 134
  Server errors  : 19
  Redirects      : 88
─────────────────────────────────────────────────────
FINDINGS:
  [CRITICAL] AWS credential found in /api/config response
  [HIGH]     SQL error on /search?q= parameter
  [HIGH]     Stack trace on /api/users?id=abc
  [MEDIUM]   PUT method succeeds on /api/profile/settings
  [MEDIUM]   Admin path /admin/users returns 200
─────────────────────────────────────────────────────
FILES CREATED:
  extracted_tokens.txt    → Auth tokens for replay testing
  response_secrets.txt    → Potential credentials/keys
  endpoints_params.txt    → All unique paths + params
  flagged_requests.txt    → Manual review queue
NEXT STEPS:
  1. Review flagged_requests.txt — prioritize SQL error and AWS credential
  2. Test PUT method on /api/profile/settings
  3. Feed endpoints_params.txt into parameter_discovery.md
```
