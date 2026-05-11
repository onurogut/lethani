# Playbook: Business Logic Testing

## Purpose
Identify flaws in application workflow, pricing, access control, and
business rules that automated scanners cannot detect. Requires understanding
the application's intended functionality.
Input: authenticated session, understanding of application workflow.

---

## Step 1 — Map the Business Logic

Before testing, understand the complete workflow:

```
DOCUMENT:
  1. User roles and their permissions
  2. Complete transaction/purchase flow (every step)
  3. Pricing model (discounts, tiers, taxes)
  4. Limits and quotas (per user, per day, per account)
  5. State transitions (order: draft→pending→paid→shipped)
  6. Approval workflows (request→review→approve)
  7. Data relationships (user→orders→items→payments)
```

---

## Step 2 — Price Manipulation

```bash
COOKIE="session=AUTHENTICATED_COOKIE"

# Negative price/quantity
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/cart/add" \
  -H "Content-Type: application/json" \
  -d '{"product_id": 1, "quantity": -1, "price": 100}'

# Zero price
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/cart/add" \
  -d '{"product_id": 1, "quantity": 1, "price": 0}'

# Fractional quantity
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/cart/add" \
  -d '{"product_id": 1, "quantity": 0.001}'

# Price parameter tampering (if price is in request)
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/checkout" \
  -d '{"product_id": 1, "price": 0.01, "quantity": 1}'

# Discount stacking
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/apply-discount" \
  -d '{"code": "DISCOUNT10"}'
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/apply-discount" \
  -d '{"code": "DISCOUNT20"}'
# Can multiple discounts stack beyond 100%?

# Currency confusion
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/checkout" \
  -d '{"amount": 100, "currency": "IDR"}'  # Pay in cheaper currency
```

---

## Step 3 — Workflow Bypass

```bash
# Skip steps in multi-step process
# Normal flow: Step1 → Step2 → Step3 → Complete
# Test: Jump directly to Step3 or Complete

# Direct access to final step
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/order/complete" \
  -d '{"order_id": 123}'

# Access step 3 without completing step 2
curl -sk -b "$COOKIE" "https://TARGET/checkout/step3"

# Replay a completed action
# Complete an order, then replay the completion request
# Does it create a duplicate?

# Skip payment verification
# Normal: add-to-cart → checkout → payment → confirm
# Test: add-to-cart → confirm (skip payment)
```

---

## Step 4 — Parameter Tampering

```bash
# Modify hidden/readonly fields
# User ID manipulation
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/profile" \
  -d '{"user_id": 999, "name": "Attacker"}'

# Role/privilege escalation
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/register" \
  -d '{"username": "test", "password": "test", "role": "admin"}'

# Account type manipulation
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/upgrade" \
  -d '{"plan": "enterprise", "price": 0}'

# Status manipulation
curl -sk -b "$COOKIE" -X PUT "https://TARGET/api/order/123" \
  -d '{"status": "refunded"}'
```

---

## Step 5 — Limit/Quota Bypass

```bash
# Daily limit bypass
# If daily transfer limit is 10,000 TL:

# Test: Transfer 10,000 at 23:59 and 10,000 at 00:01
# Test: Multiple small transfers that exceed total limit
# Test: Negative transfer to reset counter
# Test: Concurrent requests (see race_condition.md)

# Free tier limit bypass
# Free plan: 100 API calls/day
# Test: Reset by creating new account
# Test: API key rotation resets counter?
# Test: Different endpoints share same counter?

# Invitation limit bypass
# "Invite 5 friends" → can you invite more?
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/invite" \
  -d '{"email": "friend6@test.com"}'

# Trial period manipulation
# Extend trial by:
# - Changing dates in request
# - Re-registering with same email
# - Cookie/local storage manipulation
```

---

## Step 6 — Access Control Logic Flaws

```bash
# Horizontal privilege escalation
# Access another user's resources by changing ID
curl -sk -b "$COOKIE" "https://TARGET/api/orders/OTHER_USER_ORDER_ID"

# Vertical privilege escalation
# Access admin functions as regular user
curl -sk -b "$COOKIE" "https://TARGET/admin/users"
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/admin/create-user" \
  -d '{"username": "newadmin", "role": "admin"}'

# Function-level access control
# Can a regular user access:
curl -sk -b "$COOKIE" "https://TARGET/api/reports/financial"
curl -sk -b "$COOKIE" "https://TARGET/api/export/all-users"
curl -sk -b "$COOKIE" -X DELETE "https://TARGET/api/users/456"

# Object-level access control
# Can user A modify user B's data?
curl -sk -b "$COOKIE_A" -X PUT "https://TARGET/api/users/B_ID" \
  -d '{"email": "attacker@evil.com"}'
```

---

## Step 7 — Data Validation Logic

```bash
# Email verification bypass
# Register with email A, change to email B before verification
# Does email B become verified?

# Phone verification bypass
# Similar — change phone after OTP sent

# Identity verification bypass
# Upload ID for user A, use verification for user B

# Input boundary testing
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/transfer" \
  -d '{"amount": 99999999999}'   # Integer overflow
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/transfer" \
  -d '{"amount": 0.0000001}'     # Precision abuse
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/transfer" \
  -d '{"amount": "100"}'         # String vs number type
curl -sk -b "$COOKIE" -X POST "https://TARGET/api/transfer" \
  -d '{"amount": "1e5"}'         # Scientific notation = 100000
```

---

## Step 8 — Timing and State Attacks

```bash
# Action after account deletion
# Delete account → can you still use active session?
# Delete account → do scheduled tasks still execute?

# Expired subscription access
# Subscription expired → can you still access premium content?
# Downgrade plan → does cached data remain accessible?

# Concurrent state changes
# User changes password while admin resets it
# User deletes account while payment is processing
```

---

## Output

```
ENDPOINT      : POST /api/apply-discount
FINDING       : Multiple discount codes can be stacked
STEPS         :
  1. Add item to cart (100 TL)
  2. Apply DISCOUNT10 → price becomes 90 TL
  3. Apply DISCOUNT20 → price becomes 72 TL (stacked!)
  4. Apply SUMMER30 → price becomes 50.4 TL (triple stack!)
EXPECTED      : Only one discount code per order
ACTUAL        : Unlimited discount stacking allowed
SEVERITY      : HIGH
IMPACT        : Financial loss — items purchased at arbitrarily low prices
EVIDENCE      : [request/response chain showing price decrease]
```
