# Playbook: Report Writer

## Purpose
Transform a raw finding into a structured, clear, high-quality bug report
that maximizes triage speed, minimizes back-and-forth, and gets paid faster.
Input: finding details (endpoint, steps, impact, evidence).

---

## Report Template

Fill every section. Leave none blank — incomplete reports get triaged last.

---

### Title

Format: `[Vulnerability Type] in [Feature/Endpoint] allows [Impact]`

Good examples:
- `Horizontal IDOR on /api/v2/orders/{id} allows any authenticated user to read another user's order history and PII`
- `Unauthenticated SSRF via ?url= parameter on /api/preview reaches AWS metadata service`
- `Stored XSS in user profile "bio" field executes in admin dashboard`
- `SQL Injection in /products?id= allows full database read via UNION-based attack`

Bad examples:
- `IDOR found` ← no context
- `SQL Injection vulnerability` ← no impact
- `Security issue on target.com` ← useless

---

### Vulnerability Type
Select the most specific applicable type for the platform's taxonomy.

---

### Severity
State your severity assessment (from severity_scorer.md) and briefly justify.

```
Severity: HIGH
Rationale: Any authenticated user (free account sufficient) can access
full order data of any other user, including name, address, and payment method.
No user interaction or special privilege required beyond registration.
```

---

### Summary

2-5 sentences. Non-technical enough for a product manager to understand.

```
The order history API endpoint at /api/v2/orders/{id} does not validate
that the requesting user owns the order being fetched. By substituting any
numeric order ID, an authenticated attacker can retrieve complete order details
belonging to other customers, including their full name, shipping address,
email, phone number, and partial payment information.

This affects all orders in the system and requires only a free account to exploit.
```

---

### Affected Asset

```
URL    : https://api.target.com/api/v2/orders/{id}
Type   : REST API endpoint
Scope  : In-scope (listed as *.target.com)
```

---

### Steps to Reproduce

Be precise. Assume the reader will follow these exactly.
Number every step. Include exact HTTP requests.

```
Prerequisites:
- Account A (attacker): attacker@test.com / registered free account
- Account B (victim):   victim@test.com / registered free account
- Attacker needs to know a valid order ID belonging to Account B
  (obtainable by browsing the order confirmation page: /orders/10046)

Steps:
1. Log in as Account A (attacker@test.com)
2. Capture your session token from any authenticated request:
   Authorization: Bearer eyJhbGci...

3. Make the following request, substituting Account B's order ID:

   GET /api/v2/orders/10046 HTTP/1.1
   Host: api.target.com
   Authorization: Bearer ATTACKER_TOKEN
   Content-Type: application/json

4. Observe the response:

   HTTP/1.1 200 OK
   {
     "order_id": 10046,
     "customer": {
       "name": "Jane Victim",
       "email": "victim@test.com",
       "phone": "+1-555-0100",
       "address": "123 Main St, Springfield, IL"
     },
     "items": [...],
     "payment_last4": "4242"
   }

5. The response contains Account B's full PII and order details,
   despite the request being made with Account A's credentials.
```

---

### Proof of Concept

Include at minimum:
- Screenshot or HTTP request/response pair
- Video walkthrough for complex exploits (Loom, Streamable)
- Working curl command (for APIs)

```bash
# Working PoC curl command:
curl -sk 'https://api.target.com/api/v2/orders/10046' \
  -H 'Authorization: Bearer ATTACKER_TOKEN' \
  -H 'Content-Type: application/json'

# Expected output (victim's data):
# {"order_id":10046,"customer":{"name":"Jane Victim","email":"victim@test.com",...}}
```

---

### Impact

The most important section. Be specific. Quantify when possible.

```
An attacker with any valid account can:
1. Access the full name, email, phone number, and shipping address of any customer
2. View complete order history for any user in the system
3. Retrieve partial payment card information (last 4 digits, card type)

With sequential order IDs (currently starting at ~10000 range), an attacker
could enumerate all orders in the system automatically, exposing PII of
every customer who has ever placed an order.

This constitutes a data breach event under GDPR Article 33, potentially
requiring regulatory disclosure within 72 hours of discovery.

Estimated affected records: all orders in system (order IDs are sequential
starting from low values, indicating potentially thousands of records).
```

---

### Remediation

Always include. Shows you understand the vulnerability and builds credibility.

```
Recommended fixes:
1. [PRIMARY] Before returning order data, verify that the authenticated
   user's account ID matches the customer_id associated with the requested
   order_id. Example:
   
   if order.customer_id != current_user.id:
       return 403 Forbidden

2. [SECONDARY] Consider using non-sequential, random UUIDs for order IDs
   to prevent enumeration even if access control is misconfigured.

3. [ADDITIONAL] Implement logging and alerting for unusual patterns of
   order ID lookups from a single account.
```

---

### References

```
- OWASP IDOR: https://owasp.org/www-chapter-ghana/assets/slides/IDOR.pdf
- OWASP API Security Top 10 - API1: Broken Object Level Authorization
- HackerOne similar disclosed report: https://hackerone.com/reports/XXXXXX
```

---

## Quality Checklist

Before submitting, verify:

```
[ ] Title clearly states: vuln type + location + impact
[ ] Summary is readable by non-technical person
[ ] Steps to reproduce are numbered and exact
[ ] HTTP requests included (not just screenshots)
[ ] Both attacker and victim accounts are clearly labeled
[ ] PoC curl command or code is included and works
[ ] Impact section quantifies affected users/data
[ ] Severity justification addresses likely objections
[ ] Remediation is specific (not just "add authorization check")
[ ] Affected asset URL matches in-scope list exactly
[ ] Duplicate check was done (see duplicate_checker.md)
[ ] All screenshots/videos are attached, not just referenced
```

---

## Platform-Specific Adjustments

### HackerOne
- Use their CVSS calculator for Severity field
- Attach all files directly — don't use external links if avoidable
- Set "Weakness" type accurately (maps to CWE)

### Bugcrowd
- Select VRT category carefully — it affects base payout
- Include "Environment" field: Production / Staging / Both

### Intigriti
- Impact and business context are weighted heavily
- Include regulatory implications (GDPR, PCI-DSS) where relevant
