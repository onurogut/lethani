# Bug Bounty Lessons — Real Reports & Patterns

Patterns distilled from high-paying public disclosures and prior engagements.

---

## 1. Report Quality (Non-Negotiable)

**Title formula:** `[Vuln Type] in [endpoint/feature] allows [attacker action]`
- BAD: "XSS in web app"
- GOOD: "Stored XSS in order notes field allows session hijacking of support agents"

**Required sections:** Title, Summary (2-3 sentences), Steps to Reproduce (numbered + URL/param/role), Impact (concrete, not theoretical), Supporting Material (curl + screenshot), Remediation (optional, earns goodwill).

**Auto-reject triggers:** scanner copy-paste; theoretical impact ("could potentially…"); missing repro; exaggerated severity; broken formatting.

---

## 2. IDOR — Highest ROI ($1K–$12.5K)

**Discovery:**
1. Capture authenticated traffic in Caido/Burp.
2. Find EVERY ID parameter — URL path, query, JSON body, GraphQL variable, cookie.
3. **Two accounts mandatory** (Account A session + Account B object ID).
4. Test READ (GET) + WRITE (POST/PUT/DELETE) — both.
5. Horizontal (same role) + vertical (user → admin).

**ID types:** sequential int, UUID (flip one character), base64-encoded GraphQL node ID (decode + modify + re-encode), hashed (try predictable inputs).

**E-commerce IDOR hunting:**
```
/api/orders/{id}              — other users' order details
/api/users/{id}/addresses     — other users' addresses
/api/invoices/{id}            — other users' invoices
/api/payments/{id}            — other users' payment info
/api/tickets/{id}             — other users' support tickets
/api/wishlist/{id}            — other users' wishlists
/api/reviews/{id}             — delete/edit other users' reviews
/graphql (node ID)            — base64 decode + change type/number
```

**Public examples that paid:**
- PayPal $10,500 — `/businessmanage/users/api/v1/users` path ID
- Shopify $5,000 — GraphQL `BillingDocumentDownload`
- HackerOne $12,500 — GraphQL mutation, delete user certifications
- Starbucks — IDOR → ATO chain

---

## 3. SSRF — Highest Single-Vuln Potential ($3K–$25K)

**Where to look:** webhook, callback, import/export (Confluence ZIP, CSV, XLSX), profile picture URL, PDF generator, link preview, Open Graph fetcher. Parameter names: `url, uri, path, dest, redirect, src, source, link, feed`.

**Testing sequence:**
1. OOB confirm with Burp Collaborator / interactsh.io.
2. Internal target:
   ```
   http://169.254.169.254/latest/meta-data/         (AWS)
   http://metadata.google.internal/computeMetadata/v1/  (GCP)
   http://169.254.169.254/metadata/instance         (Azure)
   http://127.0.0.1:<common-ports>/
   ```
3. Bypasses:
   ```
   IP encoding:  0x7f000001 | 0177.0.0.1 | 2130706433 | 127.1
   IPv6:         [::1] | [::ffff:169.254.169.254]
   DNS rebind:   lock.cmpxchg8b.com/rebinder.html | rbndr.us
   Redirect:     302 on your server → internal IP
   URL parse:    evil.com@169.254.169.254 | 169.254.169.254%00.evil.com
   ```
4. If AWS metadata reachable:
   ```
   /latest/meta-data/iam/security-credentials/        → role list
   /latest/meta-data/iam/security-credentials/ROLE    → temp creds
   /latest/user-data                                  → startup scripts (may have secrets)
   ```

**Example — LarkSuite (Critical):** Wiki "import from docs" fetches image URLs server-side. Direct metadata blocked. DNS rebinding bypass, ~10 attempts, full EC2 creds exfiltrated.

**Example — HelloSign/Dropbox ($4,913):** Webhook URL → Collaborator → OOB confirm → metadata → private key.

---

## 4. XSS — Chain Required for Real Money ($500–$20K)

Standalone reflected XSS pays $500 or N/A. Find stored XSS or chain it.

**High-value patterns:**
- **Stored XSS in support tickets** → fires in admin panel = blind XSS = HIGH
- **Cache poisoning + XSS** → stored XSS at CDN scale = CRITICAL ($20K PayPal)
- **XSS + CSRF** → ATO = HIGH
- **XSS in email templates** → HTML inject + render

**Where to look in e-commerce:**
- Search (reflected)
- Product reviews (stored)
- Profile fields — name/address (stored)
- Support ticket subject/body (blind XSS — admin panel)
- 404/error pages with reflected path
- URL redirect param + `javascript:` protocol

**Public bounty:** PayPal $20K (sign-in cache poison + stored XSS); Valve $7,500 (Steam React `dangerouslySetInnerHTML`); Reddit $5K (redirect param → XSS); Basecamp $5K (HEY.com email stored XSS).

---

## 5. Auth & Session

**Password reset flow:**
- Token predictability (sequential? timestamp? short?)
- Token reuse after password change
- Host header poisoning in reset email link
- Rate limiting on reset requests
- IDOR on reset endpoint (reset other users' password)

**OAuth/SSO:**
- `redirect_uri` validation bypass (open redirect → token theft)
- `state` param missing or unvalidated (CSRF on OAuth)
- PKCE downgrade (plain vs S256)
- Account linking without email verification

---

## 6. E-Commerce Specific

**Payment flow manipulation (NOT coupon/voucher abuse):**
- Intercept checkout POST → modify `total_amount`
- Negative quantity/price
- Currency confusion (cross-region)
- Race: submit two payments simultaneously
- Modify shipping address after payment

**Cart/order:**
- Add items after price lock
- Quantity 0/negative after checkout
- Access other users' carts via ID
- Replay completed orders

**Example — Checkout price manipulation ($4,200):** Burp intercepts checkout POST, `total_amount` $115 → $0.50, server accepts client value without validation.

---

## 7. GraphQL

1. **Introspection:** `{__schema{types{name,fields{name}}}}` — if open, full schema.
2. **Batch query:** array of queries in one request → rate-limit bypass.
3. **Field suggestion:** typo a field, server suggests valid ones.
4. **Mutation auth gap:** queries require auth, mutations do not (common).
5. **Node ID enum:** base64-decode global IDs → change type prefix / numeric.
6. **Depth/complexity DoS:** no depth limit → nested query.

---

## 8. Vulnerability Chaining — Severity Escalation

| Chain                                | Combined                |
|--------------------------------------|-------------------------|
| Open redirect + OAuth                | LOW → CRITICAL          |
| SSRF + cloud metadata                | MED → CRITICAL          |
| XSS + CSRF                           | MED → HIGH              |
| IDOR + PII                           | MED → CRITICAL          |
| Cache poison + XSS                   | MED → CRITICAL ($20K)   |
| LFI + log poisoning                  | MED → CRITICAL (RCE)    |
| Prototype pollution + gadget         | MED → CRITICAL (RCE)    |
| HTTP smuggling + cache               | MED → HIGH              |
| Host header + password reset         | LOW → HIGH (ATO)        |
| Prompt injection + tool calling      | MED → CRITICAL          |
| CI/CD injection + secret exfil       | MED → CRITICAL          |

**Strategy:** after every low-severity finding, ask "what does this pair with?". Score on combined impact.

---

## 9. Program-Specific Discipline

1. **Read the entire policy** — exclusions, required headers, email format.
2. **Check the bounty table** — focus on vuln types in the highest tier.
3. **Read hacktivity** — what has been reported, avoid duplicates.
4. **Use program-required email** for account creation (e.g. `@wearehackerone.com`).
5. **Use EU/US VPN** if geo-restricted.
6. **Respect rate limits** — getting banned wastes time.
7. **Test on the primary domain** when specified (`.com`).
8. **Save everything** — curl, full HTTP request/response, timestamps.

---

## 10. Honest Self-Assessment (Before Submit)

1. "Would I pay money for this report?" — if no, don't submit.
2. "Is the impact real or am I stretching?"
3. "Could a competent attacker actually harm users with this?"
4. "Is this just a missing best practice?" — usually rejected.
5. "Does this match the program's focus areas?"

Low-quality reports damage your reputation score. One strong report beats ten weak ones.

---

## References

- HackerOne top reports: `github.com/reddelexc/hackerone-reports`
- Writeups: `pentester.land/writeups/`
- IDOR guide: `intigriti.com/researchers/hackademy/idor`
- SSRF + XSS: `github.com/swisskyrepo/PayloadsAllTheThings`
- H1 quality docs: `docs.hackerone.com/en/articles/8475116-quality-reports`
