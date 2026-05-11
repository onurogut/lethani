# Playbook: Email Harvesting

## Purpose
Discover email addresses associated with a target organization for
social engineering assessment, credential stuffing checks, and attack
surface mapping. Covers passive OSINT, search engine dorking, and
data source enumeration.
Input: target domain or organization name.

---

## Step 1 — theHarvester

```bash
DOMAIN="TARGET"

# Comprehensive scan with multiple sources
theHarvester -d "$DOMAIN" -b all -l 500 -f harvest_results

# Individual sources for deeper results
theHarvester -d "$DOMAIN" -b google -l 200
theHarvester -d "$DOMAIN" -b bing -l 200
theHarvester -d "$DOMAIN" -b linkedin -l 200
theHarvester -d "$DOMAIN" -b hunter -l 200
theHarvester -d "$DOMAIN" -b crtsh -l 200
theHarvester -d "$DOMAIN" -b dnsdumpster -l 200

# Parse results
cat harvest_results.json | python3 -c "
import sys, json
data = json.load(sys.stdin)
emails = data.get('emails', [])
for e in sorted(set(emails)):
    print(e)
" > emails_harvested.txt

echo "Harvested: $(wc -l < emails_harvested.txt) unique emails"
```

---

## Step 2 — Search Engine Dorking

```bash
# Google dorks (use in browser or via API)
DORKS=(
  "site:$DOMAIN intext:@$DOMAIN"
  "\"@$DOMAIN\" -site:$DOMAIN"
  "\"@$DOMAIN\" filetype:pdf"
  "\"@$DOMAIN\" filetype:xlsx OR filetype:csv OR filetype:doc"
  "site:linkedin.com \"$DOMAIN\" email"
  "site:github.com \"@$DOMAIN\""
  "site:pastebin.com \"@$DOMAIN\""
  "\"@$DOMAIN\" site:twitter.com OR site:x.com"
)

echo "Google dorks to run:"
for dork in "${DORKS[@]}"; do
  echo "  $dork"
done

# Automated Google dorking (be careful with rate limits)
# Use proxies or manual search
```

---

## Step 3 — Hunter.io API

```bash
HUNTER_API="YOUR_API_KEY"

# Domain search
curl -s "https://api.hunter.io/v2/domain-search?domain=$DOMAIN&api_key=$HUNTER_API" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
print(f\"Organization: {data.get('organization')}\")
print(f\"Pattern: {data.get('pattern')}\")
print(f\"Total emails: {data.get('emails_count', 0)}\")
print()
for email in data.get('emails', []):
    conf = email.get('confidence', 0)
    print(f\"  {email['value']} (confidence: {conf}%, sources: {len(email.get('sources', []))})\")
"

# Email verification
curl -s "https://api.hunter.io/v2/email-verifier?email=john@$DOMAIN&api_key=$HUNTER_API" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
print(f\"Email: {data['email']}\")
print(f\"Status: {data['status']}\")
print(f\"Score: {data['score']}\")
"

# Email pattern discovery
curl -s "https://api.hunter.io/v2/domain-search?domain=$DOMAIN&api_key=$HUNTER_API&type=personal" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
print(f\"Email pattern: {data.get('pattern', 'unknown')}\")
# Patterns: {first}.{last}, {f}{last}, {first}{l}, etc.
"
```

---

## Step 4 — Phonebook.cz and Intelligence X

```bash
# phonebook.cz — free email/domain search
# Use via browser or API: https://phonebook.cz/

# IntelligenceX API
INTELX_API="YOUR_API_KEY"

# Search for emails
curl -s -X POST "https://2.intelx.io/intelligent/search" \
  -H "x-key: $INTELX_API" \
  -H "Content-Type: application/json" \
  -d "{\"term\":\"@$DOMAIN\",\"maxresults\":100,\"media\":0,\"sort\":2,\"terminate\":[]}"

# Results come async — poll with search ID
```

---

## Step 5 — LinkedIn OSINT

```bash
# Extract names from LinkedIn for email generation
# Manual: Search "company TARGET" on LinkedIn, note employee names

# crosslinked — scrape LinkedIn for names
crosslinked -f '{first}.{last}@$DOMAIN' -t 20 "TARGET Company Name"

# linkedin2username
python3 linkedin2username.py -c "TARGET Company" -d "$DOMAIN"

# Generate emails from discovered names
# Combine with email pattern from Hunter.io
python3 << 'PYEOF'
import sys

pattern = "{first}.{last}"  # From Hunter.io
domain = "TARGET"

names = [
    ("Ahmet", "Yilmaz"),
    ("Mehmet", "Kaya"),
    # Add discovered names
]

for first, last in names:
    f, l = first.lower(), last.lower()
    patterns = {
        "{first}.{last}": f"{f}.{l}",
        "{first}{last}": f"{f}{l}",
        "{f}{last}": f"{f[0]}{l}",
        "{first}{l}": f"{f}{l[0]}",
        "{f}.{last}": f"{f[0]}.{l}",
        "{last}.{first}": f"{l}.{f}",
    }
    for pat_name, email in patterns.items():
        print(f"{email}@{domain}")
PYEOF
```

---

## Step 6 — Data Breach Check

```bash
# Check if harvested emails appear in known breaches
# (for authorized assessment only)

# h8mail — email breach checking
h8mail -t emails_harvested.txt -o breach_results.txt

# haveibeenpwned API (requires API key)
HIBP_API="YOUR_HIBP_KEY"
while read email; do
  RESP=$(curl -s -H "hibp-api-key: $HIBP_API" \
    -H "user-agent: BugBountyRecon" \
    "https://haveibeenpwned.com/api/v3/breachedaccount/$email")
  if [ -n "$RESP" ] && [ "$RESP" != "[]" ]; then
    BREACHES=$(echo "$RESP" | python3 -c "import sys,json; print(','.join([b['Name'] for b in json.load(sys.stdin)]))")
    echo "[BREACH] $email — $BREACHES"
  fi
  sleep 1.5  # API rate limit
done < emails_harvested.txt
```

---

## Step 7 — Email Verification

```bash
# Verify discovered emails are valid (MX + SMTP check)

# Check MX records
dig MX "$DOMAIN" +short

# Basic SMTP verification script
python3 << 'PYEOF'
import smtplib
import dns.resolver

domain = "TARGET"

# Get MX record
mx_records = dns.resolver.resolve(domain, 'MX')
mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange)

print(f"MX Server: {mx_host}")

emails_to_check = open("emails_harvested.txt").read().strip().split("\n")

for email in emails_to_check[:10]:  # Limit to avoid blocks
    try:
        server = smtplib.SMTP(mx_host, 25, timeout=10)
        server.ehlo()
        server.mail("test@test.com")
        code, msg = server.rcpt(email)
        if code == 250:
            print(f"  [VALID] {email}")
        else:
            print(f"  [INVALID] {email} ({code})")
        server.quit()
    except Exception as e:
        print(f"  [ERROR] {email} ({e})")
PYEOF
```

---

## Step 8 — Consolidate Results

```bash
# Merge all sources
cat emails_harvested.txt emails_generated.txt crosslinked_results.txt 2>/dev/null | \
  tr '[:upper:]' '[:lower:]' | sort -u > emails_all.txt

# Categorize
grep -i "admin\|root\|postmaster\|info\|contact\|support" emails_all.txt > emails_generic.txt
grep -viE "admin|root|postmaster|info|contact|support" emails_all.txt > emails_personal.txt

echo "=== Email Harvest Summary ==="
echo "Total unique: $(wc -l < emails_all.txt)"
echo "Generic:      $(wc -l < emails_generic.txt)"
echo "Personal:     $(wc -l < emails_personal.txt)"
```

---

## Output

```
TARGET        : example.com
SOURCES       : theHarvester, Hunter.io, LinkedIn, Google dorks
PATTERN       : {first}.{last}@example.com
RESULTS       :
  Total emails found   : 87
  Verified valid       : 52
  In data breaches     : 12
  Generic (info/admin) : 8
  Personal             : 79
KEY FINDINGS  :
  - CTO's email found in 3 breaches (LinkedIn, Adobe, Dropbox)
  - Pattern allows generation of any employee's email
  - 4 emails found on GitHub in commit history
NEXT STEPS    : Check breached credentials, generate targeted phishing
                list for authorized social engineering test
```

---

## Tools Reference

```bash
# theHarvester
pip install theHarvester

# hunter.io — email finder (freemium API)
# https://hunter.io/api

# h8mail — email OSINT and breach check
pip install h8mail

# crosslinked — LinkedIn scraper
pip install crosslinked

# phonebook.cz — free email search
# https://phonebook.cz/
```
