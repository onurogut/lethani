# Playbook: Virtual Host Discovery

## Purpose
Discover hidden virtual hosts, subdomains, and alternative web applications
hosted on the same IP by fuzzing the Host header. Reveals admin panels,
staging environments, internal tools, and undocumented APIs.
Input: target IP or domain.

---

## Step 1 — Baseline Response

```bash
TARGET_IP="TARGET_IP"
TARGET_DOMAIN="TARGET"

# Get baseline response for comparison
# Response with correct Host
curl -sk -o /tmp/vhost_baseline.txt -D /tmp/vhost_baseline_headers.txt \
  -H "Host: $TARGET_DOMAIN" "https://$TARGET_IP/"
BASELINE_SIZE=$(wc -c < /tmp/vhost_baseline.txt)
BASELINE_WORDS=$(wc -w < /tmp/vhost_baseline.txt)
echo "Baseline: ${BASELINE_SIZE} bytes, ${BASELINE_WORDS} words"

# Response with IP (no Host / IP as Host)
curl -sk -o /tmp/vhost_default.txt "https://$TARGET_IP/"
DEFAULT_SIZE=$(wc -c < /tmp/vhost_default.txt)
echo "Default (IP): ${DEFAULT_SIZE} bytes"

# Response with random Host (to identify default/catch-all)
curl -sk -o /tmp/vhost_random.txt \
  -H "Host: randomnonexistent12345.com" "https://$TARGET_IP/"
RANDOM_SIZE=$(wc -c < /tmp/vhost_random.txt)
echo "Random host: ${RANDOM_SIZE} bytes"
```

---

## Step 2 — ffuf Virtual Host Fuzzing

```bash
# Using ffuf with Host header fuzzing
ffuf -u "https://$TARGET_IP/" \
  -H "Host: FUZZ.$TARGET_DOMAIN" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs $RANDOM_SIZE \
  -mc all \
  -o vhost_results.json \
  -of json

# With multiple filter options
ffuf -u "https://$TARGET_IP/" \
  -H "Host: FUZZ.$TARGET_DOMAIN" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -fs $RANDOM_SIZE \
  -fw $BASELINE_WORDS \
  -mc all \
  -t 50 \
  -rate 100

# Full domain fuzzing (not just subdomains)
ffuf -u "https://$TARGET_IP/" \
  -H "Host: FUZZ" \
  -w custom_vhost_wordlist.txt \
  -fs $RANDOM_SIZE \
  -mc all
```

---

## Step 3 — gobuster vhost Mode

```bash
# gobuster vhost discovery
gobuster vhost -u "https://$TARGET_IP" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --domain "$TARGET_DOMAIN" \
  --append-domain \
  -t 50 \
  -o gobuster_vhost.txt

# With TLS (skip cert validation)
gobuster vhost -u "https://$TARGET_IP" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --domain "$TARGET_DOMAIN" \
  --append-domain \
  -k \
  -t 50
```

---

## Step 4 — Custom Wordlist Generation

```bash
# Build vhost wordlist from various sources

# From certificate transparency
curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" | \
  python3 -c "import sys,json; [print(d) for d in set(sum([x['name_value'].split('\n') for x in json.load(sys.stdin)],[]))]" | \
  sed "s/\*\.//g" | sort -u > ct_vhosts.txt

# From DNS brute results (if available)
cat dns_brute_results.txt 2>/dev/null >> ct_vhosts.txt

# Common internal vhost patterns
cat << 'EOF' >> custom_vhosts.txt
admin
api
api-internal
backend
beta
cms
console
dashboard
dev
development
grafana
internal
jenkins
jira
kibana
legacy
login
mail
manage
monitor
ops
panel
portal
prometheus
qa
staging
status
test
testing
tools
vpn
wiki
EOF

# Combine all
cat ct_vhosts.txt custom_vhosts.txt 2>/dev/null | sort -u > vhost_wordlist.txt
echo "Wordlist: $(wc -l < vhost_wordlist.txt) entries"
```

---

## Step 5 — Manual Targeted Testing

```bash
# Test specific high-value vhosts
VHOSTS=(
  "admin.$TARGET_DOMAIN"
  "api.$TARGET_DOMAIN"
  "staging.$TARGET_DOMAIN"
  "dev.$TARGET_DOMAIN"
  "internal.$TARGET_DOMAIN"
  "jenkins.$TARGET_DOMAIN"
  "grafana.$TARGET_DOMAIN"
  "portal.$TARGET_DOMAIN"
  "mail.$TARGET_DOMAIN"
  "vpn.$TARGET_DOMAIN"
)

for vhost in "${VHOSTS[@]}"; do
  RESP=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" \
    -H "Host: $vhost" "https://$TARGET_IP/")
  CODE=$(echo "$RESP" | cut -d: -f1)
  SIZE=$(echo "$RESP" | cut -d: -f2)
  [ "$SIZE" != "$RANDOM_SIZE" ] && echo "[HIT] $vhost → $CODE ($SIZE bytes)"
done

# Check for different response on HTTP vs HTTPS
for vhost in "${VHOSTS[@]}"; do
  HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -H "Host: $vhost" "http://$TARGET_IP/")
  HTTPS=$(curl -sk -o /dev/null -w "%{http_code}" -H "Host: $vhost" "https://$TARGET_IP/")
  echo "$vhost → HTTP:$HTTP HTTPS:$HTTPS"
done
```

---

## Step 6 — TLS Certificate Analysis

```bash
# Extract SANs from TLS certificate (reveals vhosts)
echo | openssl s_client -connect "$TARGET_IP:443" 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name" | \
  tr ',' '\n' | grep DNS | sed 's/.*DNS://g' | sort -u

# Check multiple ports for different certificates
for PORT in 443 8443 8080 4443; do
  SANS=$(echo | openssl s_client -connect "$TARGET_IP:$PORT" 2>/dev/null | \
    openssl x509 -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | \
    tr ',' '\n' | grep DNS | sed 's/.*DNS://g' | tr '\n' ', ')
  [ -n "$SANS" ] && echo "Port $PORT SANs: $SANS"
done

# SNI-based vhost check
for vhost in "${VHOSTS[@]}"; do
  CERT_CN=$(echo | openssl s_client -servername "$vhost" -connect "$TARGET_IP:443" 2>/dev/null | \
    openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN = //')
  echo "$vhost → Certificate CN: $CERT_CN"
done
```

---

## Step 7 — Verify and Enumerate Discovered Vhosts

```bash
# For each discovered vhost, gather details
DISCOVERED="admin.TARGET dev.TARGET staging.TARGET"

for vhost in $DISCOVERED; do
  echo "=== $vhost ==="
  # Title
  TITLE=$(curl -sk -H "Host: $vhost" "https://$TARGET_IP/" | \
    grep -oiE "<title>[^<]*</title>" | head -1)
  echo "Title: $TITLE"

  # Tech headers
  curl -sk -I -H "Host: $vhost" "https://$TARGET_IP/" | \
    grep -iE "^(server|x-powered|set-cookie|x-frame|content-type):" | head -5

  # Screenshot (if gowitness available)
  # gowitness single "https://$vhost/" --chrome-path /usr/bin/chromium

  echo ""
done
```

---

## Output

```
TARGET IP     : 203.0.113.50
DOMAIN        : example.com
BASELINE      : 15420 bytes (main site)
DEFAULT       : 5230 bytes (nginx welcome)
DISCOVERED    :
  admin.example.com    → 200 (8432 bytes) — Django admin panel
  staging.example.com  → 200 (15380 bytes) — staging environment
  api-v2.example.com   → 200 (124 bytes) — API endpoint
  jenkins.example.com  → 403 (294 bytes) — Jenkins CI (restricted)
SEVERITY      : MEDIUM-HIGH (depends on exposed content)
NEXT STEPS    : Test each vhost for auth bypass, default creds,
                information disclosure
```

---

## Tools Reference

```bash
# ffuf
go install github.com/ffuf/ffuf/v2@latest

# gobuster
go install github.com/OJ/gobuster/v3@latest

# Wordlists
# SecLists: Discovery/DNS/subdomains-top1million-*.txt
# https://github.com/danielmiessler/SecLists
```
