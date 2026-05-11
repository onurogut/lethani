# Playbook: ASN & IP Range Mapper

## Purpose
Discover all IP ranges, ASNs, and netblocks owned by the target organization.
Ensures full infrastructure coverage beyond just known domains.
Used to expand scope and find assets not linked to the main domain.
Input: company name, domain, or known IP.

---

## Step 1 — Find ASN by Organization Name

```bash
TARGET_ORG="Target Inc"
TARGET_DOMAIN="target.com"

# Method A — BGPView API
curl -sk "https://api.bgpview.io/search?query_term=${TARGET_ORG// /+}" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin).get('data', {})
print('=== ASNs ===')
for asn in data.get('asns', []):
    print(f\"  AS{asn['asn']} — {asn['description']} ({asn.get('country_code','')})\")
print('=== IPv4 Prefixes ===')
for prefix in data.get('ipv4_prefixes', []):
    print(f\"  {prefix['prefix']} — {prefix.get('name','')}\")
" 2>/dev/null

# Method B — search via ARIN (for US companies)
curl -sk "https://rdap.arin.net/registry/entity/${TARGET_ORG// /%20}" \
  | python3 -m json.tool 2>/dev/null | grep -E '"handle"|"name"'

# Method C — whois
whois -h whois.radb.net -- "-i origin AS12345" 2>/dev/null | grep "route:"

# Method D — Hurricane Electric BGP Toolkit
echo "Manual: https://bgp.he.net/search?search[search]=${TARGET_ORG// /+}"
```

---

## Step 2 — Get All Prefixes for Known ASN

```bash
TARGET_ASN="12345"  # without AS prefix

# BGPView — get all prefixes
curl -sk "https://api.bgpview.io/asn/$TARGET_ASN/prefixes" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin).get('data', {})

print('=== IPv4 Prefixes ===')
for p in data.get('ipv4_prefixes', []):
    print(f\"  {p['prefix']}  ({p.get('name','')}) — {p.get('description','')}\")

print('=== IPv6 Prefixes ===')
for p in data.get('ipv6_prefixes', []):
    print(f\"  {p['prefix']}  ({p.get('name','')})\")" \
  > asn_prefixes.txt

cat asn_prefixes.txt
echo "Total prefixes: $(grep -c '^\s' asn_prefixes.txt)"
```

---

## Step 3 — Find ASN from Known IP

```bash
KNOWN_IP="1.2.3.4"

# BGPView — reverse lookup
curl -sk "https://api.bgpview.io/ip/$KNOWN_IP" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin).get('data', {})
prefixes = data.get('prefixes', [])
for p in prefixes:
    asn = p.get('asn', {})
    print(f\"IP: $KNOWN_IP\")
    print(f\"Prefix: {p.get('prefix')}\")
    print(f\"ASN: AS{asn.get('asn')} — {asn.get('description')}\")
    print(f\"Country: {p.get('country_code')}\")
"

# Via WHOIS
whois "$KNOWN_IP" | grep -iE "^(origin|route|netname|org|organisation|netrange|cidr)"

# Via ip-api
curl -sk "http://ip-api.com/json/$KNOWN_IP?fields=org,as,asname,isp,country,regionName,city"
```

---

## Step 4 — Enumerate IPs Within CIDR Ranges

```bash
# Extract CIDR ranges from asn_prefixes.txt
grep -oP '\d+\.\d+\.\d+\.\d+/\d+' asn_prefixes.txt > cidrs.txt
echo "CIDR ranges: $(wc -l < cidrs.txt)"

# Generate host list from CIDRs
# nmap style (fast)
nmap -sL -n $(cat cidrs.txt | tr '\n' ' ') 2>/dev/null \
  | grep "Nmap scan report" | awk '{print $NF}' > all_ips.txt

# Or with prips
while read cidr; do
  prips "$cidr"
done < cidrs.txt >> all_ips.txt

# Or with Python
python3 -c "
import ipaddress
with open('cidrs.txt') as f:
    for line in f:
        cidr = line.strip()
        if cidr:
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                # Skip huge blocks > /16
                if net.prefixlen < 16:
                    print(f'Skipping large block: {cidr}')
                    continue
                for ip in net.hosts():
                    print(ip)
            except:
                pass
" > all_ips.txt

echo "Total IPs to probe: $(wc -l < all_ips.txt)"
```

---

## Step 5 — Mass Probe IP Ranges

```bash
# Fast port scan to find live hosts with web services
# nmap — web ports only
nmap -iL all_ips.txt \
  -p 80,443,8080,8443,8888,3000,4000,5000,9000 \
  --open \
  -T4 \
  --min-rate 1000 \
  -oG nmap_web.txt 2>/dev/null

grep "open" nmap_web.txt | awk '{print $2}' | sort -u > live_hosts.txt
echo "Live hosts with web ports: $(wc -l < live_hosts.txt)"

# Convert to URLs for httpx
python3 -c "
with open('nmap_web.txt') as f:
    for line in f:
        if 'open' in line:
            parts = line.split()
            ip = parts[1]
            ports_raw = [p for p in parts if '/open' in p]
            for p in ports_raw:
                port = p.split('/')[0]
                scheme = 'https' if port in ('443','8443','4443') else 'http'
                print(f'{scheme}://{ip}:{port}')
" > ip_urls.txt

# Run httpx against all discovered IPs
cat ip_urls.txt | httpx \
  -silent \
  -status-code \
  -title \
  -tech-detect \
  -web-server \
  -content-length \
  -ip \
  -o ip_range_httpx.txt

echo "Live web services in IP ranges: $(wc -l < ip_range_httpx.txt)"
```

---

## Step 6 — Reverse DNS on IP Ranges

```bash
# Reverse DNS — find hostnames pointing to IPs
# Reveals shadow IT, forgotten assets, internal naming conventions

# dnsx — fast reverse DNS
dnsx -l all_ips.txt -ptr -silent -o reverse_dns.txt

# Or with dig
while read ip; do
  hostname=$(dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//')
  [ -n "$hostname" ] && echo "$ip → $hostname"
done < live_hosts.txt > ptr_records.txt

# Filter for target domain-related hostnames
grep -iE "\.target\.com|\.targetcorp\." ptr_records.txt > target_ptr.txt

# New subdomains discovered via reverse DNS
cut -d' ' -f3 target_ptr.txt | sort -u > new_subdomains_from_rdns.txt
echo "New subdomains via PTR: $(wc -l < new_subdomains_from_rdns.txt)"
```

---

## Step 7 — Certificate Transparency for IP Range

```bash
# Find certificates issued for IPs in your ranges
# (some servers have certs that reveal internal hostnames)

while read ip; do
  # Grab cert CN and SANs
  result=$(echo | timeout 3 openssl s_client -connect "$ip:443" 2>/dev/null \
    | openssl x509 -noout -text 2>/dev/null \
    | grep -E "Subject:|DNS:" | tr -d ' ')
  [ -n "$result" ] && echo "$ip: $result"
done < live_hosts.txt > cert_info.txt

# Extract domain names from certs
grep -oP 'DNS:[^\s,]+' cert_info.txt \
  | sed 's/DNS://' \
  | grep -i "target\|corp\|internal" \
  | sort -u > cert_internal_domains.txt

echo "Internal domains from certs: $(wc -l < cert_internal_domains.txt)"
```

---

## Step 8 — Autonomous System Relationship Mapping

```bash
# Find related ASNs (same org may have multiple)
TARGET_ASN="12345"

# Get upstream/downstream AS relationships
curl -sk "https://api.bgpview.io/asn/$TARGET_ASN/upstreams" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin).get('data', {})
print('Upstream ASNs:')
for asn in data.get('ipv4_upstreams', []):
    print(f\"  AS{asn['asn']} — {asn.get('description','')} ({asn.get('country_code','')})\")
"

# Check if org has multiple ASNs (subsidiaries, regions)
curl -sk "https://api.bgpview.io/search?query_term=${TARGET_ORG// /+}" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin).get('data', {})
for asn in data.get('asns', []):
    print(f\"  AS{asn['asn']} — {asn['description']}\")
"
```

---

## Output

```
TARGET        : Target Inc / target.com
─────────────────────────────────────────────────────
ASNs FOUND    :
  AS12345 — Target Inc (US)
  AS67890 — Target Inc EU (DE)   ← subsidiary

IP RANGES     :
  1.2.3.0/24     (Target Inc — Primary)
  4.5.6.0/22     (Target Inc — CDN)
  7.8.9.128/25   (Target Inc EU)
  Total IPs: 1,408

LIVE WEB      : 89 hosts with open web ports
PTR RECORDS   : 34 internal hostnames discovered
NEW SUBDOMAINS: 12 not in original DNS enumeration
CERT DOMAINS  : 8 internal domains from cert SANs
─────────────────────────────────────────────────────
NOTABLE:
  10 IPs with no PTR record but serving HTTPS (shadow IT)
  3 IPs with expired/self-signed certs
  2 IPs with internal hostnames (*.corp.target.com) in cert SANs
─────────────────────────────────────────────────────
NEXT STEPS:
  1. Feed ip_range_httpx.txt into httpx_triage framework
  2. Feed new_subdomains_from_rdns.txt into 01_recon pipeline
  3. Feed cert_internal_domains.txt into subdomain_takeover.md
  4. Run Shodan queries against newly discovered CIDRs
     → load 05_osint/shodan_censys_queries.md
```
