# Playbook: DNS Enumeration & Attack Surface Mapping

## Purpose
Comprehensive DNS enumeration to discover subdomains, map infrastructure, identify
misconfigurations, and expand the attack surface for bug bounty targets.
Input: target domain, IP range, or ASN.

---

## Step 1 -- Passive DNS Collection

Gather subdomains without touching the target directly.

```bash
# crt.sh Certificate Transparency logs
curl -s "https://crt.sh/?q=%25.TARGET.com&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh_subs.txt

# SecurityTrails API (requires API key)
curl -s "https://api.securitytrails.com/v1/domain/TARGET.com/subdomains" \
  -H "APIKEY: $SECURITYTRAILS_KEY" \
  | jq -r '.subdomains[]' | sed "s/$/.TARGET.com/" >> passive_subs.txt

# VirusTotal API (requires API key)
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=$VT_KEY&domain=TARGET.com" \
  | jq -r '.subdomains[]' >> passive_subs.txt

# DNSDumpster (scrape -- use with caution, may need session handling)
# Prefer API-based sources or tools that wrap it

# RapidDNS
curl -s "https://rapiddns.io/subdomain/TARGET.com?full=1#result" \
  | grep -oP '<td>[a-zA-Z0-9._-]+\.TARGET\.com</td>' \
  | sed 's/<\/?td>//g' | sort -u >> passive_subs.txt

# ProjectDiscovery Chaos (requires API key)
chaos -d TARGET.com -key $CHAOS_KEY -silent >> passive_subs.txt

# CertSpotter
curl -s "https://api.certspotter.com/v1/issuances?domain=TARGET.com&include_subdomains=true&expand=dns_names" \
  | jq -r '.[].dns_names[]' | sed 's/\*\.//g' | sort -u >> passive_subs.txt

# Deduplicate
sort -u passive_subs.txt -o passive_subs.txt
echo "Passive subdomains: $(wc -l < passive_subs.txt)"
```

---

## Step 2 -- Active Subdomain Enumeration

```bash
# subfinder -- aggregates 40+ passive sources
subfinder -d TARGET.com -all -silent -o subfinder_subs.txt

# amass enum -- passive + active DNS resolution
amass enum -d TARGET.com -passive -o amass_passive.txt
amass enum -d TARGET.com -active -o amass_active.txt

# Merge all sources
cat passive_subs.txt subfinder_subs.txt amass_passive.txt amass_active.txt \
  | sort -u > all_subs_raw.txt
echo "Total unique subdomains before resolution: $(wc -l < all_subs_raw.txt)"
```

---

## Step 3 -- DNS Resolution & Validation

Resolve all discovered subdomains and filter dead ones.

```bash
# Prepare resolvers list (critical for accuracy)
# Use fresh public resolvers -- stale ones cause false positives
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt

# puredns -- resolve with wildcard filtering built in
puredns resolve all_subs_raw.txt \
  -r resolvers.txt \
  --write resolved_subs.txt \
  --write-wildcards wildcards.txt \
  --write-massdns massdns_out.txt

# Alternative: massdns for raw speed
massdns -r resolvers.txt -t A -o S -w massdns_raw.txt all_subs_raw.txt

# Alternative: dnsx for targeted resolution
dnsx -l all_subs_raw.txt -silent -a -resp -o dnsx_resolved.txt

echo "Live subdomains: $(wc -l < resolved_subs.txt)"
echo "Wildcards detected: $(wc -l < wildcards.txt)"
```

---

## Step 4 -- DNS Record Analysis

Pull all record types for each resolved subdomain.

```bash
# A and AAAA records (IPv4 + IPv6)
dnsx -l resolved_subs.txt -a -resp-only -silent -o a_records.txt
dnsx -l resolved_subs.txt -aaaa -resp-only -silent -o aaaa_records.txt

# CNAME records (critical for subdomain takeover)
dnsx -l resolved_subs.txt -cname -resp -silent -o cname_records.txt

# MX records (mail infrastructure)
dnsx -l resolved_subs.txt -mx -resp -silent -o mx_records.txt

# NS records (delegation)
dnsx -l resolved_subs.txt -ns -resp -silent -o ns_records.txt

# TXT records (SPF, DKIM, verification tokens)
dnsx -l resolved_subs.txt -txt -resp -silent -o txt_records.txt

# SOA records (zone authority)
dnsx -l resolved_subs.txt -soa -resp -silent -o soa_records.txt

# SRV records (service discovery -- often overlooked)
for srv in _sip._tcp _sip._udp _xmpp-client._tcp _xmpp-server._tcp \
  _caldav._tcp _carddav._tcp _ldap._tcp _kerberos._tcp _http._tcp; do
  dig +short SRV "${srv}.TARGET.com" | grep -v "^$" \
    && echo "  -> ${srv}.TARGET.com"
done > srv_records.txt

# PTR records (reverse DNS on discovered IPs)
cat a_records.txt | sort -u | while read ip; do
  ptr=$(dig +short -x "$ip" 2>/dev/null)
  [ -n "$ptr" ] && echo "$ip -> $ptr"
done > ptr_records.txt

# Full record dump per subdomain (for deep analysis)
while read sub; do
  echo "=== $sub ===" >> full_dns_dump.txt
  dig ANY "$sub" +noall +answer >> full_dns_dump.txt 2>/dev/null
done < resolved_subs.txt
```

---

## Step 5 -- Zone Transfer Testing

Zone transfers expose the entire DNS zone if misconfigured.

```bash
# Get nameservers for the target
dig +short NS TARGET.com > nameservers.txt

# Test AXFR against each nameserver
while read ns; do
  echo "--- Testing AXFR on $ns ---"
  dig AXFR TARGET.com "@$ns" +noall +answer
done < nameservers.txt | tee zone_transfer_results.txt

# Alternative with host
while read ns; do
  host -l TARGET.com "$ns" 2>&1
done < nameservers.txt >> zone_transfer_results.txt

# Alternative with nslookup
# nslookup -> server NS1.TARGET.COM -> ls -d TARGET.com

# Check for IXFR (incremental zone transfer) as well
while read ns; do
  dig IXFR=0 TARGET.com "@$ns" +noall +answer
done < nameservers.txt >> zone_transfer_results.txt

# If zone transfer succeeds -> CRITICAL finding, extract all records
grep -v "^---\|^$" zone_transfer_results.txt | sort -u > zt_records.txt
```

---

## Step 6 -- Wildcard DNS Detection & Handling

Wildcard records cause false positives in enumeration. Detect and filter them.

```bash
# Test for wildcard by querying random nonexistent subdomains
for i in $(seq 1 5); do
  random=$(cat /dev/urandom | tr -dc 'a-z' | head -c 12)
  result=$(dig +short A "${random}.TARGET.com")
  echo "${random}.TARGET.com -> $result"
done | tee wildcard_test.txt

# If all return the same IP -> wildcard is active
wildcard_ip=$(head -1 wildcard_test.txt | awk '{print $NF}')

# Filter wildcard responses from results
if [ -n "$wildcard_ip" ] && [ "$wildcard_ip" != "" ]; then
  echo "[WILDCARD DETECTED] IP: $wildcard_ip"
  # Remove subdomains resolving only to the wildcard IP
  while read sub; do
    ip=$(dig +short A "$sub" | head -1)
    [ "$ip" != "$wildcard_ip" ] && echo "$sub"
  done < resolved_subs.txt > filtered_subs.txt
else
  cp resolved_subs.txt filtered_subs.txt
fi

# puredns handles this automatically with --wildcard-tests flag
# shuffledns also has built-in wildcard filtering:
shuffledns -d TARGET.com -w wordlist.txt -r resolvers.txt \
  -o shuffledns_out.txt -wt 5
```

---

## Step 7 -- Reverse DNS on IP Ranges

Discover additional hostnames by reverse-resolving IP ranges.

```bash
# Identify IP ranges from resolved subdomains
cat a_records.txt | sort -u > target_ips.txt

# Group by /24 to find CIDR blocks
cat target_ips.txt | cut -d'.' -f1-3 | sort -u | while read prefix; do
  echo "${prefix}.0/24"
done > cidr_ranges.txt

# Mass reverse DNS with hakrevdns
cat target_ips.txt | hakrevdns -d | tee reverse_dns.txt

# Reverse DNS on full /24 ranges (expand the surface)
for cidr in $(cat cidr_ranges.txt); do
  prips "$cidr" | hakrevdns -d
done | sort -u >> reverse_dns.txt

# Filter for target-related hostnames
grep -i "TARGET" reverse_dns.txt > reverse_dns_relevant.txt

# Alternative: dig PTR on a range
for cidr in $(cat cidr_ranges.txt); do
  prips "$cidr" | while read ip; do
    ptr=$(dig +short -x "$ip" 2>/dev/null)
    [ -n "$ptr" ] && echo "$ip -> $ptr"
  done
done > ptr_range_results.txt
```

---

## Step 8 -- DNS Bruteforce

Active bruteforce with curated wordlists.

```bash
# Wordlist selection (use multiple, merge)
# Small/fast: n0kovo_subdomains_small.txt (~100K)
# Medium: best-dns-wordlist.txt (~1M, from Assetnote)
# Large: all.txt from SecLists (~2M)
# Targeted: generate from existing subdomains
cat resolved_subs.txt | sed "s/.TARGET.com//" | sort -u > known_prefixes.txt

# shuffledns bruteforce with wildcard filtering
shuffledns -d TARGET.com -w /opt/wordlists/best-dns-wordlist.txt \
  -r resolvers.txt -o bruteforce_subs.txt

# puredns bruteforce (recommended -- best wildcard handling)
puredns bruteforce /opt/wordlists/best-dns-wordlist.txt TARGET.com \
  -r resolvers.txt \
  --write bruteforce_puredns.txt \
  --write-wildcards bruteforce_wildcards.txt

# Permutation bruteforce -- combine known prefixes with mutations
# gotator generates permutations from existing subdomains
gotator -sub resolved_subs.txt -perm /opt/wordlists/permutations.txt \
  -depth 1 -numbers 3 -md | head -10000000 > permutations.txt
puredns resolve permutations.txt -r resolvers.txt --write permutation_results.txt

# alterx for smart subdomain wordlist generation
echo "TARGET.com" | alterx -enrich -silent | dnsx -silent -o alterx_results.txt

# Resolver management -- keep resolvers fresh
# Validate resolvers before bruteforce
dnsvalidator -tL https://public-dns.info/nameservers.txt \
  -threads 100 -o fresh_resolvers.txt

# False positive filtering
# Compare bruteforce results against wildcard IPs
# Discard subdomains pointing to known wildcard addresses
# Cross-reference with passive results for confidence scoring
comm -12 <(sort bruteforce_puredns.txt) <(sort passive_subs.txt) > high_confidence.txt
comm -23 <(sort bruteforce_puredns.txt) <(sort passive_subs.txt) > brute_only.txt
```

---

## Step 9 -- TXT Record OSINT

TXT records leak infrastructure details, third-party services, and email security posture.

```bash
# Pull all TXT records for the apex domain
dig TXT TARGET.com +short | tee txt_apex.txt

# SPF analysis -- reveals authorized mail senders and infrastructure
dig TXT TARGET.com +short | grep "v=spf1" | tee spf_record.txt
# Parse SPF includes to map third-party services
grep -oP 'include:([^\s]+)' spf_record.txt | while read inc; do
  echo "--- $inc ---"
  dig TXT "$(echo $inc | cut -d: -f2)" +short
done > spf_includes.txt

# DMARC record
dig TXT _dmarc.TARGET.com +short | tee dmarc_record.txt
# p=none means no enforcement -- email spoofing may be possible

# DKIM selectors (common ones -- bruteforce for more)
for selector in default google selector1 selector2 s1 s2 k1 k2 \
  mail dkim sig1 mandrill; do
  result=$(dig TXT "${selector}._domainkey.TARGET.com" +short 2>/dev/null)
  [ -n "$result" ] && echo "${selector}: $result"
done | tee dkim_records.txt

# Domain verification tokens -- reveal third-party services in use
dig TXT TARGET.com +short | grep -iE \
  "MS=|google-site-verification|facebook-domain|_globalsign|docusign|\
   adobe-idp|atlassian-domain|hubspot|amazonses|v=BIMI|stripe-verification|\
   apple-domain|zoom|webex|citrix|logmein" \
  | tee verification_tokens.txt

# MX-based service identification
dig MX TARGET.com +short | tee mx_analysis.txt
# google.com MX -> G Suite
# outlook.com MX -> Microsoft 365
# pphosted.com MX -> Proofpoint
# mimecast.com MX -> Mimecast
```

---

## Step 10 -- NS Delegation Analysis

Identify DNS providers and check for NS takeover opportunities.

```bash
# Get authoritative nameservers
dig NS TARGET.com +short | tee ns_servers.txt

# Identify DNS provider
# Common patterns:
# ns-*.awsdns-*.{com,net,org,co.uk} -> AWS Route53
# *.domaincontrol.com -> GoDaddy
# *.cloudflare.com -> Cloudflare
# *.nsone.net -> NS1
# *.ultradns.{com,net,org} -> UltraDNS
# *.azure-dns.{com,net,org,info} -> Azure DNS
# *.googledomains.com -> Google Cloud DNS
# *.dynect.net -> Dyn/Oracle

# Check for lame delegation (NS records pointing to non-authoritative servers)
while read ns; do
  result=$(dig SOA TARGET.com "@$ns" +short 2>/dev/null)
  if [ -z "$result" ]; then
    echo "[LAME DELEGATION] $ns does not respond authoritatively"
  fi
done < ns_servers.txt | tee lame_delegation.txt

# NS takeover check -- does the NS domain itself expire or is it unclaimed?
while read ns; do
  ns_domain=$(echo "$ns" | sed 's/\.$//')
  whois_result=$(dig +short A "$ns_domain" 2>/dev/null)
  if [ -z "$whois_result" ]; then
    echo "[NS TAKEOVER CANDIDATE] $ns_domain does not resolve"
  fi
done < ns_servers.txt | tee ns_takeover.txt

# Check delegation for each subdomain (some may use different NS)
while read sub; do
  ns=$(dig +short NS "$sub" 2>/dev/null)
  [ -n "$ns" ] && echo "$sub -> $ns"
done < resolved_subs.txt | sort -u > subdomain_delegations.txt
```

---

## Step 11 -- DNSSEC Analysis & NSEC Walking

If DNSSEC is enabled with NSEC (not NSEC3), zone contents can be enumerated.

```bash
# Check if DNSSEC is enabled
dig DNSKEY TARGET.com +short | tee dnssec_check.txt
dig TARGET.com +dnssec +short

# Check for NSEC vs NSEC3
dig NSEC TARGET.com +short
dig NSEC3PARAM TARGET.com +short

# NSEC zone walking (if NSEC is used, not NSEC3)
# ldns-walk (from ldns package)
ldns-walk TARGET.com | tee nsec_walk.txt

# Alternative: nsec3walker for NSEC3 cracking
# nsec3walker collects NSEC3 hashes, then cracks them offline
nsec3walker collect TARGET.com > nsec3_hashes.txt
nsec3walker crack nsec3_hashes.txt /opt/wordlists/subdomains.txt > nsec3_cracked.txt

# dnsrecon NSEC walking
dnsrecon -d TARGET.com -t zonewalk -o dnsrecon_nsec.txt

# Check DS records at parent zone (delegation signer)
dig DS TARGET.com +short | tee ds_records.txt
```

---

## Step 12 -- Certificate Transparency Deep Dive

CT logs provide historical and current subdomain data.

```bash
# crt.sh API -- full JSON with issuer and dates
curl -s "https://crt.sh/?q=%25.TARGET.com&output=json" \
  | jq -r '.[] | "\(.not_before) \(.not_after) \(.name_value)"' \
  | sort -u > ct_timeline.txt

# Extract unique subdomains from CT
curl -s "https://crt.sh/?q=%25.TARGET.com&output=json" \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | tr '\n' '\n' \
  | sort -u > ct_subdomains.txt

# CertSpotter API (higher rate limits than crt.sh)
curl -s "https://api.certspotter.com/v1/issuances?domain=TARGET.com&include_subdomains=true&expand=dns_names" \
  | jq -r '.[].dns_names[]' | sort -u >> ct_subdomains.txt

# Historical certificates -- find old/expired subdomains that may still resolve
curl -s "https://crt.sh/?q=%25.TARGET.com&output=json&exclude=expired" \
  | jq -r '.[].name_value' | sort -u > ct_active_certs.txt

# Compare active vs all CT subdomains
comm -23 <(sort ct_subdomains.txt) <(sort ct_active_certs.txt) > ct_expired_subs.txt
# Expired cert subdomains may still resolve -- check for takeover potential
dnsx -l ct_expired_subs.txt -silent -a -resp -o ct_expired_live.txt

# Look for wildcard certs (indicates scope of infrastructure)
grep '^\*\.' ct_timeline.txt | sort -u > wildcard_certs.txt

# Look for internal/interesting hostnames in CT
grep -iE "(internal|staging|dev|test|admin|api|vpn|mail|portal|jenkins|gitlab|jira)" \
  ct_subdomains.txt > ct_interesting.txt

echo "CT subdomains: $(wc -l < ct_subdomains.txt)"
echo "Interesting: $(wc -l < ct_interesting.txt)"
echo "Expired but live: $(wc -l < ct_expired_live.txt)"
```

---

## Step 13 -- DNS Rebinding (Theory & Detection)

DNS rebinding can be chained with SSRF for internal network access.

```bash
# Theory:
# 1. Attacker controls a domain (evil.com) with very low TTL
# 2. First DNS query returns attacker IP (passes browser/server checks)
# 3. Second DNS query returns internal IP (127.0.0.1, 169.254.169.254, etc.)
# 4. Application makes request to "evil.com" but hits internal service
#
# Useful when:
# - Target fetches URLs you provide (webhook, avatar URL, import URL)
# - Target has SSRF protections that check DNS at request time
# - You need to bypass IP-based allowlists/denylists
#
# Detection: check if target is vulnerable to rebinding

# Check TTL of target's DNS records (low TTL = they might be doing dynamic DNS)
dig TARGET.com +noall +answer | awk '{print $2}' | head -5

# Test with a rebinding service (for authorized testing only)
# rbndr.us -- returns alternating IPs
# Example: A record for 7f000001.ATTACKER_IP.rbndr.us
# Alternates between 127.0.0.1 and ATTACKER_IP
nslookup 7f000001.c0a80001.rbndr.us

# singularity -- full DNS rebinding attack framework
# https://github.com/nccgroup/singularity
# Set up: configure attacker DNS server with rebinding payload
# Requires infrastructure setup -- not a passive check

# whonow -- dynamic DNS rebinding server
# https://github.com/brannondorsey/whonow
# Query format: A.10.0.0.1.forever.B.127.0.0.1.forever.whonow.mattbryant.io

# Check if target validates DNS resolution timing
# If target resolves DNS, checks IP, then resolves again to fetch:
#   -> vulnerable to TOCTOU DNS rebinding
# If target pins DNS resolution:
#   -> likely not vulnerable

# Common rebinding targets:
# 127.0.0.1         -- localhost services
# 169.254.169.254   -- cloud metadata (AWS/GCP/Azure)
# 10.0.0.0/8        -- internal RFC1918
# 172.16.0.0/12     -- internal RFC1918
# 192.168.0.0/16    -- internal RFC1918
# [::1]             -- IPv6 localhost
```

---

## Step 14 -- Comprehensive dnsrecon & fierce Scans

```bash
# dnsrecon -- all-in-one DNS enumeration
dnsrecon -d TARGET.com -t std -o dnsrecon_standard.txt    # standard records
dnsrecon -d TARGET.com -t brt -D /opt/wordlists/subdomains-top1million-5000.txt  # bruteforce
dnsrecon -d TARGET.com -t axfr                             # zone transfer
dnsrecon -d TARGET.com -t rvl -r CIDR_RANGE               # reverse lookup
dnsrecon -d TARGET.com -t srv                              # SRV enumeration
dnsrecon -d TARGET.com -t snoop -n NS_SERVER               # cache snooping

# fierce -- DNS reconnaissance
fierce --domain TARGET.com --subdomains /opt/wordlists/fierce-hostlist.txt \
  | tee fierce_output.txt

# dig deep -- custom queries for edge cases
# Check for ANY record (some servers still respond)
dig ANY TARGET.com @8.8.8.8 +noall +answer

# Check for CAA records (Certificate Authority Authorization)
dig CAA TARGET.com +short

# Check for LOC records (geographic location -- rare but informative)
dig LOC TARGET.com +short

# CHAOS class queries -- may leak server version
dig @NS_SERVER version.bind txt chaos
dig @NS_SERVER hostname.bind txt chaos
dig @NS_SERVER id.server txt chaos
```

---

## Step 15 -- Merge & Deduplicate All Results

```bash
# Combine all subdomain sources
cat passive_subs.txt subfinder_subs.txt amass_passive.txt amass_active.txt \
  bruteforce_puredns.txt permutation_results.txt ct_subdomains.txt \
  reverse_dns_relevant.txt alterx_results.txt \
  2>/dev/null | sort -u > all_subdomains_final.txt

# Final resolution check
puredns resolve all_subdomains_final.txt -r resolvers.txt \
  --write live_subdomains.txt

# Probe with httpx for web services
httpx -l live_subdomains.txt -silent -status-code -title -tech-detect \
  -follow-redirects -o httpx_output.txt

echo "=== DNS ENUMERATION COMPLETE ==="
echo "Total unique subdomains: $(wc -l < all_subdomains_final.txt)"
echo "Live subdomains: $(wc -l < live_subdomains.txt)"
echo "Web services: $(wc -l < httpx_output.txt)"
```

---

## Output

For each significant finding:

```
ASSET     : TARGET.com
FINDING   : [description]
TYPE      : [zone_transfer | ns_takeover | lame_delegation | wildcard |
             subdomain_count | dnssec_walk | email_spoofing | rebinding_vector]
SEVERITY  : [CRITICAL | HIGH | MEDIUM | INFO]
EVIDENCE  : [command output or record data]
NEXT STEP : [recommended follow-up action]
```

Example findings:

```
ASSET     : TARGET.com
FINDING   : Zone transfer enabled on ns2.TARGET.com -- full zone exposed
TYPE      : zone_transfer
SEVERITY  : CRITICAL
EVIDENCE  : dig AXFR TARGET.com @ns2.TARGET.com returned 847 records
NEXT STEP : Document all records, check for internal hostnames, report immediately

ASSET     : TARGET.com
FINDING   : DMARC policy is p=none -- email spoofing possible
TYPE      : email_spoofing
SEVERITY  : MEDIUM
EVIDENCE  : _dmarc.TARGET.com TXT "v=DMARC1; p=none; rua=..."
NEXT STEP : Test email spoofing with controlled recipient, chain with phishing scenario

ASSET     : old-api.TARGET.com
FINDING   : Expired CT cert subdomain still resolves to orphaned server
TYPE      : subdomain_count
SEVERITY  : HIGH
EVIDENCE  : Certificate expired 2024-01-15, host returns default nginx page
NEXT STEP : Check for subdomain takeover, test for exposed services
```

---

## Findings Severity Guide

| Finding | Severity |
|---|---|
| Zone transfer enabled (AXFR) | CRITICAL |
| NS takeover possible (unresolvable NS) | CRITICAL |
| Lame delegation (non-authoritative NS) | HIGH |
| NSEC zone walking exposes full zone | HIGH |
| Subdomain with expired cert still live | HIGH |
| SPF/DMARC misconfiguration (p=none) | MEDIUM |
| Wildcard DNS active (enumeration impact) | MEDIUM |
| DNS rebinding vector identified | MEDIUM |
| Domain verification tokens leaked | INFO |
| DNSSEC not enabled | INFO |
| Low TTL on records | INFO |
| CHAOS class version disclosure | INFO |

---

## Tools Reference

```bash
# Core DNS tools
# dig, nslookup, host -- included with bind-utils / dnsutils

# Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/hakluke/hakrevdns@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/Josue87/gotator@latest

# massdns (compile from source)
git clone https://github.com/blechschmidt/massdns.git && cd massdns && make

# amass
go install github.com/owasp-amass/amass/v4/...@master

# Python tools
pip install dnsrecon
pip install fierce

# DNSSEC tools
# ldns-walk -- part of ldns package
# apt install ldnsutils / brew install ldns

# Resolver validator
go install github.com/vortexau/dnsvalidator/cmd/dnsvalidator@latest

# Wordlists
# https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS
# https://wordlists.assetnote.io/ (best-dns-wordlist)
# https://github.com/n0kovo/n0kovo_subdomains
```
