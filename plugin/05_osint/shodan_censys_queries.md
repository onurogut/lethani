# Playbook: Shodan / Censys Query Builder

## Purpose
Generate optimized search queries for Shodan and Censys to discover
exposed infrastructure, services, and misconfigurations associated with the target.
Input: company name, domain, ASN, or IP range.

---

## Step 1 — Gather Identifiers

Before querying, collect all target identifiers:

```bash
TARGET_DOMAIN="target.com"
TARGET_ORG="Target Inc"      # company name as it appears in Shodan org field
TARGET_ASN="AS12345"         # from ASN lookup (see asn_ip_mapper.md)
TARGET_CIDR="1.2.3.0/24"    # known IP ranges

# Quick ASN lookup if you don't have it
curl -sk "https://api.bgpview.io/search?query_term=$TARGET_DOMAIN" \
  | python3 -c "import sys,json; data=json.load(sys.stdin); [print(a['asn'],a['description']) for a in data.get('data',{}).get('asns',[])]"

# Get SSL cert fingerprint for org (catches assets that don't mention domain in DNS)
echo | openssl s_client -connect "app.$TARGET_DOMAIN:443" 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 2>/dev/null
```

---

## Step 2 — Shodan Queries

### Organization-Based Discovery
```
org:"Target Inc"
org:"Target Inc" port:443
org:"Target Inc" http.title:"Login"
org:"Target Inc" http.title:"Dashboard"
org:"Target Inc" http.title:"Admin"
org:"Target Inc" product:"Jenkins"
org:"Target Inc" product:"Grafana"
org:"Target Inc" product:"Kibana"
org:"Target Inc" product:"Elasticsearch"
```

### ASN-Based Discovery
```
asn:AS12345
asn:AS12345 port:8080,8443,8888,3000,4000,5000
asn:AS12345 http.title:"Login"
asn:AS12345 product:"Apache Tomcat"
asn:AS12345 product:"nginx"
asn:AS12345 200
```

### SSL Certificate Discovery (catches all IPs with target's cert)
```
ssl:"target.com"
ssl.cert.subject.cn:"*.target.com"
ssl.cert.subject.org:"Target Inc"
ssl.cert.issuer.cn:"target.com"
ssl:"target.com" port:443,8443,4443
```

### Domain-Based Discovery
```
hostname:"target.com"
hostname:".target.com"
hostname:"api.target.com"
hostname:"internal.target.com"
```

### Specific Exposed Service Queries
```
# Exposed databases
org:"Target Inc" port:27017  # MongoDB
org:"Target Inc" port:6379   # Redis
org:"Target Inc" port:9200   # Elasticsearch
org:"Target Inc" port:5432   # PostgreSQL
org:"Target Inc" port:3306   # MySQL

# Exposed management panels
org:"Target Inc" http.title:"phpMyAdmin"
org:"Target Inc" http.title:"pgAdmin"
org:"Target Inc" http.title:"Redis Commander"
org:"Target Inc" http.title:"Mongo Express"

# Exposed CI/CD
org:"Target Inc" http.title:"Jenkins"
org:"Target Inc" http.title:"GitLab"
org:"Target Inc" http.title:"Grafana"
org:"Target Inc" http.title:"Kibana"

# Remote access
org:"Target Inc" port:3389  # RDP
org:"Target Inc" port:22    # SSH
org:"Target Inc" port:5900  # VNC
org:"Target Inc" product:"OpenVPN"
org:"Target Inc" http.title:"Pulse Secure"
org:"Target Inc" http.title:"Fortinet"
org:"Target Inc" http.title:"Citrix"

# Cloud metadata (misconfigured)
org:"Target Inc" "X-Amz-" http.status:200
```

### Vulnerability-Specific Queries
```
# Apache path traversal (CVE-2021-41773)
org:"Target Inc" "Apache/2.4.49"
org:"Target Inc" "Apache/2.4.50"

# Log4Shell targets
org:"Target Inc" http.title:"Confluence"
org:"Target Inc" http.title:"VMware"
org:"Target Inc" http.title:"vCenter"

# Exposed Kubernetes
org:"Target Inc" "kubernetes" port:6443,8443,10250

# Exposed Docker API
org:"Target Inc" port:2375,2376 "Docker"
```

---

## Step 3 — Shodan CLI Commands

```bash
# Install Shodan CLI
pip install shodan --break-system-packages
shodan init YOUR_API_KEY

# Search and download
shodan search "org:\"Target Inc\"" --fields ip_str,port,hostnames,org,product \
  | tee shodan_results.txt

# Download full results (requires paid API)
shodan download --limit 1000 shodan_dump "org:\"Target Inc\""
shodan parse --fields ip_str,port,product,http.title shodan_dump.json.gz \
  > shodan_parsed.txt

# Get info on specific IP
shodan host 1.2.3.4

# Alert on new assets (monitoring)
shodan alert create "Target Monitor" "org:\"Target Inc\""
```

---

## Step 4 — Censys Queries

Censys is better for SSL certificate enumeration and IPv6.

### Censys Search (Web UI: search.censys.io)
```
# By organization
autonomous_system.organization:"Target Inc"
autonomous_system.organization:"Target Inc" AND services.port:9200

# By certificate
parsed.names:"target.com"
parsed.subject_dn:"O=Target Inc"
parsed.issuer.organization:"Target Inc"

# By hostname
dns.reverse_dns.reverse_dns:"target.com"

# By IP range
ip:[1.2.3.0 TO 1.2.3.255]

# Exposed services
services.service_name:ELASTICSEARCH AND autonomous_system.organization:"Target Inc"
services.service_name:REDIS AND autonomous_system.organization:"Target Inc"
services.service_name:MONGODB AND autonomous_system.organization:"Target Inc"
services.service_name:KUBERNETES AND autonomous_system.organization:"Target Inc"
```

### Censys CLI
```bash
pip install censys --break-system-packages
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"

# Search hosts
censys search "autonomous_system.organization:\"Target Inc\"" \
  --index-type hosts \
  --fields ip,services.port,services.service_name \
  | tee censys_results.txt

# Enumerate certs
censys search "parsed.names:\"target.com\"" \
  --index-type certificates \
  --fields parsed.names,parsed.subject_dn,parsed.issuer \
  | tee censys_certs.txt
```

---

## Step 5 — Combine and Deduplicate IPs

```bash
# Extract IPs from all sources
grep -oP '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' shodan_results.txt \
  | sort -u > ips_shodan.txt

grep -oP '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' censys_results.txt \
  | sort -u > ips_censys.txt

# Merge with httpx results
grep -oP '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' httpx_raw.txt \
  | sort -u > ips_httpx.txt

# Find IPs in Shodan/Censys NOT in httpx (potential missed assets)
comm -23 <(sort ips_shodan.txt) <(sort ips_httpx.txt) > ips_new_discovery.txt
echo "New IPs not in original scope: $(wc -l < ips_new_discovery.txt)"

# Add http/https prefix and probe
sed 's/^/https:\/\//' ips_new_discovery.txt > new_targets.txt
sed 's/^/http:\/\//' ips_new_discovery.txt >> new_targets.txt
cat new_targets.txt | httpx -silent -status-code -title -o new_targets_httpx.txt
```

---

## Step 6 — Triage Shodan Findings

```bash
# Flag critical exposures
grep -iE "redis|mongodb|elasticsearch|kibana|grafana|jenkins|phpmyadmin|admin|login|dashboard" \
  shodan_results.txt > shodan_critical.txt

# Check for default ports that shouldn't be public
awk -F'\t' '$2 ~ /^(27017|6379|9200|5432|3306|2375|2376|5900|6443|10250)$/' \
  shodan_results.txt > shodan_exposed_services.txt

echo "Critical exposures: $(wc -l < shodan_critical.txt)"
echo "Exposed internal services: $(wc -l < shodan_exposed_services.txt)"
```

---

## Output

```
TARGET        : Target Inc / target.com / AS12345
─────────────────────────────────────────────────────
SHODAN RESULTS : 847 IPs found in org
NEW DISCOVERY  : 34 IPs not in original httpx results

CRITICAL FINDINGS:
  [CRITICAL] 1.2.3.45:9200 — Elasticsearch exposed, no auth, 2.3M records
  [CRITICAL] 1.2.3.67:6379 — Redis exposed, no auth, no password
  [HIGH]     1.2.3.89:8080 — Jenkins (v2.319) — check CVE-2024-23897
  [HIGH]     1.2.3.101:3000 — Grafana login page — check CVE-2021-43798
  [MEDIUM]   1.2.3.200:22 — SSH exposed on non-standard server
  [MEDIUM]   1.2.3.211:3389 — RDP exposed to internet

CERT-BASED DISCOVERY:
  12 additional subdomains found via SSL cert CN fields
  (not in DNS, found via Censys cert search)
─────────────────────────────────────────────────────
NEXT STEPS:
  1. Test Elasticsearch at 1.2.3.45 — no auth = data exposure
  2. Test Redis at 1.2.3.67 — unauthenticated write = possible RCE
  3. Probe new IPs via httpx → feed to httpx_triage framework
  4. Test Grafana CVE-2021-43798 → load 04_automation/nuclei_template_selector.md
```
