# Playbook: CVE-to-Target Matcher

## Purpose
Cross-reference tech-detect output from httpx against known CVEs
to find unpatched vulnerable software on in-scope targets.
Input: httpx output with -tech-detect, or manual technology list.

---

## Step 1 — Extract Technology + Version from httpx

```bash
# Parse technologies from httpx output
grep -oP '\[([^\]]+)\]' httpx_raw.txt \
  | tr -d '[]' \
  | tr ',' '\n' \
  | sort -u \
  | grep -v "^$" > tech_detected.txt

# Also extract version numbers from Server headers
grep -oP '(Server|X-Powered-By): [^\r\n]+' httpx_raw.txt \
  | sort -u > server_headers.txt

# Combine and show
echo "=== Detected Technologies ==="
cat tech_detected.txt

echo "=== Server Headers ==="
cat server_headers.txt
```

---

## Step 2 — Lookup CVEs by Technology

For each technology found, query NVD:

```bash
# Automated CVE lookup via NVD API (no key required for basic queries)
while read tech; do
  clean=$(echo "$tech" | sed 's/[:\/].*//') # strip version
  echo "=== $tech ==="
  curl -sk "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${clean}&resultsPerPage=5" \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
vulns = data.get('vulnerabilities', [])
for v in vulns:
    cve = v['cve']
    cvss = cve.get('metrics',{}).get('cvssMetricV31',[{}])[0].get('cvssData',{})
    score = cvss.get('baseScore','N/A')
    severity = cvss.get('baseSeverity','N/A')
    desc = cve.get('descriptions',[{}])[0].get('value','')[:100]
    print(f\"  [{cve['id']}] CVSS:{score} ({severity}) — {desc}\")
" 2>/dev/null
  sleep 0.5  # rate limit
done < tech_detected.txt
```

---

## Step 3 — High-Priority CVE Checklist by Software

Use this table to immediately check the most critical CVEs for detected software.
Mark each with: PATCHED / VULNERABLE / UNTESTED

### Atlassian
```
[ ] CVE-2022-26134  Confluence OGNL RCE (CVSS 9.8)    — unauthenticated
[ ] CVE-2021-26084  Confluence OGNL RCE (CVSS 9.8)    — unauthenticated
[ ] CVE-2023-22515  Confluence broken access control   — creates admin
[ ] CVE-2023-22518  Confluence improper authorization  — data destruction
[ ] CVE-2022-0540   Jira auth bypass (CVSS 9.8)        — unauthenticated
[ ] CVE-2019-11581  Jira SSTI RCE                      — admin required
[ ] CVE-2021-26085  Jira SSRF                          — unauthenticated
```

### Microsoft Exchange
```
[ ] CVE-2021-26855  ProxyLogon SSRF                    — pre-auth RCE chain
[ ] CVE-2021-26857  ProxyLogon insecure deserialization
[ ] CVE-2021-34473  ProxyShell remote code execution
[ ] CVE-2021-34523  ProxyShell elevation of privilege
[ ] CVE-2021-31207  ProxyShell security feature bypass
[ ] CVE-2022-41082  ProxyNotShell RCE
[ ] CVE-2023-21529  Exchange memory corruption RCE
```

### Apache
```
[ ] CVE-2021-41773  Apache 2.4.49 path traversal/RCE
[ ] CVE-2021-42013  Apache 2.4.50 path traversal bypass
[ ] CVE-2017-7679   Apache mod_mime buffer overflow
[ ] CVE-2017-9798   Apache Optionsbleed
```

### Apache Tomcat
```
[ ] CVE-2020-1938   Ghostcat — AJP file read/include (CVSS 9.8)
[ ] CVE-2019-0232   Tomcat CGI enableCmdLineArguments RCE
[ ] CVE-2017-12617  Tomcat PUT method JSP upload
[ ] CVE-2021-25329  Tomcat partial PUT RCE
```

### GitLab
```
[ ] CVE-2021-22205  GitLab RCE via image upload (CVSS 10.0) — pre-auth
[ ] CVE-2022-2992   GitLab RCE via CI/CD
[ ] CVE-2021-4191   GitLab user enumeration
[ ] CVE-2023-2825   GitLab path traversal
```

### Jenkins
```
[ ] CVE-2018-1000861 Jenkins RCE via Groovy sandbox bypass
[ ] CVE-2019-1003000 Jenkins script security bypass
[ ] CVE-2016-0792   Jenkins XXE / unauthenticated access
[ ] CVE-2024-23897  Jenkins arbitrary file read (CVSS 9.8) — pre-auth
```

### Spring / Spring Boot
```
[ ] CVE-2022-22965  Spring4Shell RCE (CVSS 9.8)
[ ] CVE-2022-22963  Spring Cloud Function SpEL injection RCE
[ ] CVE-2021-22053  Spring Boot H2 console RCE
[ ] Actuator exposure: /actuator/env, /actuator/heapdump, /actuator/trace
```

### Grafana
```
[ ] CVE-2021-43798  Grafana path traversal (CVSS 7.5) — pre-auth file read
[ ] CVE-2021-43813  Grafana path traversal (markdown)
[ ] CVE-2022-31097  Grafana stored XSS
```

### F5 BIG-IP
```
[ ] CVE-2022-1388   iControl REST auth bypass (CVSS 9.8) — pre-auth RCE
[ ] CVE-2021-22986  iControl REST RCE — unauthenticated
[ ] CVE-2020-5902   TMUI RCE — unauthenticated (CVSS 10.0)
```

### Citrix
```
[ ] CVE-2019-19781  Citrix ADC path traversal / RCE
[ ] CVE-2023-3519   Citrix ADC RCE (CVSS 9.8) — unauthenticated
[ ] CVE-2023-4966   Citrix Bleed session token leak
```

### WordPress
```
[ ] Check version: curl -sk https://TARGET/wp-login.php | grep "ver="
[ ] CVE-2019-9978   Social Warfare XSS/RCE
[ ] CVE-2020-25213  File Manager plugin RCE
[ ] Run: wpscan --url TARGET --enumerate vp,vt --api-token YOUR_TOKEN
```

### Kubernetes
```
[ ] CVE-2018-1002105 Privilege escalation (CVSS 9.8)
[ ] CVE-2019-11247   API server path traversal
[ ] Unauthenticated dashboard: https://TARGET/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/
```

### Fortinet
```
[ ] CVE-2018-13379  FortiOS SSL VPN path traversal (CVSS 9.8) — pre-auth
[ ] CVE-2022-40684  FortiOS auth bypass (CVSS 9.8)
[ ] CVE-2023-27997  FortiOS heap overflow RCE — pre-auth
```

---

## Step 4 — Version-Specific Check

```bash
# Extract version from response headers and match against CVE
TARGET_URL="https://vulnerable-target.com"

# Get version from headers
VERSION=$(curl -sI "$TARGET_URL" | grep -oP '(?<=Server: )[^\r\n]+')
echo "Detected: $VERSION"

# For Confluence — check version
curl -sk "https://confluence.target.com/login.action" \
  | grep -oP 'Confluence [0-9.]+'

# For Jira — check version
curl -sk "https://jira.target.com/login.jsp" \
  | grep -oP 'Jira [0-9.]+'

# For Jenkins
curl -sk "https://jenkins.target.com" | grep -i "jenkins"
curl -sI "https://jenkins.target.com" | grep -i "x-jenkins"

# For Grafana
curl -sk "https://grafana.target.com/api/health" | python3 -m json.tool
```

---

## Step 5 — Match to Nuclei Templates and Test

For each confirmed vulnerable software version:

```bash
# Load 04_automation/nuclei_template_selector.md for next steps
# Run targeted CVE template:

CVE_ID="CVE-2021-43798"  # Grafana path traversal
nuclei -u "https://grafana.target.com" \
  -t ~/nuclei-templates/cves/2021/${CVE_ID}.yaml \
  -debug

# Manual PoC test (Grafana path traversal example):
curl -sk "https://grafana.target.com/public/plugins/alertlist/../../../../../../../etc/passwd"
```

---

## Output

```
TARGET        : 89 unique technologies detected across 147 hosts
─────────────────────────────────────────────────────
MATCHES FOUND:
  [CRITICAL] Confluence 7.13.0 on conf.target.com
             CVE-2022-26134 (CVSS 9.8) — unauthenticated RCE
             Nuclei template: cves/2022/CVE-2022-26134.yaml
             Status: UNTESTED → run Nuclei template now

  [HIGH]     Grafana 8.2.3 on grafana.target.com
             CVE-2021-43798 (CVSS 7.5) — unauthenticated path traversal
             Status: UNTESTED → test manually + Nuclei

  [HIGH]     Jenkins on jenkins.target.com (no version)
             CVE-2024-23897 — arbitrary file read
             Status: UNTESTED

  [INFO]     WordPress on blog.target.com (version unknown)
             Run wpscan for plugin/theme CVEs
─────────────────────────────────────────────────────
NEXT STEPS:
  1. Run Nuclei CVE templates → load 04_automation/nuclei_template_selector.md
  2. Test Confluence RCE manually → report if confirmed
  3. Run wpscan on blog.target.com
```
