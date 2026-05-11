# Playbook: Nuclei Template Selector

## Purpose
Select and run the right Nuclei templates based on asset type, technology stack,
and httpx findings. Avoid noisy full-template runs — be surgical.
Input: httpx output or asset list with technology tags.

---

## Step 1 — Update Templates

```bash
nuclei -update-templates
nuclei -update
echo "Template count: $(ls ~/nuclei-templates/**/*.yaml 2>/dev/null | wc -l)"
```

---

## Step 2 — Map Asset Type to Template Categories

Based on httpx tech-detect output, select template categories:

```bash
# Read your httpx output
cat httpx_raw.txt | head -20
```

### By Technology Detected

| Technology | Template paths to run |
|---|---|
| WordPress | `technologies/wordpress/` `cves/` (filter WordPress CVEs) |
| Drupal | `technologies/drupal/` `cves/` |
| Joomla | `technologies/joomla/` |
| Apache Tomcat | `cves/2020/CVE-2020-1938.yaml` (Ghostcat) `misconfiguration/tomcat/` |
| Apache (generic) | `misconfiguration/apache/` `cves/` (Apache filter) |
| IIS | `misconfiguration/iis/` `fuzzing/iis-shortname.yaml` |
| Nginx | `misconfiguration/nginx/` |
| Spring Boot | `cves/` (Spring filter) `exposures/configs/spring-boot-actuator.yaml` |
| Jenkins | `technologies/jenkins/` `cves/` (Jenkins filter) |
| Jira | `cves/` (Jira filter) `technologies/atlassian/` |
| Confluence | `cves/` (Confluence filter) |
| GitLab | `technologies/gitlab/` `cves/` (GitLab filter) |
| Elasticsearch | `exposures/` `misconfiguration/elastic/` |
| Kubernetes | `misconfiguration/kubernetes/` |
| PHP | `fuzzing/` `exposures/files/` |
| Node.js | `fuzzing/` |
| Laravel | `exposures/configs/laravel-env.yaml` `cves/` (Laravel) |
| Grafana | `cves/2021/CVE-2021-43798.yaml` (path traversal) |
| Citrix | `cves/` (Citrix filter) |
| F5 BIG-IP | `cves/2022/CVE-2022-1388.yaml` |
| Fortinet | `cves/` (Fortinet filter) |
| Exchange | `cves/2021/CVE-2021-26855.yaml` (ProxyLogon) and related |
| SharePoint | `cves/` (SharePoint filter) |
| Keycloak | `cves/` (Keycloak filter) |
| MinIO | `cves/` (MinIO filter) `misconfiguration/` |

---

## Step 3 — Template Run Commands

### Run by technology (targeted)
```bash
# WordPress
nuclei -l hosts.txt \
  -t ~/nuclei-templates/technologies/wordpress/ \
  -t ~/nuclei-templates/cves/ \
  -tags wordpress \
  -severity medium,high,critical \
  -o nuclei_wordpress.txt

# IIS shortname scan
nuclei -l hosts.txt \
  -t ~/nuclei-templates/fuzzing/iis-shortname.yaml \
  -o nuclei_iis_shortname.txt

# Spring Boot Actuator exposure
nuclei -l hosts.txt \
  -t ~/nuclei-templates/exposures/configs/spring-boot-actuator.yaml \
  -o nuclei_spring.txt

# Exposed credentials / config files
nuclei -l hosts.txt \
  -t ~/nuclei-templates/exposures/ \
  -severity medium,high,critical \
  -o nuclei_exposures.txt

# All CVEs (filtered by severity)
nuclei -l hosts.txt \
  -t ~/nuclei-templates/cves/ \
  -severity critical,high \
  -o nuclei_cves_critical.txt

# Takeovers
nuclei -l hosts.txt \
  -t ~/nuclei-templates/http/takeovers/ \
  -o nuclei_takeovers.txt

# Misconfigurations
nuclei -l hosts.txt \
  -t ~/nuclei-templates/misconfiguration/ \
  -severity medium,high,critical \
  -o nuclei_misconfig.txt

# Default credentials
nuclei -l hosts.txt \
  -t ~/nuclei-templates/default-logins/ \
  -o nuclei_default_creds.txt

# Directory listing
nuclei -l hosts.txt \
  -t ~/nuclei-templates/exposures/configs/ \
  -tags listing \
  -o nuclei_listing.txt
```

### Full targeted run (based on httpx tech-detect output)
```bash
# Extract all detected technologies from httpx output
TECHS=$(grep -oP '\[([^\]]+)\]' httpx_raw.txt \
  | tr -d '[]' | tr ',' '\n' | sort -u | tr '[:upper:]' '[:lower:]')

echo "Detected technologies:"
echo "$TECHS"

# Build nuclei tag list
TAGS=$(echo "$TECHS" | tr '\n' ',' | sed 's/,$//')

# Run with matching tags
nuclei -l hosts.txt \
  -tags "$TAGS" \
  -severity medium,high,critical \
  -o nuclei_tech_targeted.txt
```

---

## Step 4 — Specific High-Value CVE Templates

Always run these against any target regardless of tech:

```bash
# Run specific high-impact CVEs
HIGH_VALUE_CVES=(
  "cves/2021/CVE-2021-26855.yaml"    # Exchange ProxyLogon
  "cves/2021/CVE-2021-34473.yaml"    # Exchange ProxyShell
  "cves/2021/CVE-2021-43798.yaml"    # Grafana path traversal
  "cves/2022/CVE-2022-1388.yaml"     # F5 BIG-IP auth bypass
  "cves/2021/CVE-2021-41773.yaml"    # Apache path traversal
  "cves/2021/CVE-2021-42013.yaml"    # Apache path traversal 2
  "cves/2021/CVE-2021-26084.yaml"    # Confluence OGNL RCE
  "cves/2022/CVE-2022-26134.yaml"    # Confluence RCE
  "cves/2021/CVE-2021-3129.yaml"     # Laravel debug RCE
  "cves/2022/CVE-2022-0540.yaml"     # Jira auth bypass
  "cves/2019/CVE-2019-11581.yaml"    # Jira SSTI
  "cves/2021/CVE-2021-40539.yaml"    # ManageEngine RCE
  "cves/2020/CVE-2020-1938.yaml"     # Tomcat Ghostcat
  "cves/2021/CVE-2021-25646.yaml"    # Druid RCE
)

for cve in "${HIGH_VALUE_CVES[@]}"; do
  nuclei -l hosts.txt \
    -t ~/nuclei-templates/$cve \
    -o "nuclei_$(basename $cve .yaml).txt" 2>/dev/null
done
```

---

## Step 5 — Output Triage

```bash
# Merge all nuclei results
cat nuclei_*.txt 2>/dev/null | sort -u > nuclei_all.txt

# Filter critical and high only
grep -E "\[critical\]|\[high\]" nuclei_all.txt > nuclei_priority.txt

# Extract finding types
grep -oP '\[([^\]]+)\]\s*\[([^\]]+)\]' nuclei_all.txt | sort | uniq -c | sort -rn

echo "Total findings: $(wc -l < nuclei_all.txt)"
echo "Critical/High: $(wc -l < nuclei_priority.txt)"
```

---

## Step 6 — False Positive Reduction

```bash
# For each finding, manually verify before reporting
# Common FPs to check:
# - CVE templates that fire on version number in header only (not actual vuln)
# - Takeover templates that fire on shared hosting responses
# - Default-login templates (try the credentials manually)

# Re-run specific finding to confirm
nuclei -u "https://specific-target.com" \
  -t ~/nuclei-templates/cves/2021/CVE-2021-43798.yaml \
  -debug 2>&1 | grep -E "matched|request|response"
```

---

## Output

```
TARGET        : 147 hosts from httpx
TECHNOLOGIES  : WordPress, IIS, Tomcat, Spring Boot, Jira
─────────────────────────────────────────────────────
TEMPLATES RUN :
  wordpress/      → 24 templates
  iis/            → 8 templates
  tomcat/         → 12 templates
  spring/         → 6 templates
  cves/ (targeted)→ 31 templates
  exposures/      → 15 templates
  takeovers/      → 1 template
─────────────────────────────────────────────────────
FINDINGS:
  [CRITICAL] CVE-2022-26134 — Confluence RCE on conf.target.com
  [HIGH]     Tomcat Ghostcat on tomcat.target.com:8009
  [HIGH]     Spring Boot /actuator/env exposed on api.target.com
  [MEDIUM]   WordPress xmlrpc.php bruteforce enabled on blog.target.com
  [MEDIUM]   IIS shortname disclosure on www.target.com
─────────────────────────────────────────────────────
NEXT STEPS:
  1. Manually verify CRITICAL finding → report immediately
  2. Test Ghostcat with PoC → load 02_vuln_testing for manual testing
  3. Check /actuator/env for credentials → manual testing
```
