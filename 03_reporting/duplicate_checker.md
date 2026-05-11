# Playbook: Duplicate Check

## Purpose
Before submitting any report, verify it isn't a known/public finding.
Saves time, protects reputation, and prevents N/A marks on your profile.
Input: finding type + target domain.

---

## Step 1 — HackerOne Public Disclosures

```bash
TARGET="target.com"
VULN_TYPE="idor"  # e.g. ssrf, xss, sqli, rce, takeover, idor

# Search HackerOne disclosed reports
QUERY="${TARGET} ${VULN_TYPE}"

# Manual search URLs:
echo "https://hackerone.com/hacktivity?querystring=${TARGET// /+}+${VULN_TYPE// /+}"

# Via API (if you have HackerOne API token)
curl -s "https://api.hackerone.com/v1/hackers/hacktivity?\
  filter[disclosed]=true&\
  filter[text_query]=${TARGET}+${VULN_TYPE}" \
  -u "USERNAME:API_TOKEN" | python3 -m json.tool
```

---

## Step 2 — Search Platforms Manually

Open each URL and search for your target + vuln type:

```
HackerOne Hacktivity   : https://hackerone.com/hacktivity
Bugcrowd Crowdstream   : https://bugcrowd.com/crowdstream
Intigriti Disclosures  : https://app.intigriti.com/research/submissions (public)
OpenBugBounty          : https://www.openbugbounty.org/search/
Vulnhub/CVE            : https://nvd.nist.gov/vuln/search
```

---

## Step 3 — Search on Twitter/X and GitHub

```bash
# Finding may have been tweeted or POC posted
QUERIES=(
  "site:twitter.com \"${TARGET}\" \"${VULN_TYPE}\""
  "site:github.com \"${TARGET}\" \"${VULN_TYPE}\""
  "\"${TARGET}\" bug bounty ${VULN_TYPE}"
  "\"${TARGET}\" hackerone ${VULN_TYPE}"
)

for q in "${QUERIES[@]}"; do
  echo "Search: https://www.google.com/search?q=$(echo $q | python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))')"
done
```

---

## Step 4 — Check CVE / NVD for Third-Party Software

If the finding involves a known third-party software:

```bash
SOFTWARE="Confluence"
VERSION="7.13.0"

# NVD search
echo "https://nvd.nist.gov/vuln/search/results?query=${SOFTWARE}+${VERSION}"

# Shodan CVE check (if you have Shodan)
shodan search "product:\"${SOFTWARE}\" version:\"${VERSION}\"" --fields ip_str,port,org

# Nuclei CVE template check
ls ~/nuclei-templates/http/cves/ | grep -i "${SOFTWARE,,}"

# Mitre CVE
echo "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=${SOFTWARE}"
```

---

## Step 5 — Check the Program's Own Disclosed/Fixed List

Most programs maintain a Hall of Fame or Changelog:

```bash
# Common locations
URLS=(
  "https://${TARGET}/security"
  "https://${TARGET}/security.txt"
  "https://${TARGET}/.well-known/security.txt"
  "https://${TARGET}/bug-bounty"
  "https://${TARGET}/responsible-disclosure"
  "https://${TARGET}/changelog"
)

for url in "${URLS[@]}"; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "$url")
  [ "$status" = "200" ] && echo "[FOUND] $url"
done
```

---

## Step 6 — Determine Uniqueness

After research, classify your finding:

```
UNIQUE      → No matching public report found. Proceed with submission.

SIMILAR     → Public report exists but:
              - Different endpoint / parameter
              - Different bypass technique
              - Different scope (subdomain)
              - Fixed version re-introduced (regression)
              → Proceed with clear differentiation noted in report

POTENTIAL   → Very similar report exists but details unclear (private)
DUPLICATE   → Check if fixed:
              - Test if the original finding is still reproducible
              - If still working → submit as "regression" or "unfixed duplicate"
              - If fixed → note as reference in your own distinct finding

KNOWN CVE   → Your finding triggers a known CVE:
              - Still report if target is unpatched
              - Reference CVE ID in your report
              - Nuclei template likely already exists — mention it
```

---

## Output

```
FINDING       : IDOR on /api/v2/orders/{id}
TARGET        : target.com
─────────────────────────────────────────────────
DUPLICATE CHECK RESULTS:

HackerOne     : 1 similar report found
  https://hackerone.com/reports/XXXXXX
  - Same endpoint but different parameter (/api/v1/ not v2/)
  - Status: Resolved (2022)

Bugcrowd      : No matches
GitHub        : No public PoC found
CVE           : Not applicable (custom code)
Program page  : No mention in security changelog

CONCLUSION    : LIKELY UNIQUE — prior report was on v1 API (now deprecated).
                Current finding is on v2 which was introduced after the fix.
                Note prior report as context in submission.

ACTION        : Proceed with report. Reference H1 XXXXXX as context.
                Make clear this is v2 endpoint (different code path).
```
