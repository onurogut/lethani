# Playbook: Subdomain Takeover Detection

## Purpose
Identify dangling DNS records and CNAME chains pointing to unclaimed third-party services.
Input: domain name, subdomain list, or httpx output.

---

## Step 1 — Gather CNAMEs

```bash
# For each subdomain, resolve CNAME chain
while read sub; do
  cname=$(dig +short CNAME "$sub" | tr -d '.')
  [ -n "$cname" ] && echo "$sub → $cname"
done < hosts.txt > cnames.txt

# Alternative with dnsx
dnsx -l hosts.txt -cname -silent -o cnames_dnsx.txt
```

---

## Step 2 — Check for Dangling CNAMEs

A CNAME is dangling when:
- It resolves to a CNAME target that returns NXDOMAIN
- The CNAME target belongs to a service that allows claiming

```bash
# Find NXDOMAIN on CNAME targets
while read line; do
  target=$(echo "$line" | awk '{print $NF}')
  result=$(dig +short A "$target")
  [ -z "$result" ] && echo "[DANGLING] $line"
done < cnames.txt
```

---

## Step 3 — Match Against Vulnerable Service Fingerprints

For each dangling CNAME, match the target domain against this list:

| Service | CNAME pattern | Takeover method |
|---|---|---|
| GitHub Pages | `*.github.io` | Create repo matching subdomain |
| Heroku | `*.herokudns.com`, `*.herokuapp.com` | Claim app name |
| Fastly | `*.fastly.net` | Create Fastly service |
| Pantheon | `*.pantheonsite.io` | Claim via dashboard |
| Shopify | `*.myshopify.com` | Claim shop name |
| Tumblr | `*.domains.tumblr.com` | Claim blog |
| Ghost | `*.ghost.io` | Claim org name |
| Readme.io | `*.readme.io` | Claim project |
| Surge.sh | `*.surge.sh` | Run `surge` and claim domain |
| Cargo | `*.cargocollective.com` | Claim account |
| StatusPage | `*.statuspage.io` | Claim page |
| Helpjuice | `*.helpjuice.com` | Contact support |
| HelpScout | `*.helpscoutdocs.com` | Claim site |
| Bitbucket | `*.bitbucket.io` | Create matching repo |
| Webflow | `*.webflow.io` | Claim project |
| Azure | `*.azurewebsites.net`, `*.cloudapp.net`, `*.trafficmanager.net` | Claim resource |
| AWS S3 | `*.s3.amazonaws.com`, `*.s3-website-*.amazonaws.com` | Create bucket |
| AWS Elastic Beanstalk | `*.elasticbeanstalk.com` | Claim app |
| Zendesk | `*.zendesk.com` | Create account |
| Intercom | `*.custom.intercom.help` | Claim workspace |
| Desk.com | `*.desk.com` | Claim account |
| Tilda | `*.tilda.ws` | Claim project |
| JetBrains | `*.myjetbrains.com` | Claim instance |
| Wordpress.com | `*.wordpress.com` | Claim blog |
| Netlify | `*.netlify.app` | Claim site name |
| Vercel | `*.vercel.app` | Claim project |

---

## Step 4 — HTTP Fingerprint Confirmation

Even if DNS resolves, check for service-specific "unclaimed" error pages:

```bash
# Fetch and grep for takeover confirmation strings
curl -sk "https://TARGET" | grep -iE \
  "there is no app here|no such app|repository not found|project not found|\
   isn't here|unavailable|doesn't exist|not found|no longer available|\
   fastly error|heroku \| no such app|github.*404|this site.*not configured"
```

Confirm with: `subjack`, `nuclei -t takeovers/`, or `subzy`

```bash
subjack -w hosts.txt -t 100 -timeout 30 -o takeover_results.txt -ssl
nuclei -l hosts.txt -t ~/nuclei-templates/http/takeovers/ -o takeover_nuclei.txt
```

---

## Step 5 — A Record + IP Checks

Some takeovers aren't CNAME-based — check A records pointing to released IPs:

```bash
# Extract IPs from httpx output
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' httpx_raw.txt | sort -u > ips.txt

# Cross-reference with cloud IP ranges (AWS, Azure, GCP)
# Download range files:
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json -o aws_ranges.json
curl -s https://www.gstatic.com/ipranges/cloud.json -o gcp_ranges.json
```

---

## Step 6 — Wildcard DNS Detection

Before reporting, check if the domain has wildcard DNS (would invalidate findings):

```bash
dig +short A "nonexistent-$(date +%s).TARGET.com"
# If this returns an IP → wildcard DNS → all subdomains resolve → not a real takeover
```

---

## Output

For each confirmed takeover candidate:

```
ASSET    : sub.target.com
CNAME    : sub.target.com → service.github.io
STATUS   : DANGLING (NXDOMAIN on target)
SERVICE  : GitHub Pages
CONFIRM  : HTTP response contains "There isn't a GitHub Pages site here"
SEVERITY : HIGH
ACTION   : Create github.com/[org]/[matching-repo-name] with index.html
EVIDENCE : [paste dig output + curl response snippet]
```

---

## Tools Reference

```bash
# Install
go install github.com/haccer/subjack@latest
go install github.com/LukaSikic/subzy@latest
nuclei -update-templates
```
