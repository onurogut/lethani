# Playbook: JavaScript Endpoint Extractor

## Purpose
Mine JavaScript files for hidden API endpoints, secrets, hardcoded credentials,
internal URLs, and sensitive configuration.
Input: domain, URL list, or raw JS file paths.

---

## Step 1 — Collect JavaScript Files

```bash
# From a live target — spider and collect JS URLs
katana -u https://TARGET -jc -d 5 -silent \
  | grep "\.js$" | sort -u > js_urls.txt

# From wayback
gau TARGET | grep "\.js$" | sort -u >> js_urls.txt
sort -u js_urls.txt -o js_urls.txt

# From httpx output — pull JS from known live hosts
cat httpx_raw.txt | grep -oP 'https?://[^\s]+' \
  | httpx -silent -mc 200 -path "/static/js/main.js,/app.js,/bundle.js" >> js_urls.txt

echo "Total JS files: $(wc -l < js_urls.txt)"
```

---

## Step 2 — Download All JS Files

```bash
mkdir -p js_files
while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -sk "$url" -o "js_files/$filename"
  echo "$url → js_files/$filename"
done < js_urls.txt > js_map.txt
```

---

## Step 3 — Extract Endpoints

```bash
# Using getJS + LinkFinder
getJS --input js_urls.txt --complete --output js_endpoints.txt
python3 LinkFinder.py -i js_urls.txt -d -o cli >> js_endpoints.txt

# Manual grep patterns for API endpoints
grep -rhoP "(\/api\/[a-zA-Z0-9_\-\/]+|\/v[0-9]+\/[a-zA-Z0-9_\-\/]+)" js_files/ \
  | sort -u > api_endpoints.txt

# GraphQL endpoints
grep -rhoP "(\/graphql[a-zA-Z0-9_\-\/]*)" js_files/ | sort -u >> api_endpoints.txt

# Absolute URLs pointing to internal/other domains
grep -rhoP "https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}[^\s\"'<>]+" js_files/ \
  | grep -v "cdn\|static\|fonts\|analytics\|google\|facebook" \
  | sort -u > internal_urls.txt

echo "Endpoints found: $(wc -l < api_endpoints.txt)"
```

---

## Step 4 — Secret & Credential Detection

```bash
# Using trufflehog (most comprehensive)
trufflehog filesystem ./js_files/ --json 2>/dev/null > secrets_trufflehog.json

# Using gitleaks
gitleaks detect --source ./js_files/ --report-path secrets_gitleaks.json --no-git

# Manual grep patterns (high signal)
grep -rhoiP \
  "(api[_-]?key|apikey|api[_-]?secret|access[_-]?key|secret[_-]?key|\
    aws[_-]?access|aws[_-]?secret|client[_-]?secret|client[_-]?id|\
    authorization|bearer\s+[a-zA-Z0-9._-]+|token\s*[:=]\s*['\"][a-zA-Z0-9._-]+['\"]|\
    password\s*[:=]\s*['\"][^'\"]+['\"]|passwd|private[_-]?key|\
    stripe[_-]?key|twilio|sendgrid|mailgun|firebase|algolia)[^'\"<>]{0,100}" \
  js_files/ | sort -u > secrets_manual.txt
```

---

## Step 5 — Hardcoded Infrastructure Signals

```bash
# Internal hostnames and IPs
grep -rhoP "\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b" \
  js_files/ | sort -u > internal_ips.txt

# Dev/staging URLs hardcoded in prod JS
grep -rhoiP "https?://(dev|stg|staging|test|qa|uat|internal|corp)\.[a-zA-Z0-9._-]+" \
  js_files/ | sort -u > dev_urls.txt

# S3 buckets
grep -rhoiP "([a-z0-9_-]+\.s3\.amazonaws\.com|s3\.amazonaws\.com\/[a-z0-9_-]+)" \
  js_files/ | sort -u > s3_buckets.txt

# Firebase URLs
grep -rhoiP "[a-z0-9_-]+-default-rtdb\.firebaseio\.com" \
  js_files/ | sort -u > firebase_urls.txt

# Version strings (for CVE matching)
grep -rhoiP "(\"version\"\s*:\s*\"[0-9.]+\"|v[0-9]+\.[0-9]+\.[0-9]+)" \
  js_files/ | sort -u > versions.txt
```

---

## Step 6 — Prioritize & Verify Endpoints

```bash
# Probe found endpoints against live target
sed 's|^|https://TARGET|' api_endpoints.txt \
  | httpx -silent -status-code -title -mc 200,301,302,401,403,405 \
  -o live_endpoints.txt

# Sort by interesting status codes
grep -E "\[401\]|\[403\]|\[405\]" live_endpoints.txt > auth_required.txt
grep "\[200\]" live_endpoints.txt > open_endpoints.txt
```

---

## Step 7 — Source Map Extraction (bonus)

If `.js.map` files are exposed, you can recover original source:

```bash
# Check for source maps
while read url; do
  mapurl="${url}.map"
  status=$(curl -sk -o /dev/null -w "%{http_code}" "$mapurl")
  [ "$status" = "200" ] && echo "[SOURCE MAP EXPOSED] $mapurl"
done < js_urls.txt

# Download and extract with sourcemapper
sourcemapper -url TARGET -output ./sourcemap_output/
```

---

## Output

```
ASSET         : https://target.com/static/js/app.js
ENDPOINTS     : 47 API paths found
SECRETS       : 2 potential keys (see secrets_manual.txt)
INTERNAL URLs : dev.target-internal.com, 10.0.0.5
S3 BUCKETS    : target-prod-uploads.s3.amazonaws.com
DEV URLS      : https://staging.target.com/api/v2
SOURCE MAPS   : EXPOSED at /static/js/app.js.map
NEXT STEPS    : Probe live_endpoints.txt, verify S3 access, test dev URLs
```

---

## Tools Reference

```bash
go install github.com/003random/getJS@latest
pip install linkfinder
go install github.com/trufflesecurity/trufflehog/v3@latest
brew install gitleaks
go install github.com/hakluke/hakrawler@latest
pip install sourcemapper
```
