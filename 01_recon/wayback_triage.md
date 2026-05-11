# Playbook: Wayback / Historical URL Triage

## Purpose
Collect historical URLs from passive sources and categorize them into
high-value targets: admin paths, backup files, exposed configs, old APIs,
leaked params, and deprecated endpoints.
Input: domain name or raw gau/wayback output.

---

## Step 1 — Collect Historical URLs

```bash
# gau (preferred — multi-source)
gau TARGET --subs --blacklist png,jpg,gif,ico,svg,woff,woff2,ttf,css \
  | sort -u > wayback_raw.txt

# waybackurls
waybackurls TARGET | sort -u >> wayback_raw.txt

# katana (live crawl for comparison)
katana -u https://TARGET -d 5 -silent -o katana_live.txt

# merge all
cat wayback_raw.txt katana_live.txt | sort -u > urls_all.txt
echo "Total URLs: $(wc -l < urls_all.txt)"
```

---

## Step 2 — Deduplicate & Normalize

```bash
# Remove noisy extensions
cat urls_all.txt | grep -vE "\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|css|pdf|zip|tar|gz)(\?|$)" \
  > urls_filtered.txt

# Deduplicate by path (strip query strings for path-level dedup)
cat urls_filtered.txt | sed 's/?.*$//' | sort -u > paths_unique.txt

echo "Unique paths: $(wc -l < paths_unique.txt)"
```

---

## Step 3 — Categorize by Pattern

Run each grep block. Results go to separate files for targeted testing.

```bash
# --- ADMIN & MANAGEMENT ---
grep -iE "/(admin|administrator|manage|management|backend|backoffice|cpanel|dashboard|console|portal|superuser|staff|internal)" \
  urls_filtered.txt > cat_admin.txt

# --- API ENDPOINTS ---
grep -iE "/(api|v[0-9]+|graphql|gql|rest|rpc|grpc|swagger|openapi|webhook)" \
  urls_filtered.txt > cat_api.txt

# --- BACKUP & CONFIG FILES ---
grep -iE "\.(bak|backup|old|orig|copy|tmp|swp|sql|dump|db|sqlite|sqlite3|env|config|conf|cfg|ini|log|gz|tar|zip|7z|rar)(\?|$)" \
  urls_filtered.txt > cat_backup.txt

# --- AUTHENTICATION ---
grep -iE "/(login|signin|sign-in|logout|signout|register|signup|auth|oauth|sso|token|session|password|reset|forgot|2fa|mfa|otp)" \
  urls_filtered.txt > cat_auth.txt

# --- FILE UPLOAD ---
grep -iE "/(upload|uploads|file|files|media|attachment|import|export|download)" \
  urls_filtered.txt > cat_upload.txt

# --- DEBUG & DEV ARTIFACTS ---
grep -iE "/(debug|trace|test|dev|staging|phpinfo|info\.php|server-status|server-info|_profiler|telescope|horizon|clockwork|whoops|actuator|metrics|health|status)" \
  urls_filtered.txt > cat_debug.txt

# --- SENSITIVE PATHS ---
grep -iE "/(\.git|\.env|\.htaccess|\.htpasswd|web\.config|wp-config|config\.php|settings\.py|application\.properties|appsettings\.json|secrets|credentials|private)" \
  urls_filtered.txt > cat_sensitive.txt

# --- INTERESTING PARAMETERS ---
grep -iE "[?&](url|redirect|next|return|dest|destination|path|file|page|target|src|source|load|include|callback|continue|ref|redir|forward|open|uri|endpoint|host|proxy|fetch|request)" \
  urls_filtered.txt > cat_interesting_params.txt

# --- OLD/VERSIONED API PATHS ---
grep -iE "/v[0-9]+(\/|$)" urls_filtered.txt \
  | grep -v "$(grep -oP '/v[0-9]+' katana_live.txt | sort -u | tr '\n' '|' | sed 's/|$//')" \
  > cat_old_api.txt

echo "Categories:"
for f in cat_*.txt; do echo "  $f: $(wc -l < $f)"; done
```

---

## Step 4 — Probe Live Status

```bash
# Check which historical URLs are still alive
cat cat_admin.txt cat_debug.txt cat_sensitive.txt cat_backup.txt \
  | sort -u | httpx -silent -status-code -title -mc 200,301,302,401,403,500 \
  -o wayback_live.txt

# Separate by status
grep "\[200\]" wayback_live.txt > live_200.txt
grep -E "\[401\]|\[403\]" wayback_live.txt > live_auth.txt
grep "\[500\]" wayback_live.txt > live_500.txt
```

---

## Step 5 — Parameter Analysis

```bash
# Extract all unique parameters across all URLs
cat urls_filtered.txt \
  | grep "?" \
  | sed 's/.*?\(.*\)/\1/' \
  | tr '&' '\n' \
  | sed 's/=.*//' \
  | sort -u > all_params.txt

# High-value parameter names (SSRF, redirect, LFI candidates)
grep -iE "^(url|uri|redirect|next|dest|path|file|page|src|include|callback|host|proxy|endpoint|target|return|open|load|fetch|resource|template|view|route|dir|folder|document|ref|site|domain|feed|to|from|out|window|data|config|setting)" \
  all_params.txt > high_value_params.txt

echo "Unique params: $(wc -l < all_params.txt)"
echo "High-value params: $(wc -l < high_value_params.txt)"
```

---

## Step 6 — Diff Against Live Site

Endpoints that existed historically but are now 404 may still be accessible
via path manipulation, backup paths, or cache:

```bash
# Paths in wayback but not in katana live crawl
comm -23 <(sort paths_unique.txt) <(sort katana_live.txt | sed 's/?.*$//') \
  > wayback_only.txt

# These are "ghost" paths — probe them
cat wayback_only.txt | httpx -silent -status-code -mc 200,301,302,401,403 \
  -o ghost_paths_live.txt
```

---

## Output

```
TARGET         : target.com
TOTAL URLs     : 12,843
AFTER FILTER   : 4,291
─────────────────────────────────────────
CATEGORY       COUNT   LIVE (non-404)
Admin paths  :   143     12
API endpoints:   892     67
Backup files :    34      3  ← INVESTIGATE
Auth paths   :    78     24
Debug paths  :    56      8  ← INVESTIGATE
Sensitive    :    22      1  ← INVESTIGATE
─────────────────────────────────────────
HIGH-VALUE PARAMS: url, redirect, file, src, path
GHOST PATHS    :   89 (existed historically, now 404)
NEXT STEPS     :
  1. Manually review cat_backup.txt live hits
  2. Test cat_interesting_params.txt for SSRF/redirect
  3. Check cat_debug.txt for info disclosure
  4. Run parameter discovery on cat_api.txt endpoints
```
