# Playbook: Custom Wordlist Builder

## Purpose
Generate target-specific wordlists from application content, technology
fingerprints, and OSINT data for more effective fuzzing. Covers CeWL,
username generation, API wordlists, and permutation techniques.
Input: target domain, crawled content, or technology profile.

---

## Step 1 — CeWL Content-Based Wordlist

```bash
TARGET="https://TARGET"

# Basic crawl-based wordlist
cewl "$TARGET" -d 3 -m 5 -w cewl_words.txt
echo "CeWL words: $(wc -l < cewl_words.txt)"

# With email extraction
cewl "$TARGET" -d 3 -m 5 -w cewl_words.txt -e --email_file emails.txt

# Include meta data
cewl "$TARGET" -d 3 -m 5 --meta --meta_file meta.txt -w cewl_words.txt

# Custom User-Agent and authentication
cewl "$TARGET" -d 3 -m 5 \
  --ua "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  --auth_type basic --auth_user admin --auth_pass password \
  -w cewl_words.txt

# Lowercase and unique
cat cewl_words.txt | tr '[:upper:]' '[:lower:]' | sort -u > cewl_clean.txt
```

---

## Step 2 — Technology-Based Wordlists

```bash
# Based on detected technology, select relevant wordlists

# PHP application
cat << 'EOF' > tech_php.txt
wp-admin
wp-content
wp-includes
wp-login.php
xmlrpc.php
.htaccess
php.ini
.env
composer.json
composer.lock
vendor/
config.php
database.php
db.php
admin.php
info.php
phpinfo.php
debug.php
test.php
install.php
setup.php
EOF

# ASP.NET application
cat << 'EOF' > tech_aspnet.txt
web.config
global.asax
elmah.axd
trace.axd
bin/
App_Data/
App_Code/
default.aspx
login.aspx
admin.aspx
error.aspx
swagger/
api/swagger
hangfire
health
EOF

# Node.js application
cat << 'EOF' > tech_node.txt
package.json
package-lock.json
node_modules/
.env
.env.local
.env.production
server.js
app.js
config.js
next.config.js
nuxt.config.js
webpack.config.js
.npmrc
tsconfig.json
graphql
playground
EOF

# Java/Spring application
cat << 'EOF' > tech_java.txt
actuator
actuator/health
actuator/env
actuator/beans
actuator/mappings
actuator/configprops
actuator/trace
actuator/heapdump
swagger-ui.html
swagger-ui/
v2/api-docs
v3/api-docs
api-docs
console
h2-console
jolokia
WEB-INF/web.xml
META-INF/
status
info
EOF
```

---

## Step 3 — Username Generation

```bash
# From name list, generate common username patterns
python3 << 'PYEOF'
import sys

names = [
    ("John", "Smith"),
    ("Jane", "Doe"),
    # Add discovered names here
]

patterns = []
for first, last in names:
    f, l = first.lower(), last.lower()
    patterns.extend([
        f,                    # john
        l,                    # smith
        f"{f}{l}",           # johnsmith
        f"{f}.{l}",          # john.smith
        f"{f}_{l}",          # john_smith
        f"{f[0]}{l}",        # jsmith
        f"{f}{l[0]}",        # johns
        f"{f[0]}.{l}",       # j.smith
        f"{l}{f}",           # smithjohn
        f"{l}{f[0]}",        # smithj
        f"{l}.{f}",          # smith.john
        f"{f}{l}1",          # johnsmith1
    ])

for p in sorted(set(patterns)):
    print(p)
PYEOF

# Email pattern generation
DOMAIN="TARGET"
cat usernames.txt | while read user; do
  echo "${user}@${DOMAIN}"
  echo "${user}@mail.${DOMAIN}"
done > emails_generated.txt

# From LinkedIn/OSINT gathered names
# Use tools like linkedin2username or crosslinked
```

---

## Step 4 — Password Wordlist Generation

```bash
# Base words from target (replace with terms extracted from the target)
BASE_WORDS="<company> <product> <city> <country> 2026 2025"

# Generate mutations
python3 << 'PYEOF'
import itertools

base_words = ["<company>", "<product>", "<city>", "<country>", "admin", "password"]
years = ["2024", "2025", "2026"]
specials = ["!", "@", "#", "$", ".", "_", "123", "1234"]

passwords = set()
for word in base_words:
    passwords.add(word)
    passwords.add(word.capitalize())
    passwords.add(word.upper())
    for year in years:
        passwords.add(f"{word}{year}")
        passwords.add(f"{word.capitalize()}{year}")
        passwords.add(f"{word}{year}!")
        passwords.add(f"{word.capitalize()}{year}!")
    for s in specials:
        passwords.add(f"{word}{s}")
        passwords.add(f"{word.capitalize()}{s}")
        passwords.add(f"{s}{word}")

for p in sorted(passwords):
    print(p)
PYEOF

# Using hashcat rules on base wordlist
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule base_words.txt > mutated.txt

# Using John rules
john --wordlist=base_words.txt --rules --stdout > john_mutated.txt
```

---

## Step 5 — API Endpoint Wordlist

```bash
# Build API wordlist from discovered patterns
# If API uses /api/v1/users, generate related endpoints

python3 << 'PYEOF'
resources = [
    "users", "accounts", "profiles", "settings", "config",
    "orders", "products", "items", "payments", "invoices",
    "messages", "notifications", "alerts", "logs", "events",
    "files", "uploads", "images", "documents", "reports",
    "roles", "permissions", "groups", "teams", "organizations",
    "tokens", "keys", "sessions", "auth", "login", "register",
    "search", "export", "import", "sync", "health", "status",
    "admin", "dashboard", "metrics", "stats", "analytics",
    "webhooks", "callbacks", "integrations", "plugins",
]

actions = ["", "/list", "/all", "/create", "/new", "/delete", "/update",
           "/export", "/import", "/count", "/search", "/batch"]
versions = ["", "v1/", "v2/", "v3/"]
prefixes = ["api/", "api/", ""]

for prefix in prefixes:
    for version in versions:
        for resource in resources:
            for action in actions:
                print(f"{prefix}{version}{resource}{action}")

# Singular/plural
for resource in resources:
    if resource.endswith("s"):
        print(f"api/{resource[:-1]}")  # singular
    else:
        print(f"api/{resource}s")  # plural
PYEOF
```

---

## Step 6 — Permutation and Combination

```bash
# Subdomain permutations
# If we know "api" and "staging" exist, generate combinations
python3 << 'PYEOF'
prefixes = ["api", "dev", "staging", "test", "admin", "internal", "beta"]
suffixes = ["", "-v2", "-new", "-old", "-legacy", "-beta", "-test"]
separators = [".", "-"]
base = "TARGET"

for prefix in prefixes:
    for suffix in suffixes:
        print(f"{prefix}{suffix}.{base}")
    for sep in separators:
        for prefix2 in prefixes:
            if prefix != prefix2:
                print(f"{prefix}{sep}{prefix2}.{base}")
PYEOF

# Directory permutation based on discovered paths
# If /admin exists, try:
cat << 'EOF' > admin_permutations.txt
admin/login
admin/dashboard
admin/users
admin/settings
admin/config
admin/logs
admin/backup
admin/api
admin/panel
admin/console
administrator
administration
admin2
admin-panel
admin-console
_admin
.admin
EOF
```

---

## Step 7 — Wordlist Optimization

```bash
# Remove duplicates
sort -u wordlist.txt -o wordlist_clean.txt

# Remove too short/too long entries
awk 'length >= 3 && length <= 50' wordlist_clean.txt > wordlist_filtered.txt

# Remove entries with unwanted characters
grep -E '^[a-zA-Z0-9._/-]+$' wordlist_filtered.txt > wordlist_safe.txt

# Merge multiple wordlists
cat wordlist_*.txt | sort -u > combined_wordlist.txt
echo "Combined: $(wc -l < combined_wordlist.txt) entries"

# Prioritize (put likely hits first)
# Move common/important entries to top
grep -iE "^(admin|api|config|backup|debug|test|login|dashboard)" combined_wordlist.txt > priority_wordlist.txt
grep -viE "^(admin|api|config|backup|debug|test|login|dashboard)" combined_wordlist.txt >> priority_wordlist.txt
```

---

## Output

```
TARGET        : example.com
WORDLISTS GENERATED:
  cewl_clean.txt        — 2,340 words from site content
  tech_node.txt         — 18 Node.js-specific paths
  usernames.txt         — 156 username permutations
  api_endpoints.txt     — 1,200 API path combinations
  combined_wordlist.txt — 4,891 unique entries (prioritized)
NEXT STEPS    : Use with ffuf_fuzzing.md for targeted discovery
```

---

## Tools Reference

```bash
# CeWL
gem install cewl

# Mentalist (GUI wordlist generator)
# https://github.com/sc0tfree/mentalist

# Username generators
# linkedin2username, crosslinked, namemash

# hashcat rules
# /usr/share/hashcat/rules/best64.rule
# /usr/share/hashcat/rules/rockyou-30000.rule
```
