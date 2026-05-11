# Playbook: Technology Fingerprinting

## Purpose
Identify web server, framework, language, CMS, CDN, WAF, and third-party
services powering the target. Maps technology stack to known vulnerabilities
and informs subsequent testing strategy.
Input: target domain or URL list.

---

## Step 1 — HTTP Header Analysis

```bash
TARGET="https://TARGET"

# Full response headers
curl -sk -D- -o /dev/null "$TARGET" | head -30

# Key headers to check:
# Server: Apache/2.4.51, nginx/1.21.0, IIS/10.0
# X-Powered-By: PHP/8.1, ASP.NET, Express
# X-AspNet-Version: 4.0.30319
# X-Generator: WordPress 6.4, Drupal 10
# Set-Cookie: PHPSESSID (PHP), JSESSIONID (Java), ASP.NET_SessionId (.NET)
# X-Drupal-Cache, X-WordPress-*, X-Magento-*
# CF-RAY (Cloudflare), X-Amz-* (AWS), X-Azure-*

# Multiple paths for different headers
PATHS=("/" "/robots.txt" "/favicon.ico" "/nonexistent_404" "/login" "/api/")
for path in "${PATHS[@]}"; do
  echo "=== $path ==="
  curl -sk -D- -o /dev/null "${TARGET}${path}" 2>/dev/null | grep -iE "^(server|x-powered|x-asp|x-generator|x-drupal|x-frame|x-content|set-cookie|cf-ray|x-amz|x-cache|via):" | head -5
done
```

---

## Step 2 — WAF Detection

```bash
# wafw00f
wafw00f "$TARGET"

# Manual WAF detection via error triggering
# Send a malicious payload and check response
curl -sk -D- "$TARGET/?id=1' OR 1=1--" | head -20
# Cloudflare: "Attention Required!" / cf-ray header
# AWS WAF: 403 with x-amzn-requestid
# Akamai: "Access Denied" reference number
# Imperva: custom error page
# ModSecurity: 403 with mod_security in headers

# Check common WAF headers
curl -sk -I "$TARGET" | grep -iE "^(cf-ray|x-sucuri|x-akamai|x-cdn|x-waf|x-firewall|x-protected)"

# Detect CDN/proxy
curl -sk -I "$TARGET" | grep -iE "^(via|x-cache|x-served-by|x-proxy|cdn-|x-edge|x-varnish)"
```

---

## Step 3 — CMS Detection

```bash
# WordPress
curl -sk "$TARGET/wp-login.php" -o /dev/null -w "%{http_code}" && echo "WordPress detected"
curl -sk "$TARGET/wp-json/wp/v2/users" 2>/dev/null | python3 -m json.tool 2>/dev/null | head -20
curl -sk "$TARGET/wp-includes/version.php" 2>/dev/null | grep "wp_version"
curl -sk "$TARGET" | grep -ioE "wp-content|wp-includes|wordpress" | head -3

# Drupal
curl -sk "$TARGET/CHANGELOG.txt" 2>/dev/null | head -3
curl -sk "$TARGET/core/CHANGELOG.txt" 2>/dev/null | head -3
curl -sk "$TARGET" | grep -ioE "drupal|sites/default" | head -3

# Joomla
curl -sk "$TARGET/administrator/" -o /dev/null -w "%{http_code}" && echo "Joomla detected"
curl -sk "$TARGET/language/en-GB/en-GB.xml" 2>/dev/null | grep -i "version"

# Generic CMS check
curl -sk "$TARGET" | grep -ioE "content=\"(WordPress|Drupal|Joomla|Magento|Shopify|Wix|Squarespace|Ghost|Hugo|Jekyll)[^\"]*\"" | head -5

# WPScan (for WordPress)
wpscan --url "$TARGET" --enumerate vp,vt,u --api-token "$WPSCAN_API"
```

---

## Step 4 — JavaScript Framework Detection

```bash
# Check page source for framework indicators
curl -sk "$TARGET" | grep -ioE "(react|angular|vue|next|nuxt|svelte|ember|backbone|jquery)[^\"']*\.(js|min\.js)" | sort -u

# React: __NEXT_DATA__, _reactRootContainer, data-reactroot
curl -sk "$TARGET" | grep -ioE "__NEXT_DATA__|_reactRootContainer|data-reactroot|react-app" | head -3

# Angular: ng-version, ng-app, angular.js
curl -sk "$TARGET" | grep -ioE "ng-version|ng-app|angular\.(min\.)?js" | head -3

# Vue: __vue__, data-v-, vue.js
curl -sk "$TARGET" | grep -ioE "data-v-[a-f0-9]|__vue__|vue\.(min\.)?js" | head -3

# Check script sources for CDN-loaded frameworks
curl -sk "$TARGET" | grep -oE 'src="[^"]*"' | grep -iE "react|angular|vue|jquery|bootstrap" | head -10
```

---

## Step 5 — Backend Technology Detection

```bash
# Error page fingerprinting
curl -sk "$TARGET/nonexistent_$(date +%s)" | head -30
# Apache: "Not Found" / apache signature
# Nginx: "404 Not Found" / nginx
# IIS: detailed ASP.NET error
# Tomcat: Apache Tomcat/X.X error page
# Express: "Cannot GET /path"
# Django: yellow debug page (if DEBUG=True)
# Laravel: Whoops error page
# Spring Boot: "Whitelabel Error Page"

# File extension probing
EXTS=(".php" ".asp" ".aspx" ".jsp" ".do" ".action" ".py" ".rb" ".pl")
for ext in "${EXTS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${TARGET}/test${ext}")
  [ "$CODE" != "404" ] && echo "Extension $ext → $CODE (may be processed)"
done

# Default files
curl -sk -o /dev/null -w "%{http_code}" "$TARGET/server-info" && echo "Apache server-info"
curl -sk -o /dev/null -w "%{http_code}" "$TARGET/server-status" && echo "Apache server-status"
curl -sk -o /dev/null -w "%{http_code}" "$TARGET/elmah.axd" && echo ".NET ELMAH"
curl -sk -o /dev/null -w "%{http_code}" "$TARGET/actuator" && echo "Spring Boot Actuator"
curl -sk -o /dev/null -w "%{http_code}" "$TARGET/debug/pprof/" && echo "Go pprof"
```

---

## Step 6 — Automated Fingerprinting

```bash
# Wappalyzer CLI (webanalyze)
webanalyze -host "$TARGET" -crawl 2

# httpx with tech detection
echo "TARGET" | httpx -tech-detect -status-code -title

# whatweb
whatweb "$TARGET" -v

# Nmap service detection
nmap -sV -p 80,443,8080,8443 TARGET_IP

# Nuclei tech detection templates
nuclei -t technologies/ -u "$TARGET"
```

---

## Step 7 — Third-Party Service Mapping

```bash
# Extract external resources
curl -sk "$TARGET" | grep -oE '(src|href|action)="https?://[^"]*"' | \
  grep -v "$(echo $TARGET | sed 's|https\?://||')" | sort -u

# Common services to look for:
# Analytics: Google Analytics (UA-/G-), Hotjar, Mixpanel
# CDN: Cloudflare, CloudFront, Akamai, Fastly
# Payment: Stripe, PayPal, Braintree
# Chat: Intercom, Zendesk, Drift, Crisp
# Email: Mailchimp, SendGrid, Mailgun
# Auth: Auth0, Okta, Firebase Auth
# Monitoring: Sentry, Datadog, New Relic

curl -sk "$TARGET" | grep -ioE "(google-analytics|googletagmanager|hotjar|stripe|sentry|intercom|zendesk|auth0|firebase)\.[a-z]*" | sort -u
```

---

## Output

```
TARGET        : https://example.com
WEB SERVER    : nginx/1.21.6 (behind Cloudflare CDN)
WAF           : Cloudflare
LANGUAGE      : PHP 8.1 (PHPSESSID cookie)
CMS           : WordPress 6.4.2
FRAMEWORK     : N/A (standard WP)
JS FRAMEWORK  : jQuery 3.7.1
DATABASE      : MySQL (inferred from WP)
CDN           : Cloudflare (cf-ray header)
3RD PARTY     : Google Analytics, Stripe, Sentry
INTERESTING   : wp-json API exposed, user enumeration possible
NEXT STEPS    : Run wpscan, check WP plugin vulnerabilities,
                test wp-json endpoints for IDOR
```

---

## Tools Reference

```bash
# webanalyze (Wappalyzer CLI)
go install github.com/rverton/webanalyze/cmd/webanalyze@latest

# whatweb
gem install whatweb

# wpscan
gem install wpscan

# builtwith.com — online lookup (passive)
```
