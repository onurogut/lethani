# Technology Attack Matrix

Playbooks that **must** be run for each detected technology stack.

| Detected Tech                | Always Run                                                              |
|------------------------------|-------------------------------------------------------------------------|
| PHP (Laravel/Symfony/WP)     | sqli, xss, ssti, deserialization (PHPGGC), lfi (wrappers), file_upload, xxe |
| Java (Spring/Tomcat/JBoss)   | deserialization (ysoserial), ssti (SpEL), sqli, ssrf, path_traversal, xxe |
| .NET (ASP.NET/IIS)           | deserialization (ViewState), sqli, xss, path_traversal, xxe             |
| Node.js (Express/Koa)        | prototype_pollution, ssti, ssrf, sqli (NoSQL), xss, http_smuggling      |
| Python (Django/Flask)        | ssti (Jinja2), sqli, ssrf, deserialization (pickle), path_traversal     |
| Ruby (Rails/Sinatra)         | deserialization (Marshal), ssti (ERB), sqli, ssrf, idor                 |
| GraphQL                      | graphql_attacks, idor, sqli, auth_bypass, rate_limit                    |
| REST API                     | api_security, idor, auth_bypass, sqli, ssrf, rate_limit                 |
| WordPress                    | sqli, xss, file_upload, auth_bypass, xxe, path_traversal                |
| nginx reverse proxy          | http_smuggling, cache_poisoning, vhost_discovery, crlf                  |
| Cloudflare/CDN               | cache_poisoning, http_smuggling, waf bypass (xss, sqli)                 |
| Mobile app (APK/IPA)         | mobile_thick_client, api_security, auth_bypass, idor                    |
| Electron app                 | mobile_thick_client, xss (nodeIntegration), path_traversal              |
| WebSocket                    | websocket_testing, auth_bypass, sqli, xss                               |
| JWT auth                     | jwt_attack, auth_bypass                                                  |
| OAuth/SSO                    | oauth_sso_saml, auth_bypass, open_redirect, csrf                        |
| File upload present          | file_upload, xxe (SVG/XLSX), path_traversal, ssrf                       |
| SAML                         | oauth_sso_saml, xxe (SAML), auth_bypass                                 |
| AI/LLM features              | llm_ai_security, xss (output), ssrf (tool calls)                        |
| Next.js                      | cache_poisoning (ISR), ssti, ssrf, prototype_pollution                  |
| .NET SOAP/WSDL               | deserialization (SOAPwn), xxe, sqli                                     |
| GitHub Actions / CI/CD       | cicd_supply_chain, github_dorking                                       |

---

## Endpoint-Type Quick Reference

```
LOGIN PAGE     → auth_bypass, sqli, xss, csrf, rate_limit, crlf
SEARCH BOX     → sqli, xss, ssti, path_traversal
FILE UPLOAD    → file_upload, xxe (SVG), path_traversal (filename)
API ENDPOINT   → api_security, idor, sqli, ssrf, auth_bypass, race
CONTACT FORM   → xss (stored), csrf, crlf (email), ssti, captcha bypass
PROFILE PAGE   → idor, xss (stored), file_upload (avatar), csrf
PASSWORD RESET → auth_bypass, idor, rate_limit, token prediction, host_header
PAYMENT FLOW   → business_logic, race_condition, idor, csrf, price manip
REDIRECT PARAM → open_redirect, ssrf, xss (javascript:)
WEBHOOK URL    → ssrf, api_security
EXPORT/IMPORT  → xxe, ssrf, sqli, path_traversal, deserialization
ADMIN PANEL    → auth_bypass, idor (vertical), csrf, sqli, ssti
GRAPHQL        → graphql_attacks, idor, sqli, auth_bypass, DoS
WEBSOCKET      → websocket_testing, auth_bypass, injection
MOBILE APP     → mobile_thick_client, api_security, auth_bypass
AI CHATBOT     → llm_ai_security, xss (output rendering), ssrf (tools)
OAUTH LOGIN    → oauth_sso_saml, open_redirect, csrf, auth_bypass
SAML SSO       → oauth_sso_saml, xxe, auth_bypass
CI/CD PIPELINE → cicd_supply_chain, github_dorking
```
