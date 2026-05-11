# Per-Endpoint Checklist

Run this checklist on EVERY endpoint/form/API discovered in Phase 1-2.

```
ENDPOINT: [URL]
METHOD:   [GET/POST/PUT/DELETE]
PARAMS:   [list all parameters]

[ ] INPUT INJECTION
    [ ] SQLi — all params with DB interaction
    [ ] XSS — all reflected/stored params
    [ ] SSTI — params rendered in templates
    [ ] XXE — XML/SOAP content accepted?
    [ ] CRLF — params reflected in response headers?
    [ ] Path traversal — file/path/page/include params?
    [ ] Prototype pollution — JSON body with merge/extend?
    [ ] Command injection — params passed to OS commands?

[ ] ACCESS CONTROL
    [ ] IDOR — change object IDs; horizontal + vertical access
    [ ] Auth bypass — access without auth, expired token, role downgrade
    [ ] BFLA — call admin functions as a normal user
    [ ] CORS — test with Origin header, check credentials
    [ ] CSRF — state-changing request without valid token?

[ ] BUSINESS LOGIC
    [ ] Race condition — duplicate submission, TOCTOU
    [ ] Price/quantity manipulation — negative values, overflow
    [ ] Workflow bypass — skip steps, replay requests
    [ ] Rate limiting — brute force feasibility

[ ] SERVER-SIDE
    [ ] SSRF — URL params, webhooks, import/export
    [ ] File upload — extension, content-type, magic bytes
    [ ] Deserialization — serialized data in cookies/params
    [ ] Cache poisoning — unkeyed inputs, cache deception

[ ] RESPONSE ANALYSIS
    [ ] Information disclosure — version, stack trace, debug
    [ ] Security headers — HSTS, CSP, X-Frame, CORS
    [ ] Cookie flags — Secure, HttpOnly, SameSite
    [ ] Error handling — verbose errors, different status codes
```
