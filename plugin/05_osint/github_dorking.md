# Playbook: GitHub Dorking

## Purpose
Search GitHub for secrets, credentials, internal URLs, API keys, and
configuration files leaked by developers associated with the target organization.
Input: company name, domain, org name, or GitHub org handle.

---

## Step 1 — Identify GitHub Presence

```bash
TARGET_DOMAIN="target.com"
TARGET_ORG="TargetCorp"      # GitHub org name

# Check if org exists
curl -sk "https://api.github.com/orgs/$TARGET_ORG" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('login','Not found'), '-', d.get('public_repos','?'), 'public repos')"

# List all public repos
curl -sk "https://api.github.com/orgs/$TARGET_ORG/repos?per_page=100" \
  | python3 -c "import sys,json; [print(r['full_name'], r.get('language','')) for r in json.load(sys.stdin)]" \
  > org_repos.txt

echo "Public repos: $(wc -l < org_repos.txt)"
```

---

## Step 2 — GitHub Code Search Dorks

Use these in GitHub's search UI (https://github.com/search) or via API.
Replace `TARGET` with domain, org name, or repo path.

### Secret & Credential Leaks
```
# API Keys
"target.com" "api_key"
"target.com" "apikey"
"target.com" "api_secret"
"target.com" "secret_key"
"target.com" "access_token"
"target.com" "auth_token"
"target.com" "client_secret"

# Passwords
"target.com" "password" filename:.env
"target.com" "password" filename:config.yml
"target.com" "password" filename:settings.py
"target.com" "password" filename:application.properties
"target.com" "password" filename:docker-compose.yml
"target.com" "password" filename:.npmrc

# Private keys
"target.com" "BEGIN RSA PRIVATE KEY"
"target.com" "BEGIN OPENSSH PRIVATE KEY"
"target.com" "BEGIN EC PRIVATE KEY"
org:TargetCorp "BEGIN RSA PRIVATE KEY"

# AWS credentials
"target.com" "AKIA" 
org:TargetCorp "aws_access_key_id"
org:TargetCorp "aws_secret_access_key"
"target.com" "aws_secret" filename:*.py
"target.com" "aws_secret" filename:*.js

# DB connection strings
"target.com" "mongodb://"
"target.com" "postgresql://"
"target.com" "mysql://"
"target.com" "redis://"
org:TargetCorp "DATABASE_URL"
org:TargetCorp "DB_PASSWORD"

# JWT secrets
org:TargetCorp "JWT_SECRET"
org:TargetCorp "jwt_secret"
org:TargetCorp "SECRET_KEY"
```

### Internal Infrastructure Leaks
```
# Internal hostnames
"corp.target.com"
"internal.target.com"
".internal" "target.com"

# Internal IP ranges
org:TargetCorp "10.0.0."
org:TargetCorp "192.168."
org:TargetCorp "172.16."

# Internal service URLs
org:TargetCorp "jenkins.internal"
org:TargetCorp "jira.corp"
org:TargetCorp "confluence.corp"
org:TargetCorp "gitlab.internal"

# Staging/dev URLs
org:TargetCorp "staging.target.com"
org:TargetCorp "dev.target.com"
org:TargetCorp "test.target.com"
```

### Configuration File Searches
```
# .env files
org:TargetCorp filename:.env
org:TargetCorp filename:.env.local
org:TargetCorp filename:.env.production

# Config files
org:TargetCorp filename:config.yml
org:TargetCorp filename:config.yaml
org:TargetCorp filename:settings.py
org:TargetCorp filename:application.properties
org:TargetCorp filename:appsettings.json
org:TargetCorp filename:web.config
org:TargetCorp filename:.htpasswd
org:TargetCorp filename:wp-config.php

# Docker & infra
org:TargetCorp filename:docker-compose.yml
org:TargetCorp filename:Dockerfile
org:TargetCorp filename:.travis.yml
org:TargetCorp filename:.github/workflows

# Kubernetes / cloud
org:TargetCorp filename:*.kubeconfig
org:TargetCorp filename:*.tfvars
org:TargetCorp filename:terraform.tfstate

# SSH configs
org:TargetCorp filename:id_rsa
org:TargetCorp filename:known_hosts
org:TargetCorp filename:authorized_keys
```

### Code Pattern Searches
```
# Hardcoded credentials in code
org:TargetCorp "password = " language:python
org:TargetCorp "password = " language:javascript
org:TargetCorp "password = " language:java
org:TargetCorp 'password: "' language:yaml

# Token patterns
org:TargetCorp /ghp_[a-zA-Z0-9]{36}/   # GitHub PAT
org:TargetCorp /AKIA[A-Z0-9]{16}/       # AWS Access Key
org:TargetCorp /sk-[a-zA-Z0-9]{48}/     # OpenAI key

# Internal endpoints in code
org:TargetCorp "localhost:" language:javascript
org:TargetCorp "127.0.0.1" language:python
org:TargetCorp "/api/internal" language:javascript
```

---

## Step 3 — Automated GitHub Search via API

```bash
GITHUB_TOKEN="your_github_pat"

# Search code for secrets
search_github() {
  local query="$1"
  curl -sk "https://api.github.com/search/code?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$query'))")&per_page=10" \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github.v3+json" \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('items', [])
print(f'Results: {len(items)}')
for item in items:
    print(f\"  {item['repository']['full_name']} → {item['path']}\")
    print(f\"  URL: {item['html_url']}\")
"
}

# Run key searches
QUERIES=(
  "\"$TARGET_DOMAIN\" api_key"
  "\"$TARGET_DOMAIN\" password filename:.env"
  "org:$TARGET_ORG BEGIN RSA PRIVATE KEY"
  "org:$TARGET_ORG AWS_SECRET_ACCESS_KEY"
  "org:$TARGET_ORG DATABASE_URL"
  "org:$TARGET_ORG password filename:config"
)

for query in "${QUERIES[@]}"; do
  echo "=== Query: $query ==="
  search_github "$query"
  sleep 2  # GitHub API rate limit
done
```

---

## Step 4 — trufflehog on Org Repos

```bash
# Scan entire GitHub org for secrets
trufflehog github \
  --org=$TARGET_ORG \
  --token=$GITHUB_TOKEN \
  --only-verified \
  --json \
  > trufflehog_org.json

# Scan specific repo
trufflehog github \
  --repo="https://github.com/$TARGET_ORG/repo-name" \
  --token=$GITHUB_TOKEN \
  --json \
  > trufflehog_repo.json

# Parse results
python3 -c "
import json
with open('trufflehog_org.json') as f:
    for line in f:
        try:
            finding = json.loads(line)
            print(f\"[{finding.get('DetectorName')}] {finding.get('SourceMetadata',{}).get('Data',{}).get('Github',{}).get('link')}\")
        except:
            pass
"
```

---

## Step 5 — Commit History & Deleted File Search

```bash
# Clone repo and search full git history
git clone "https://github.com/$TARGET_ORG/target-repo.git" /tmp/target-repo
cd /tmp/target-repo

# Search all commits for secrets
git log --all -p | grep -iE \
  "(password|secret|api.key|token|credential|private.key|access.key)" \
  | grep "^+" | grep -v "^+++" > git_history_secrets.txt

# Using git-secrets
git secrets --scan-history

# Using trufflehog on local clone
trufflehog git file:///tmp/target-repo --json > trufflehog_local.json

# Search deleted files in git history
git log --diff-filter=D --name-only --pretty=format: | grep -iE "\.(env|key|pem|conf|cfg|ini)$"
```

---

## Step 6 — Gist Search

Developers often paste credentials in GitHub Gists:

```bash
# Search Gists (manual — GitHub doesn't allow Gist API search without auth)
GIST_QUERIES=(
  "target.com password"
  "target.com api_key"
  "target.com secret"
  "targetcorp internal"
)

for q in "${GIST_QUERIES[@]}"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$q'))")
  echo "https://gist.github.com/search?q=$encoded"
done

# trufflehog can also scan gists
trufflehog github \
  --repo="https://gist.github.com/$TARGET_ORG" \
  --token=$GITHUB_TOKEN \
  --json \
  >> trufflehog_org.json
```

---

## Step 7 — Validate & Prioritize Findings

```bash
# Test AWS keys from findings
AWS_KEY="AKIA..."
AWS_SECRET="..."
AWS_SESSION=""  # if temporary creds

aws sts get-caller-identity \
  --access-key-id "$AWS_KEY" \
  --secret-access-key "$AWS_SECRET" \
  2>/dev/null && echo "[VALID] AWS credentials work"

# Test other API keys (generic check — look for 200 vs 401)
API_KEY="found_key"
curl -sk -H "Authorization: Bearer $API_KEY" "https://api.target.com/v1/me" \
  -w "\n%{http_code}"
```

---

## Output

```
TARGET        : TargetCorp / target.com
PUBLIC REPOS  : 47
─────────────────────────────────────────────────────
FINDINGS:
  [CRITICAL] .env file in TargetCorp/backend-service
             Contains: DB_PASSWORD=Prod$ecret123
                       STRIPE_SECRET_KEY=sk_live_...
             URL: github.com/TargetCorp/backend-service/blob/main/.env

  [CRITICAL] AWS keys in git history (deleted 6 months ago)
             AKIA... — tested: VALID — access to S3 and EC2
             URL: github.com/TargetCorp/infra/commit/abc123

  [HIGH]     Internal hostname in config
             staging-db.corp.target.com:5432
             URL: github.com/TargetCorp/api/blob/develop/config.yml

  [MEDIUM]   Hard-coded JWT secret in test file
             SECRET_KEY="supersecretkey123"
─────────────────────────────────────────────────────
NEXT STEPS:
  1. Rotate ALL found credentials immediately (ask program to notify security team)
  2. Report CRITICAL findings before testing further
  3. Use staging-db hostname → load 01_recon/subdomain_takeover + httpx triage
  4. Load 03_reporting/report_writer.md
```

---

## Step 8 — CI/CD Secret Leakage

GitHub Actions workflows are a high-value target for secret exposure. Developers
frequently mishandle secrets in CI/CD pipelines, leaking credentials through
workflow files, build logs, and misconfigured triggers.

### 8a — GitHub Actions Workflow Secret Exfiltration Patterns

```bash
# Search for workflows that reference secrets directly
# Common mistake: echoing secrets for debugging
search_github "org:$TARGET_ORG \"echo \${{ secrets\" filename:.github/workflows"
search_github "org:$TARGET_ORG \"echo \$SECRET\" filename:.github/workflows"
search_github "org:$TARGET_ORG \"echo \$AWS\" filename:.github/workflows"

# Workflows with debug mode enabled (exposes all step outputs including secrets)
search_github "org:$TARGET_ORG \"ACTIONS_STEP_DEBUG\" filename:.github/workflows"
search_github "org:$TARGET_ORG \"ACTIONS_RUNNER_DEBUG\" filename:.github/workflows"

# Secrets printed via env dump
search_github "org:$TARGET_ORG \"printenv\" filename:.github/workflows"
search_github "org:$TARGET_ORG \"env | \" filename:.github/workflows"
search_github "org:$TARGET_ORG \"set | grep\" filename:.github/workflows"
```

### 8b — Searching Workflow Run Logs for Exposed Env Vars

```bash
# GitHub API: list workflow runs and download logs
# Logs may contain secrets if echo/debug statements are present

# List recent workflow runs
curl -sk "https://api.github.com/repos/$TARGET_ORG/REPO/actions/runs?per_page=10" \
  -H "Authorization: token $GITHUB_TOKEN" \
  | python3 -c "
import sys, json
runs = json.load(sys.stdin).get('workflow_runs', [])
for r in runs:
    print(f\"Run {r['id']} — {r['name']} — {r['status']} — {r['created_at']}\")
"

# Download logs for a specific run
curl -sk -L "https://api.github.com/repos/$TARGET_ORG/REPO/actions/runs/RUN_ID/logs" \
  -H "Authorization: token $GITHUB_TOKEN" \
  -o workflow_logs.zip

unzip -o workflow_logs.zip -d workflow_logs/

# Search downloaded logs for leaked secrets
grep -riE "(AKIA[A-Z0-9]{16}|password|secret|token|api.key|Bearer [a-zA-Z0-9._-]+)" \
  workflow_logs/ > leaked_in_logs.txt

# Search for ACTIONS_RUNTIME_TOKEN (GitHub internal token, can be abused)
grep -ri "ACTIONS_RUNTIME_TOKEN" workflow_logs/
grep -ri "ACTIONS_CACHE_URL" workflow_logs/
```

### 8c — Common Mistakes in Workflow Files

```
# Mistake 1: Echoing secrets directly
# BAD: run: echo ${{ secrets.API_KEY }}
"echo \${{ secrets" filename:.github/workflows

# Mistake 2: Debug mode left enabled in workflow
# BAD: ACTIONS_STEP_DEBUG: true
"ACTIONS_STEP_DEBUG: true" filename:.github/workflows

# Mistake 3: Secrets passed as command-line arguments (visible in process list)
# BAD: run: ./deploy --token ${{ secrets.DEPLOY_TOKEN }}
"\-\-token \${{ secrets" filename:.github/workflows
"\-\-password \${{ secrets" filename:.github/workflows

# Mistake 4: Secrets written to files that get uploaded as artifacts
">> \$GITHUB_OUTPUT" "secrets." filename:.github/workflows
">> \$GITHUB_ENV" "secrets." filename:.github/workflows

# Mistake 5: Using secrets in job names or step names (logged in clear text)
"name: Deploy to \${{ secrets" filename:.github/workflows
```

### 8d — Composite Action and Reusable Workflow Vulnerabilities

```bash
# Composite actions can reference secrets from calling workflow
# If a composite action is in a public repo, its code is visible
# and may reveal how secrets are handled

# Search for composite actions that handle secrets
search_github "org:$TARGET_ORG \"using: composite\" filename:action.yml"
search_github "org:$TARGET_ORG \"using: composite\" filename:action.yaml"

# Reusable workflows with secrets: inherit (passes ALL secrets)
search_github "org:$TARGET_ORG \"secrets: inherit\" filename:.github/workflows"

# Reusable workflows that accept secret inputs
search_github "org:$TARGET_ORG \"type: string\" \"required: true\" filename:.github/workflows"
```

### 8e — pull_request_target Workflow Exploitation

```bash
# pull_request_target runs in the context of the BASE branch with full secrets
# If it checks out the PR HEAD code, a fork can exfiltrate secrets

# Find workflows using pull_request_target
search_github "org:$TARGET_ORG \"pull_request_target\" filename:.github/workflows"

# Dangerous pattern: pull_request_target + checkout of PR code
# This allows a forked PR to run arbitrary code with base repo secrets
search_github "org:$TARGET_ORG \"pull_request_target\" \"ref: \${{ github.event.pull_request.head\" filename:.github/workflows"

# Also dangerous: workflow_run triggered by pull_request
search_github "org:$TARGET_ORG \"workflow_run\" \"pull_request\" filename:.github/workflows"

# Check if workflows have proper restrictions
# Safe: only runs on labeled PRs, only runs approved code
# Unsafe: checks out PR HEAD and runs scripts from it
```

### 8f — GitHub Dorks for CI/CD Configurations

```
# Workflow files with embedded secrets
"filename:.github/workflows" "AKIA"
"filename:.github/workflows" "BEGIN RSA PRIVATE KEY"
"filename:.github/workflows" "password:" org:TargetCorp
"filename:.github/workflows" "api_key:" org:TargetCorp

# ACTIONS_RUNTIME_TOKEN in logs or code
org:TargetCorp "ACTIONS_RUNTIME_TOKEN"
org:TargetCorp "ACTIONS_CACHE_URL"
org:TargetCorp "ACTIONS_ID_TOKEN_REQUEST_URL"

# AWS credentials in workflow files
org:TargetCorp "AWS_ACCESS_KEY_ID" filename:.github/workflows
org:TargetCorp "AWS_SECRET_ACCESS_KEY" filename:.github/workflows
org:TargetCorp "aws-access-key-id" filename:.github/workflows

# Package registry tokens in workflows
org:TargetCorp "NPM_TOKEN" filename:.github/workflows
org:TargetCorp "NODE_AUTH_TOKEN" filename:.github/workflows
org:TargetCorp "PYPI_TOKEN" filename:.github/workflows
org:TargetCorp "TWINE_PASSWORD" filename:.github/workflows
org:TargetCorp "GEM_HOST_API_KEY" filename:.github/workflows
org:TargetCorp "NUGET_API_KEY" filename:.github/workflows

# Docker registry credentials
org:TargetCorp "DOCKER_PASSWORD" filename:.github/workflows
org:TargetCorp "DOCKERHUB_TOKEN" filename:.github/workflows
org:TargetCorp "REGISTRY_PASSWORD" filename:.github/workflows

# Cloud provider tokens
org:TargetCorp "GOOGLE_APPLICATION_CREDENTIALS" filename:.github/workflows
org:TargetCorp "AZURE_CREDENTIALS" filename:.github/workflows
org:TargetCorp "ARM_CLIENT_SECRET" filename:.github/workflows

# Slack/notification webhooks (can be used for phishing or info gathering)
org:TargetCorp "SLACK_WEBHOOK" filename:.github/workflows
org:TargetCorp "hooks.slack.com" filename:.github/workflows
```

### 8g — Tag vs SHA Pinning Audit

```bash
# Actions pinned to mutable tags (v1, v2, latest) are vulnerable to
# supply chain attacks. If the action repo is compromised, the tag
# can be moved to point to malicious code.

# Find actions pinned to tags (vulnerable)
curl -sk "https://api.github.com/repos/$TARGET_ORG/REPO/contents/.github/workflows" \
  -H "Authorization: token $GITHUB_TOKEN" \
  | python3 -c "
import sys, json
files = json.load(sys.stdin)
for f in files:
    print(f['name'], f['download_url'])
"

# Download and audit each workflow file
for wf in .github/workflows/*.yml; do
  echo "=== $wf ==="
  # Show actions pinned to tags (mutable, risky)
  grep -E 'uses: [a-zA-Z0-9._/-]+@v[0-9]' "$wf"
  # Show actions pinned to full SHA (safe)
  grep -E 'uses: [a-zA-Z0-9._/-]+@[a-f0-9]{40}' "$wf"
done

# Search across org for tag-pinned actions
search_github "org:$TARGET_ORG \"uses:\" \"@v\" filename:.github/workflows"

# Known risky pattern: third-party actions pinned to major version tags
# Example: uses: some-org/some-action@v1 (BAD)
# Safe:    uses: some-org/some-action@abc123def456... (GOOD)
```

### 8h — Package Registry Token Exposure

```bash
# NPM tokens
search_github "org:$TARGET_ORG \"NPM_TOKEN\" filename:.npmrc"
search_github "org:$TARGET_ORG \"//registry.npmjs.org/:_authToken\""
search_github "org:$TARGET_ORG \"npm_\" filename:.env"

# PyPI tokens
search_github "org:$TARGET_ORG \"PYPI_TOKEN\""
search_github "org:$TARGET_ORG \"pypi-\" filename:.pypirc"
search_github "org:$TARGET_ORG \"TWINE_USERNAME\" \"TWINE_PASSWORD\""

# RubyGems tokens
search_github "org:$TARGET_ORG \"GEM_HOST_API_KEY\""
search_github "org:$TARGET_ORG \"rubygems_api_key\" filename:.gem/credentials"

# NuGet tokens
search_github "org:$TARGET_ORG \"NUGET_API_KEY\""
search_github "org:$TARGET_ORG \"nuget.org\" \"apikey\""

# GitHub Package Registry tokens (GITHUB_TOKEN with write:packages)
search_github "org:$TARGET_ORG \"packages: write\" filename:.github/workflows"

# Validate found tokens
# NPM: npm whoami --registry https://registry.npmjs.org
# PyPI: twine check (attempt upload to test PyPI)
# RubyGems: curl https://rubygems.org/api/v1/api_key.json -u ":TOKEN"
```
