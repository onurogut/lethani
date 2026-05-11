# Playbook: CI/CD Pipeline Security & Supply Chain Attack Surface

## Purpose
Discover exposed CI/CD pipelines, workflow misconfigurations, supply chain attack
vectors, container security issues, and leaked secrets in build systems.
Input: GitHub org/repo, target domain, or package name.

---

## Step 1 -- CI/CD Configuration Discovery

Identify exposed CI/CD configuration files across repositories and web assets.

```bash
ORG="targetorg"
REPO="targetrepo"

# Clone or shallow-clone the repo
git clone --depth=1 "https://github.com/$ORG/$REPO" /tmp/cicd_audit/$REPO

# Detect all CI/CD config files
find /tmp/cicd_audit/$REPO -type f \( \
  -path "*/.github/workflows/*.yml" -o \
  -path "*/.github/workflows/*.yaml" -o \
  -name ".gitlab-ci.yml" -o \
  -name "Jenkinsfile" -o \
  -name ".travis.yml" -o \
  -path "*/.circleci/config.yml" -o \
  -name "azure-pipelines.yml" -o \
  -name "bitbucket-pipelines.yml" -o \
  -name "cloudbuild.yaml" -o \
  -name "Dockerfile*" -o \
  -name "docker-compose*.yml" -o \
  -name ".drone.yml" \
\) 2>/dev/null | tee cicd_configs_found.txt

echo "CI/CD configs found: $(wc -l < cicd_configs_found.txt)"
```

### List all public repos and their workflows via GitHub API

```bash
# Enumerate all public repos in an org
gh repo list "$ORG" --public --limit 500 --json name,url -q '.[].name' \
  > org_repos.txt

# For each repo, list workflow files
while read repo; do
  workflows=$(gh api "repos/$ORG/$repo/actions/workflows" \
    --jq '.workflows[].path' 2>/dev/null)
  if [ -n "$workflows" ]; then
    echo "[$repo]"
    echo "$workflows" | sed 's/^/  /'
  fi
done < org_repos.txt > all_workflows.txt
```

### Build artifact and log exposure

```bash
# Check for publicly accessible build artifacts
gh api "repos/$ORG/$REPO/actions/artifacts" \
  --jq '.artifacts[] | "\(.name) \(.size_in_bytes) \(.archive_download_url)"' \
  2>/dev/null > artifacts.txt

# Check if workflow run logs are accessible (requires read access)
gh api "repos/$ORG/$REPO/actions/runs?per_page=10" \
  --jq '.workflow_runs[] | "\(.id) \(.name) \(.status) \(.conclusion)"' \
  2>/dev/null > workflow_runs.txt

# Attempt to download run logs (may contain secrets leaked to stdout)
RUN_ID=$(head -1 workflow_runs.txt | awk '{print $1}')
gh api "repos/$ORG/$REPO/actions/runs/$RUN_ID/logs" \
  > run_logs.zip 2>/dev/null && unzip -o run_logs.zip -d run_logs/
```

### Docker registry enumeration

```bash
# Docker Hub -- public images for the org
curl -s "https://hub.docker.com/v2/repositories/$ORG/?page_size=100" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('results', []):
    print(f\"{r['name']}  stars={r.get('star_count',0)}  pulls={r.get('pull_count',0)}  updated={r.get('last_updated','')}\")
" > dockerhub_images.txt

# GitHub Container Registry (ghcr.io)
curl -s "https://ghcr.io/v2/$ORG/tags/list" 2>/dev/null
# Enumerate known image names
for img in $(cat org_repos.txt); do
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://ghcr.io/v2/$ORG/$img/tags/list")
  [ "$status" = "200" ] && echo "[GHCR] ghcr.io/$ORG/$img"
done > ghcr_images.txt

# AWS ECR public gallery
curl -s "https://gallery.ecr.aws/search?searchTerm=$ORG" \
  -H "Accept: application/json" 2>/dev/null | python3 -m json.tool
```

---

## Step 2 -- GitHub Actions Security Analysis

### 2a. pull_request_target vulnerability

Workflows triggered by `pull_request_target` run in the context of the base
repo, with access to secrets. If they also checkout the fork PR code, a fork
attacker can execute arbitrary code with access to secrets.

```bash
# Find pull_request_target triggers
grep -rn "pull_request_target" /tmp/cicd_audit/$REPO/.github/workflows/ \
  2>/dev/null | tee prt_triggers.txt

# CRITICAL: check if any pull_request_target workflow also does checkout
# of the PR head (the dangerous pattern)
for wf in $(grep -rl "pull_request_target" \
  /tmp/cicd_audit/$REPO/.github/workflows/ 2>/dev/null); do
  if grep -q "actions/checkout" "$wf"; then
    # Check if it checks out the PR ref (dangerous)
    if grep -A5 "actions/checkout" "$wf" | grep -qE "github\.event\.pull_request\.head\.(ref|sha)|merge_group"; then
      echo "[CRITICAL] $wf -- pull_request_target + checkout of fork code"
    fi
  fi
done
```

### 2b. Expression injection (workflow injection)

Untrusted input injected into `run:` blocks via `${{ }}` expressions.

```bash
# Dangerous expression patterns -- any user-controlled context in run blocks
DANGEROUS_EXPRS=(
  'github.event.issue.title'
  'github.event.issue.body'
  'github.event.pull_request.title'
  'github.event.pull_request.body'
  'github.event.comment.body'
  'github.event.review.body'
  'github.event.discussion.title'
  'github.event.discussion.body'
  'github.event.pages.*.page_name'
  'github.event.commits.*.message'
  'github.event.commits.*.author.name'
  'github.event.head_commit.message'
  'github.event.head_commit.author.name'
  'github.head_ref'
  'github.event.workflow_run.head_branch'
)

for wf in /tmp/cicd_audit/$REPO/.github/workflows/*.yml \
          /tmp/cicd_audit/$REPO/.github/workflows/*.yaml; do
  [ -f "$wf" ] || continue
  for expr in "${DANGEROUS_EXPRS[@]}"; do
    # Check if expression is used inside a run: block (not just env)
    if grep -Pzo "(?s)run:.*?\$\{\{\s*$expr" "$wf" 2>/dev/null | grep -q .; then
      echo "[HIGH] $wf -- expression injection via $expr in run block"
    fi
  done
done 2>/dev/null | tee expression_injection.txt
```

### 2c. GITHUB_TOKEN permission analysis

```bash
# Check default permissions (repo-level setting)
gh api "repos/$ORG/$REPO" --jq '.permissions' 2>/dev/null

# Extract permissions from workflow files
for wf in /tmp/cicd_audit/$REPO/.github/workflows/*.yml \
          /tmp/cicd_audit/$REPO/.github/workflows/*.yaml; do
  [ -f "$wf" ] || continue
  echo "=== $(basename $wf) ==="
  # Top-level permissions
  grep -A20 "^permissions:" "$wf" 2>/dev/null | head -20
  # Job-level permissions
  grep -B2 -A10 "permissions:" "$wf" 2>/dev/null
  echo "---"
done > token_permissions.txt

# Flag overly permissive tokens
grep -iE "contents:\s*write|packages:\s*write|actions:\s*write|id-token:\s*write" \
  token_permissions.txt && echo "[MEDIUM] Overly broad GITHUB_TOKEN permissions found"
```

### 2d. Self-hosted runner detection

```bash
# Detect self-hosted runner usage
grep -rn "runs-on:.*self-hosted" \
  /tmp/cicd_audit/$REPO/.github/workflows/ 2>/dev/null | tee self_hosted.txt

# Self-hosted runners on public repos = anyone can fork and run code
# on the runner via a PR workflow
if [ -s self_hosted.txt ]; then
  echo "[HIGH] Self-hosted runners detected -- check if repo is public"
  echo "Risk: persistence via cron, lateral movement to internal network"
  echo "Risk: access to runner filesystem, Docker socket, cloud metadata"
fi

# Check for runner labels that reveal infrastructure
grep -rhoP "runs-on:\s*\[?[^\]]+\]?" \
  /tmp/cicd_audit/$REPO/.github/workflows/ 2>/dev/null \
  | sort -u > runner_labels.txt
```

### 2e. Secret exfiltration from workflow logs

```bash
# Download and scan workflow logs for accidentally printed secrets
if [ -d run_logs ]; then
  # AWS keys
  grep -rhoP "AKIA[0-9A-Z]{16}" run_logs/ | sort -u > log_secrets.txt
  # Generic secrets/tokens
  grep -rhoiP "(token|secret|password|api_key|apikey)\s*[:=]\s*\S+" \
    run_logs/ | sort -u >> log_secrets.txt
  # Base64-encoded blobs (sometimes used to smuggle secrets)
  grep -rhoP "[A-Za-z0-9+/]{40,}={0,2}" run_logs/ \
    | while read b; do
      decoded=$(echo "$b" | base64 -d 2>/dev/null)
      echo "$decoded" | grep -qiP "(key|secret|token|password)" && echo "[SUSPECT] $b"
    done >> log_secrets.txt
fi
```

### 2f. Composite action and reusable workflow poisoning

```bash
# Identify all third-party actions used
grep -rhoP "uses:\s*\K[^\s]+" \
  /tmp/cicd_audit/$REPO/.github/workflows/ 2>/dev/null \
  | sort -u > third_party_actions.txt

# Check for tag/branch references instead of SHA pinning
echo "--- Actions NOT pinned to SHA ---"
while read action; do
  # SHA-pinned actions look like: owner/repo@abc123def456...
  if ! echo "$action" | grep -qP '@[0-9a-f]{40}'; then
    echo "[MEDIUM] $action -- not SHA-pinned"
  fi
done < third_party_actions.txt | tee unpinned_actions.txt

# OpenSSF Scorecard -- comprehensive supply chain risk assessment
scorecard --repo="github.com/$ORG/$REPO" --format=json 2>/dev/null \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for check in data.get('checks', []):
    score = check.get('score', -1)
    name = check.get('name', '')
    reason = check.get('reason', '')
    marker = '[FAIL]' if score < 5 else '[WARN]' if score < 8 else '[PASS]'
    print(f'{marker} {name}: {score}/10 -- {reason}')
" | tee scorecard_results.txt
```

### 2g. StepSecurity harden-runner analysis

```bash
# Check if harden-runner is in use (defense indicator)
grep -rn "step-security/harden-runner" \
  /tmp/cicd_audit/$REPO/.github/workflows/ 2>/dev/null

# If not present, workflows have no outbound network restriction
# Recommend: step-security/harden-runner with egress-policy: audit/block
```

---

## Step 3 -- Supply Chain Attack Vectors

### 3a. Dependency confusion

```bash
# Extract private package names from lock files and manifests
# npm/Node.js
if [ -f /tmp/cicd_audit/$REPO/package.json ]; then
  python3 -c "
import json
with open('/tmp/cicd_audit/$REPO/package.json') as f:
    pkg = json.load(f)
for section in ['dependencies', 'devDependencies']:
    for name in pkg.get(section, {}):
        # Scoped packages (@org/name) are prime targets
        print(name)
" > npm_deps.txt

  # Check if scoped packages exist on public npm
  while read dep; do
    status=$(curl -sk -o /dev/null -w "%{http_code}" \
      "https://registry.npmjs.org/$dep")
    if [ "$status" = "404" ]; then
      echo "[HIGH] $dep -- NOT on public npm (dependency confusion candidate)"
    fi
  done < npm_deps.txt | tee depconf_npm.txt
fi

# Python
if [ -f /tmp/cicd_audit/$REPO/requirements.txt ]; then
  grep -v "^#" /tmp/cicd_audit/$REPO/requirements.txt \
    | grep -oP "^[a-zA-Z0-9_-]+" > pypi_deps.txt

  while read dep; do
    status=$(curl -sk -o /dev/null -w "%{http_code}" \
      "https://pypi.org/pypi/$dep/json")
    if [ "$status" = "404" ]; then
      echo "[HIGH] $dep -- NOT on public PyPI (dependency confusion candidate)"
    fi
  done < pypi_deps.txt | tee depconf_pypi.txt
fi

# Check for --extra-index-url in pip configs (attack surface for confusion)
grep -rn "extra-index-url\|--index-url" \
  /tmp/cicd_audit/$REPO/ 2>/dev/null | grep -v ".git/"
```

### 3b. Typosquatting detection

```bash
# Generate typosquat candidates for critical dependencies
python3 -c "
import itertools, sys
pkg = sys.argv[1]
typos = set()
# Character swap
for i in range(len(pkg)-1):
    t = list(pkg); t[i], t[i+1] = t[i+1], t[i]; typos.add(''.join(t))
# Missing character
for i in range(len(pkg)):
    typos.add(pkg[:i] + pkg[i+1:])
# Double character
for i in range(len(pkg)):
    typos.add(pkg[:i] + pkg[i] + pkg[i:])
# Separator confusion (- vs _ vs .)
typos.add(pkg.replace('-', '_')); typos.add(pkg.replace('_', '-'))
typos.add(pkg.replace('-', '')); typos.add(pkg.replace('_', ''))
typos.discard(pkg)
for t in sorted(typos):
    print(t)
" "TARGET_PACKAGE" > typosquat_candidates.txt

# Check which typosquat names actually exist on npm
while read name; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://registry.npmjs.org/$name")
  [ "$status" = "200" ] && echo "[WARN] $name exists on npm (typosquat?)"
done < typosquat_candidates.txt
```

### 3c. Malicious build scripts

```bash
# Audit package.json lifecycle scripts
if [ -f /tmp/cicd_audit/$REPO/package.json ]; then
  echo "=== npm lifecycle scripts ==="
  python3 -c "
import json
with open('/tmp/cicd_audit/$REPO/package.json') as f:
    pkg = json.load(f)
scripts = pkg.get('scripts', {})
dangerous = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall', 'prepublish']
for hook in dangerous:
    if hook in scripts:
        print(f'[WARN] {hook}: {scripts[hook]}')
"
fi

# Audit setup.py for suspicious commands
if [ -f /tmp/cicd_audit/$REPO/setup.py ]; then
  echo "=== setup.py analysis ==="
  grep -nE "(subprocess|os\.system|os\.popen|exec|eval|__import__|urllib|requests\.get|socket)" \
    /tmp/cicd_audit/$REPO/setup.py
fi

# Audit Makefile for suspicious targets
if [ -f /tmp/cicd_audit/$REPO/Makefile ]; then
  echo "=== Makefile analysis ==="
  grep -nE "(curl|wget|nc |bash -c|sh -c|/dev/tcp|base64)" \
    /tmp/cicd_audit/$REPO/Makefile
fi
```

### 3d. Lock file integrity

```bash
# Check if lock files are committed (they should be)
for lockfile in package-lock.json yarn.lock pnpm-lock.yaml \
                Pipfile.lock poetry.lock Gemfile.lock go.sum \
                Cargo.lock composer.lock; do
  if [ -f "/tmp/cicd_audit/$REPO/$lockfile" ]; then
    echo "[OK] $lockfile present"
  fi
done

# Detect lock file manipulation -- check for registry URL changes
if [ -f /tmp/cicd_audit/$REPO/package-lock.json ]; then
  # Non-standard registries in lock file
  grep -oP '"resolved":\s*"\K[^"]+' /tmp/cicd_audit/$REPO/package-lock.json \
    | grep -v "registry.npmjs.org" | sort -u | head -20 \
    && echo "[WARN] Non-standard registry URLs found in package-lock.json"
fi

if [ -f /tmp/cicd_audit/$REPO/yarn.lock ]; then
  grep -oP 'resolved\s+"\K[^"]+' /tmp/cicd_audit/$REPO/yarn.lock \
    | grep -v "registry.yarnpkg.com\|registry.npmjs.org" | sort -u | head -20 \
    && echo "[WARN] Non-standard registry URLs found in yarn.lock"
fi
```

---

## Step 4 -- Container Security

### 4a. Public Docker image secret scanning

```bash
IMAGE="$ORG/$REPO"

# Pull latest image
docker pull "$IMAGE:latest" 2>/dev/null

# Scan image layers for secrets with trufflehog
trufflehog docker --image="$IMAGE:latest" --json 2>/dev/null \
  > docker_secrets.json

# Inspect image history (reveals build commands, ARGs, ENV)
docker history --no-trunc "$IMAGE:latest" 2>/dev/null | tee docker_history.txt

# Look for secrets passed as build args or ENV
grep -iE "(password|secret|token|key|api_key|aws_|credentials)" \
  docker_history.txt && echo "[HIGH] Secrets visible in image layer history"

# Extract and scan filesystem
mkdir -p /tmp/docker_extract
docker save "$IMAGE:latest" -o /tmp/docker_image.tar
tar xf /tmp/docker_image.tar -C /tmp/docker_extract
# Scan extracted filesystem
gitleaks detect --source /tmp/docker_extract --report-path docker_gitleaks.json --no-git
```

### 4b. Dockerfile analysis

```bash
# Find all Dockerfiles
find /tmp/cicd_audit/$REPO -name "Dockerfile*" -type f > dockerfiles.txt

while read df; do
  echo "=== $df ==="

  # Hardcoded credentials
  grep -nE "(ENV|ARG).*(PASSWORD|SECRET|TOKEN|KEY|CREDENTIALS|API_KEY)" "$df" \
    && echo "[HIGH] Hardcoded credentials in Dockerfile"

  # Running as root (no USER directive)
  if ! grep -q "^USER " "$df"; then
    echo "[MEDIUM] No USER directive -- container runs as root"
  fi

  # Exposed sensitive ports
  grep -nE "EXPOSE.*(22|3306|5432|6379|27017|9200|2375|2376)" "$df" \
    && echo "[MEDIUM] Sensitive service ports exposed"

  # ADD from remote URL (potential supply chain risk)
  grep -nE "^ADD\s+https?://" "$df" \
    && echo "[MEDIUM] ADD from remote URL -- integrity not verified"

  # Using latest tag for base image
  grep -nE "^FROM\s+\S+:latest|^FROM\s+[^:]+$" "$df" \
    && echo "[LOW] Base image not pinned to specific version"

  # COPY . . (may include secrets)
  grep -nE "^COPY\s+\.\s+\." "$df" \
    && echo "[LOW] COPY . . may include sensitive files -- check .dockerignore"

done < dockerfiles.txt | tee dockerfile_audit.txt
```

### 4c. Docker socket and Kubernetes exposure

```bash
# Check for Docker socket mounts in compose files
grep -rn "/var/run/docker.sock" /tmp/cicd_audit/$REPO/ 2>/dev/null \
  | grep -v ".git/" && echo "[CRITICAL] Docker socket mounted -- container escape risk"

# Kubernetes manifests -- find and audit
find /tmp/cicd_audit/$REPO -type f \( \
  -name "*.yaml" -o -name "*.yml" \) -exec \
  grep -lE "kind:\s*(Deployment|Pod|DaemonSet|StatefulSet|CronJob)" {} \; \
  2>/dev/null > k8s_manifests.txt

while read manifest; do
  echo "=== $manifest ==="
  # Privileged containers
  grep -A2 "privileged:" "$manifest" | grep "true" \
    && echo "[CRITICAL] Privileged container in $manifest"
  # hostNetwork/hostPID
  grep -E "hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true" "$manifest" \
    && echo "[HIGH] Host namespace sharing in $manifest"
  # Secrets in env
  grep -B2 -A2 "valueFrom:\|secretKeyRef:" "$manifest"
  # Service account tokens
  grep "automountServiceAccountToken: true" "$manifest" \
    && echo "[MEDIUM] Service account token auto-mounted"
done < k8s_manifests.txt | tee k8s_audit.txt

# Helm charts
find /tmp/cicd_audit/$REPO -name "Chart.yaml" -type f 2>/dev/null \
  | while read chart; do
    dir=$(dirname "$chart")
    echo "[HELM] $dir"
    # Check values.yaml for hardcoded secrets
    grep -rniE "(password|secret|token|key):" "$dir/values.yaml" 2>/dev/null
  done
```

---

## Step 5 -- Secret Scanning

### 5a. Repository-wide secret scan

```bash
# TruffleHog -- full git history scan (most comprehensive)
trufflehog git "https://github.com/$ORG/$REPO" --json \
  2>/dev/null > secrets_trufflehog.json

python3 -c "
import json
with open('secrets_trufflehog.json') as f:
    for line in f:
        try:
            r = json.loads(line)
            dtype = r.get('DetectorName', 'unknown')
            raw = r.get('Raw', '')[:40]
            src = r.get('SourceMetadata', {})
            print(f'[{dtype}] {raw}... -- {src}')
        except: pass
" | tee secrets_summary.txt

# Gitleaks -- regex-based scan
gitleaks detect --source="/tmp/cicd_audit/$REPO" \
  --report-path=gitleaks_report.json --report-format=json

# ggshield (GitGuardian CLI) -- requires GITGUARDIAN_API_KEY
ggshield secret scan repo "/tmp/cicd_audit/$REPO" 2>/dev/null

# Semgrep -- secrets and security patterns
semgrep --config "p/secrets" --config "p/ci" \
  /tmp/cicd_audit/$REPO/ --json > semgrep_results.json 2>/dev/null
```

### 5b. CI/CD config secret exposure

```bash
# Scan workflow files specifically for hardcoded secrets
for wf in /tmp/cicd_audit/$REPO/.github/workflows/*.yml \
          /tmp/cicd_audit/$REPO/.github/workflows/*.yaml; do
  [ -f "$wf" ] || continue
  echo "=== $(basename $wf) ==="

  # Hardcoded tokens/keys (not using ${{ secrets.* }})
  grep -nP "(AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|glpat-[0-9a-zA-Z\-]{20})" "$wf"

  # Environment variables set to literal values (not secrets refs)
  grep -nP "^\s+(env|with):" -A20 "$wf" 2>/dev/null \
    | grep -iP "(key|token|secret|password)\s*:\s*['\"]?[a-zA-Z0-9]" \
    | grep -v '\$\{\{' \
    && echo "[HIGH] Hardcoded credential in workflow"

done | tee cicd_secrets.txt
```

### 5c. Exposed config files via web

```bash
# Check for common config/secret files exposed on the target web server
TARGET="https://target.com"
PATHS=(
  ".env" ".env.local" ".env.production" ".env.development"
  ".git/config" ".git/HEAD"
  ".github/workflows" ".gitlab-ci.yml"
  "Jenkinsfile" ".travis.yml"
  "docker-compose.yml" "Dockerfile"
  ".npmrc" ".yarnrc" ".pypirc"
  "config.json" "config.yaml" "config.yml"
  "wp-config.php.bak" "application.properties"
  ".aws/credentials" ".kube/config"
)

for path in "${PATHS[@]}"; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/$path")
  [ "$status" = "200" ] && echo "[HIGH] $TARGET/$path -- EXPOSED (HTTP 200)"
done | tee exposed_configs.txt
```

### 5d. GitHub secret scanning alerts (if org member or has access)

```bash
# List secret scanning alerts (requires appropriate permissions)
gh api "repos/$ORG/$REPO/secret-scanning/alerts?state=open&per_page=100" \
  --jq '.[] | "\(.secret_type) \(.state) \(.created_at) \(.html_url)"' \
  2>/dev/null | tee gh_secret_alerts.txt

# Code scanning alerts
gh api "repos/$ORG/$REPO/code-scanning/alerts?state=open&per_page=100" \
  --jq '.[] | "\(.rule.security_severity_level) \(.rule.description) \(.html_url)"' \
  2>/dev/null | tee gh_code_alerts.txt
```

---

## Step 6 -- Org-Wide GitHub Actions Audit

Across the entire organization, identify systemic risks.

```bash
# Clone all public repos (shallow) and audit
mkdir -p /tmp/cicd_audit/org_scan
while read repo; do
  git clone --depth=1 "https://github.com/$ORG/$repo" \
    "/tmp/cicd_audit/org_scan/$repo" 2>/dev/null
done < org_repos.txt

# Org-wide: count unpinned actions
find /tmp/cicd_audit/org_scan -path "*/.github/workflows/*.yml" -exec \
  grep -hoP "uses:\s*\K[^\s]+" {} \; 2>/dev/null \
  | sort | uniq -c | sort -rn > org_action_usage.txt

# Org-wide: find all pull_request_target
find /tmp/cicd_audit/org_scan -path "*/.github/workflows/*.yml" -exec \
  grep -l "pull_request_target" {} \; 2>/dev/null > org_prt_workflows.txt

# Org-wide: find self-hosted runner usage
find /tmp/cicd_audit/org_scan -path "*/.github/workflows/*.yml" -exec \
  grep -l "self-hosted" {} \; 2>/dev/null > org_selfhosted.txt

# OpenSSF Scorecard batch scan
while read repo; do
  echo "--- $ORG/$repo ---"
  scorecard --repo="github.com/$ORG/$repo" --checks="Token-Permissions,Dangerous-Workflow,Pinned-Dependencies,Branch-Protection" \
    --format=json 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for c in data.get('checks', []):
        print(f\"  {c['name']}: {c.get('score',-1)}/10\")
except: pass
"
done < org_repos.txt | tee org_scorecard.txt
```

---

## Reference: Real-World Incidents

Use these as context when reporting findings. They demonstrate impact.

| Incident | Year | Vector | Impact |
|---|---|---|---|
| **tj-actions/changed-files** | 2025 | Compromised GitHub Action tag -- malicious commit injected to exfiltrate secrets from CI runners | Secrets of 23,000+ repos exposed via workflow logs |
| **Trivy GitHub Action supply chain** | 2026 | Dependency of Trivy action compromised, injecting secret-exfil code into security scanning pipelines | Ironic -- security scanning tool became the attack vector |
| **Codecov bash uploader** | 2021 | Attacker modified Codecov's bash uploader script hosted on codecov.io -- CI/CD pipelines curled and executed it | Secrets exfiltrated from Twitch, HashiCorp, Confluent, and others |
| **ua-parser-js** | 2021 | Compromised npm maintainer account -- cryptominer + credential stealer injected | 8M weekly downloads affected |
| **event-stream** | 2018 | Social engineering: new maintainer added malicious dependency targeting Copay bitcoin wallet | Targeted supply chain attack via trust transfer |
| **SolarWinds (SUNBURST)** | 2020 | Build system compromise -- malicious code injected during CI/CD build pipeline | 18,000+ organizations affected including US government |
| **3CX** | 2023 | Cascading supply chain -- compromised upstream dependency led to trojanized desktop app | Double supply chain attack (first known) |
| **xz-utils** | 2024 | Social engineering: multi-year campaign to become maintainer, injected backdoor in build system | Near-compromise of SSH on most Linux distros |

---

## Output

```
PLAYBOOK : CI/CD Pipeline Security & Supply Chain
TARGET   : github.com/ORG/REPO
-----------------------------------------------------
STEP 1   : CI/CD Configuration Discovery
STATUS   : DONE
RESULT   : 12 workflow files, 3 Dockerfiles, 2 docker-compose, 1 Helm chart
           Docker Hub: 5 public images, GHCR: 3 images
-----------------------------------------------------
STEP 2   : GitHub Actions Security Analysis
STATUS   : DONE
RESULT   :
  [CRITICAL] deploy.yml -- pull_request_target + checkout of fork code
  [HIGH]     build.yml -- expression injection via github.event.issue.title
  [HIGH]     ci.yml -- self-hosted runner on public repo
  [MEDIUM]   17 actions not pinned to SHA (tag references only)
  [MEDIUM]   contents: write permission on 4 workflows
-----------------------------------------------------
STEP 3   : Supply Chain Attack Vectors
STATUS   : DONE
RESULT   :
  [HIGH]   @internal/auth-lib -- not on public npm (dep confusion candidate)
  [WARN]   postinstall script runs: node scripts/setup.js
  [OK]     Lock files present and committed
-----------------------------------------------------
STEP 4   : Container Security
STATUS   : DONE
RESULT   :
  [CRITICAL] docker-compose.yml mounts Docker socket
  [HIGH]     Dockerfile.prod: ENV DB_PASSWORD=... in layer history
  [MEDIUM]   No USER directive in 2/3 Dockerfiles
  [MEDIUM]   k8s deployment uses privileged: true
-----------------------------------------------------
STEP 5   : Secret Scanning
STATUS   : DONE
RESULT   :
  [CRITICAL] AWS access key (AKIA...) found in git history (commit abc123)
  [HIGH]     GitHub PAT (ghp_...) in .github/workflows/deploy.yml
  [HIGH]     .env exposed at https://target.com/.env (HTTP 200)
  [MEDIUM]   3 open GitHub secret scanning alerts
-----------------------------------------------------
FINDINGS SUMMARY
  [CRITICAL] pull_request_target + fork checkout -- full secret exfiltration
  [CRITICAL] Docker socket mounted -- container escape to host
  [CRITICAL] AWS key in git history -- check CloudTrail for abuse
  [HIGH]     Expression injection -- RCE via crafted issue title
  [HIGH]     Self-hosted runner on public repo -- lateral movement risk
  [HIGH]     Dependency confusion candidate -- @internal/auth-lib
  [MEDIUM]   17 unpinned third-party actions -- tag mutability risk
-----------------------------------------------------
NEXT STEPS
  1. Revoke exposed AWS key immediately and rotate all secrets
  2. Fix pull_request_target workflow (use workflow_run pattern instead)
  3. Pin all third-party actions to SHA
  4. Remove Docker socket mount or use read-only with socket proxy
  5. Add step-security/harden-runner to all workflows
  6. Register @internal/auth-lib on public npm as a placeholder
  7. Run OpenSSF Scorecard and remediate score < 5 checks
  8. Implement branch protection rules with required reviews
```

---

## Tools Reference

```bash
# Secret scanning
pip install trufflehog
brew install gitleaks
pip install ggshield
pip install semgrep

# Supply chain assessment
go install github.com/ossf/scorecard/v5/cmd/scorecard@latest
npm install -g snyk

# Container security
brew install trivy
brew install dive  # Docker image layer explorer

# GitHub CLI (required for API calls)
brew install gh

# StepSecurity (action hardening)
# Add step-security/harden-runner@v2 to workflows

# Useful one-liners
# List all actions used across org:
#   find . -path "*/.github/workflows/*.yml" -exec grep -hoP "uses:\s*\K[^\s]+" {} \; | sort -u
# Check if repo has branch protection:
#   gh api repos/ORG/REPO/branches/main/protection 2>/dev/null
# List all repo contributors (maintainer account audit):
#   gh api repos/ORG/REPO/contributors --jq '.[].login'
```
