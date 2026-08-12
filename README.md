# aws-security

Read-only security audit toolkit for an AWS account, run daily via GitHub
Actions. This is the AWS counterpart to
[`gcp-security`](https://github.com/jchan023/gcp-security) — same approach
(bash + CLI + `jq`, OIDC auth from CI, findings uploaded as build artifacts),
adapted to AWS services.

## What it checks

| Script | Checks |
|---|---|
| `01_mfa_audit.sh` | IAM users with console access but no MFA enrolled |
| `02_access_key_age_audit.sh` | IAM access keys older than `STALE_DAYS` (default 90) |
| `03_privileged_iam_audit.sh` | Users/roles/groups with `AdministratorAccess` or wildcard (`Action:*`/`Resource:*`) policies |
| `04_public_s3_audit.sh` | S3 buckets exposed via ACL, bucket policy, or disabled Block Public Access |
| `05_public_security_group_audit.sh` | Security groups open to `0.0.0.0/0` / `::/0`, flagging sensitive ports (SSH, RDP, DB engines) |
| `06_public_rds_audit.sh` | Publicly accessible RDS instances and publicly shared snapshots |
| `07_public_ami_snapshot_audit.sh` | Public AMIs and public EBS snapshots |
| `08_stale_resources_audit.sh` | **The "hasn't been used in 90 days" check** — inactive IAM users/roles, unattached EBS volumes, unassociated Elastic IPs, long-stopped EC2 instances |
| `09_cloudtrail_suspicious_audit.sh` | Privilege-escalation-shaped events, root account usage, anti-forensics activity (disabled logging, deleted trails) in the last `LOOKBACK_HOURS` |
| `10_securityhub_guardduty_audit.sh` | Aggregates active CRITICAL/HIGH Security Hub and GuardDuty findings across regions |

Each script prints `ISSUE: ...` lines for anything actionable, or a `No
issues found` line if clean. The GitHub Actions workflow captures each
script's output to `findings/<script-name>.txt`, uploads them as a build
artifact (90-day retention), and fails the job if any file contains an
`ISSUE` line.

## Setup

### 1. AWS side (already done for this account)

- OIDC identity provider for `token.actions.githubusercontent.com` added in IAM.
- IAM role `github-actions-aws-security-audit` trusted only for
  `repo:jchan023@7191761/aws-security@1329980626:*` (GitHub's newer OIDC
  claim format embeds immutable owner/repo IDs after each name, e.g.
  `owner@ownerId/repo@repoId`, to prevent takeover via repo
  rename/transfer — decode a token's `sub` claim in CI to see this if
  you ever need to re-verify it), with the AWS managed `SecurityAudit`
  policy attached (read-only across IAM, S3, EC2, RDS, CloudTrail,
  GuardDuty, Security Hub, etc. — no write access).
- Role ARN is referenced directly in
  `.github/workflows/aws-security-audit.yml` (`role-to-assume`). No AWS
  access keys are stored anywhere.

### 2. Push this repo to GitHub

```bash
git init
git add .
git commit -m "Initial AWS security audit toolkit"
git branch -M main
git remote add origin https://github.com/jchan023/aws-security.git
git push -u origin main
```

### 3. Run it

- It runs automatically every day at 14:00 UTC.
- Or trigger it manually: GitHub repo → **Actions** tab → **AWS Security
  Audit** workflow → **Run workflow**.

## Running locally

Requires the AWS CLI (configured with credentials for the target account)
and `jq`.

```bash
chmod +x scripts/*.sh
STALE_DAYS=90 LOOKBACK_HOURS=24 bash scripts/08_stale_resources_audit.sh
```

Or run everything:

```bash
mkdir -p findings
for script in scripts/[0-9]*.sh; do
  bash "$script" | tee "findings/$(basename "$script" .sh).txt"
done
```

## Notes

- `05_public_security_group_audit.sh`, `06`–`07`, and `08` (partially) loop
  over **every enabled AWS region** — this can take a few minutes on an
  account with many regions enabled. Consider narrowing to specific
  regions via an env var if that becomes slow.
- `10_securityhub_guardduty_audit.sh` only reports findings in regions
  where Security Hub / GuardDuty are enabled; it notes (not flags) regions
  where they're off, since enabling them account/org-wide is a separate
  decision.
- The `SecurityAudit` managed policy is intentionally broad-but-read-only.
  If you want to scope it down further, most checks above only need IAM,
  S3, EC2, RDS, CloudTrail, GuardDuty, and Security Hub read permissions.
