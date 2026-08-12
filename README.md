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
| `11_account_baseline_audit.sh` | **Account-level security baseline drift** — IAM password policy, S3 account-wide Block Public Access, EBS encryption by default, multi-region CloudTrail with log file validation, AWS Config recording |

Each script prints `ISSUE: ...` lines for anything actionable, or a `No
issues found` line if clean. The GitHub Actions workflow captures each
script's output to `findings/<script-name>.txt`, uploads them as a build
artifact (90-day retention), and emails a categorized findings summary every
run (see below) — so new findings and drift show up without anyone having
to remember to check.

The run's pass/fail status reflects whether it actually *ran* — not whether
anything was found. Findings are expected (e.g. this account's admin user
legitimately having `AdministratorAccess`), and are already surfaced via
email; a green run means the audits executed and the email sent, a red run
means one of those two things failed to happen.

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

Every run also emails a categorized findings summary so a run and its
results are visible without opening GitHub. The body is split into four
sections:

- **New Findings** — `ISSUE:` lines not seen in any prior run
- **Existing Findings** — `ISSUE:` lines seen before, with the date first
  observed
- **Drift** — [`11_account_baseline_audit.sh`](scripts/11_account_baseline_audit.sh)'s
  output specifically (account-level security settings, shown as-is every
  run rather than new/existing-tracked, same as `gcp-security`'s
  `org_policy_audit.sh` handling — this is ongoing configuration posture,
  not a one-off event, so you want to see it every day it's still true, not
  just once)
- **All Clear** — checks that came back clean

New-vs-existing tracking needs a history file that survives across runs.
That can't be committed to the repo (findings history — account IDs,
resource names, misconfiguration details — would then be public, since this
repo is), so it's kept in a [GitHub Actions
cache](https://docs.github.com/actions/writing-workflows/choosing-what-your-workflow-does/caching-dependencies-to-speed-up-workflows)
instead ([`.github/scripts/build_email_report.py`](.github/scripts/build_email_report.py)
builds it). A finding that disappears and later comes back is treated as
new again, not resurrected with its old first-seen date. Only `ISSUE`
lines are tracked (both the `ISSUE: ...` and `ISSUE [region]: ...` formats
scripts use) — header lines (`=== ... ===`), section dividers
(`--- ... ---`), and informational `NOTE:` lines (e.g. a region where
GuardDuty/Security Hub isn't enabled) are filtered out, so they don't show
up as permanent phantom findings.

Set these two repo secrets to enable the email step (GitHub repo →
**Settings** → **Secrets and variables** → **Actions** → **New repository
secret**):

- `MAIL_USERNAME` — a Gmail address to send from
- `MAIL_PASSWORD` — a Gmail [App
  Password](https://myaccount.google.com/apppasswords) for that address, **not**
  the account password (Google requires 2-Step Verification to be enabled to
  generate one)

The recipient address is hardcoded to `jchan023@gmail.com` in the workflow —
change it there if needed. Unlike findings (which no longer fail the run),
a failed email send **does** fail the job — that's the point of emailing
findings at all, so it needs to be a real failure signal.

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

- Region scoping is intentionally split into two groups, because "skip a
  region" means something different for each:
  - `05_public_security_group_audit.sh`, `06`–`07`, and `08` (partially) —
    security groups, RDS, AMIs/snapshots, stale resources — look for
    *actual resources*, so they always scan **every enabled AWS region**
    via `aws ec2 describe-regions` directly, unconditionally. Skipping a
    region here would mean silently missing a real misconfigured resource
    the moment you deploy somewhere new. They're already cheap and silent
    when a region has nothing in it, so full coverage costs nothing extra.
  - `10_securityhub_guardduty_audit.sh` and `11_account_baseline_audit.sh`
    (EBS encryption + AWS Config) check *account/region settings*, not
    resources — every enabled region always reports some status regardless
    of whether you use it, so scanning all ~17 is pure noise. These two use
    `regions_to_scan()` in `scripts/lib.sh`, which defaults to just
    `AWS_DEFAULT_REGION`. Set `AWS_REGIONS` to a space-separated list (e.g.
    `"us-east-1 us-west-2"`) to widen it once you operate in more than one
    region — these are still free read-only calls, so widening costs
    nothing but time.
- `10_securityhub_guardduty_audit.sh` only reports findings in regions
  where Security Hub / GuardDuty are enabled; it notes (not flags) regions
  where they're off, since enabling them account/org-wide is a separate
  decision.
- The `SecurityAudit` managed policy is intentionally broad-but-read-only.
  If you want to scope it down further, most checks above only need IAM,
  S3, EC2, RDS, CloudTrail, GuardDuty, and Security Hub read permissions.
- The workflow's "Run audit scripts" step runs with `set -euo pipefail`, so
  a genuine bug in one script (not just findings — those always exit 0)
  aborts the remaining scripts for that run rather than silently
  continuing. The email/artifact still reflect whatever ran before the
  failure; the next day's run isn't affected.
