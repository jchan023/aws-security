#!/usr/bin/env bash
# Flags account-level security baseline settings that aren't configured as
# recommended — ongoing configuration posture rather than a point-in-time
# resource finding. This is the AWS analogue of the GCP toolkit's
# org_policy_audit.sh (constraint drift), scoped to a single account since
# there's no AWS Organization / SCPs here to check instead. Each ISSUE line
# is self-contained with a short "why this matters" explanation, since
# these are one-off account settings rather than a uniform constraint list.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

echo "=== Account Baseline Audit: security-relevant account settings ==="
found=0

# --- IAM account password policy ---
policy_json="$(aws iam get-account-password-policy --query 'PasswordPolicy' --output json 2>/dev/null)"
if [[ -z "$policy_json" ]]; then
  echo "ISSUE: no IAM account password policy is set — console users can pick arbitrarily weak passwords with no rotation requirement"
  found=1
else
  min_len="$(echo "$policy_json" | jq -r '.MinimumPasswordLength // 0')"
  require_symbols="$(echo "$policy_json" | jq -r '.RequireSymbols // false')"
  require_numbers="$(echo "$policy_json" | jq -r '.RequireNumbers // false')"
  require_upper="$(echo "$policy_json" | jq -r '.RequireUppercaseCharacters // false')"
  require_lower="$(echo "$policy_json" | jq -r '.RequireLowercaseCharacters // false')"
  max_age="$(echo "$policy_json" | jq -r '.MaxPasswordAge // empty')"
  reuse_prevention="$(echo "$policy_json" | jq -r '.PasswordReusePrevention // 0')"

  [[ "$min_len" -lt 14 ]] && { echo "ISSUE: IAM password policy minimum length is ${min_len} (recommend 14+) — short passwords are easier to brute-force"; found=1; }
  [[ "$require_symbols" != "true" ]] && { echo "ISSUE: IAM password policy does not require symbols — reduces password entropy"; found=1; }
  [[ "$require_numbers" != "true" ]] && { echo "ISSUE: IAM password policy does not require numbers — reduces password entropy"; found=1; }
  [[ "$require_upper" != "true" ]] && { echo "ISSUE: IAM password policy does not require uppercase characters — reduces password entropy"; found=1; }
  [[ "$require_lower" != "true" ]] && { echo "ISSUE: IAM password policy does not require lowercase characters — reduces password entropy"; found=1; }
  [[ -z "$max_age" ]] && { echo "ISSUE: IAM password policy has no maximum password age — a leaked password stays valid forever"; found=1; }
  [[ "$reuse_prevention" -lt 4 ]] && { echo "ISSUE: IAM password policy allows password reuse (reuse prevention: ${reuse_prevention}, recommend 4+) — users can cycle back to a previously leaked password"; found=1; }
fi

# --- S3 account-level Block Public Access ---
account_id="$(aws sts get-caller-identity --query 'Account' --output text)"
pab_json="$(aws s3control get-public-access-block --account-id "$account_id" --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null)"
if [[ -z "$pab_json" ]]; then
  echo "ISSUE: no account-level S3 Block Public Access configuration — a single misconfigured bucket policy or ACL can expose data with no account-wide backstop"
  found=1
else
  all_blocked="$(echo "$pab_json" | jq -e '.BlockPublicAcls and .IgnorePublicAcls and .BlockPublicPolicy and .RestrictPublicBuckets' >/dev/null 2>&1 && echo yes || echo no)"
  if [[ "$all_blocked" == "no" ]]; then
    echo "ISSUE: account-level S3 Block Public Access is only partially enabled: $pab_json"
    found=1
  fi
fi

regions="$(regions_to_scan)"

# --- EBS encryption by default, per region ---
for region in $regions; do
  enc_default="$(aws ec2 get-ebs-encryption-by-default --region "$region" --query 'EbsEncryptionByDefault' --output text 2>/dev/null)"
  if [[ "$enc_default" == "False" ]]; then
    echo "ISSUE [$region]: EBS encryption by default is OFF — new volumes in this region are created unencrypted unless explicitly requested"
    found=1
  fi
done

# --- CloudTrail: at least one multi-region trail, logging, with log file validation ---
trails_json="$(aws cloudtrail describe-trails --query 'trailList[?IsMultiRegionTrail==`true`]' --output json 2>/dev/null)"
trail_count="$(echo "$trails_json" | jq 'length')"
if [[ "$trail_count" -eq 0 ]]; then
  echo "ISSUE: no multi-region CloudTrail trail found — activity in regions outside the trail's home region goes unlogged"
  found=1
else
  for i in $(seq 0 $((trail_count - 1))); do
    trail_name="$(echo "$trails_json" | jq -r ".[$i].Name")"
    trail_arn="$(echo "$trails_json" | jq -r ".[$i].TrailARN")"
    log_validation="$(echo "$trails_json" | jq -r ".[$i].LogFileValidationEnabled")"
    is_logging="$(aws cloudtrail get-trail-status --name "$trail_arn" --query 'IsLogging' --output text 2>/dev/null)"

    [[ "$log_validation" != "true" ]] && { echo "ISSUE: CloudTrail trail '$trail_name' has log file validation disabled — tampering with delivered log files wouldn't be detectable"; found=1; }
    [[ "$is_logging" != "True" ]] && { echo "ISSUE: CloudTrail trail '$trail_name' exists but is NOT currently logging"; found=1; }
  done
fi

# --- AWS Config recorder, per region ---
for region in $regions; do
  recorders_json="$(aws configservice describe-configuration-recorders --region "$region" --query 'ConfigurationRecorders' --output json 2>/dev/null)"
  recorder_count="$(echo "$recorders_json" | jq 'length' 2>/dev/null || echo 0)"
  if [[ "$recorder_count" -eq 0 ]]; then
    echo "ISSUE [$region]: AWS Config is not enabled — configuration changes to resources in this region aren't being recorded for later investigation"
    found=1
    continue
  fi
  status_json="$(aws configservice describe-configuration-recorder-status --region "$region" --query 'ConfigurationRecordersStatus[0].recording' --output text 2>/dev/null)"
  if [[ "$status_json" != "True" ]]; then
    echo "ISSUE [$region]: AWS Config recorder exists but is NOT currently recording"
    found=1
  fi
done

if [[ "$found" -eq 0 ]]; then
  echo "No issues found: account baseline settings all match recommendations."
fi
