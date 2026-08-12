#!/usr/bin/env bash
# The "hasn't been touched in 90 days" check: unused IAM identities,
# unattached EBS volumes, unassociated Elastic IPs, and long-stopped EC2
# instances. This is the AWS equivalent of a GCP "unused resource" sweep —
# nothing here is a misconfiguration, just cost/attack-surface you may
# not know you're still carrying.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

echo "=== Stale Resource Audit: unused for ${STALE_DAYS}+ days ==="
found=0
cutoff_epoch="$(days_ago_epoch "$STALE_DAYS")"
now_epoch="$(date +%s)"

# --- IAM users: no console login and no access-key use in STALE_DAYS ---
echo "--- IAM users with no activity ---"
cred_report_tmp="$(mktemp)"
aws iam generate-credential-report >/dev/null 2>&1 || true
for i in $(seq 1 10); do
  status="$(aws iam get-credential-report --query 'ReportFormat' --output text 2>/dev/null)"
  [[ "$status" == "text/csv" ]] && break
  sleep 2
done
aws iam get-credential-report --query 'Content' --output text 2>/dev/null | base64 --decode > "$cred_report_tmp" || true

if [[ -s "$cred_report_tmp" ]]; then
  while IFS=, read -r user arn user_creation_time password_enabled password_last_used rest; do
    [[ "$user" == "<root_account>" ]] && continue
    last_used_epoch=0
    if [[ "$password_last_used" != "N/A" && "$password_last_used" != "no_information" && -n "$password_last_used" ]]; then
      last_used_epoch="$(to_epoch "$password_last_used")"
    fi
    if [[ "$password_enabled" == "true" && "$last_used_epoch" -lt "$cutoff_epoch" ]]; then
      if [[ "$last_used_epoch" -eq 0 ]]; then
        echo "ISSUE: user '$user' has console access but has NEVER logged in"
      else
        days=$(( (now_epoch - last_used_epoch) / 86400 ))
        echo "ISSUE: user '$user' console login unused for ${days} days"
      fi
      found=1
    fi
  done < <(tail -n +2 "$cred_report_tmp")
fi
rm -f "$cred_report_tmp"

for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  keys="$(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[].AccessKeyId' --output text)"
  for key_id in $keys; do
    last_used="$(aws iam get-access-key-last-used --access-key-id "$key_id" --query 'AccessKeyLastUsed.LastUsedDate' --output text 2>/dev/null)"
    if [[ "$last_used" == "None" || -z "$last_used" ]]; then
      echo "ISSUE: user '$user' access key '$key_id' has NEVER been used"
      found=1
      continue
    fi
    last_used_epoch="$(to_epoch "$last_used")"
    if [[ "$last_used_epoch" -lt "$cutoff_epoch" ]]; then
      days=$(( (now_epoch - last_used_epoch) / 86400 ))
      echo "ISSUE: user '$user' access key '$key_id' unused for ${days} days"
      found=1
    fi
  done
done

# --- IAM roles: RoleLastUsed older than STALE_DAYS (excludes service-linked roles) ---
echo "--- IAM roles with no activity ---"
for role in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  [[ "$role" == AWSServiceRoleFor* ]] && continue
  last_used="$(aws iam get-role --role-name "$role" --query 'Role.RoleLastUsed.LastUsedDate' --output text 2>/dev/null)"
  if [[ "$last_used" == "None" || -z "$last_used" ]]; then
    echo "ISSUE: role '$role' has NEVER been assumed"
    found=1
    continue
  fi
  last_used_epoch="$(to_epoch "$last_used")"
  if [[ "$last_used_epoch" -lt "$cutoff_epoch" ]]; then
    days=$(( (now_epoch - last_used_epoch) / 86400 ))
    echo "ISSUE: role '$role' unused for ${days} days"
    found=1
  fi
done

regions="$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)"

# --- Unattached EBS volumes ---
echo "--- Unattached EBS volumes ---"
for region in $regions; do
  vols="$(aws ec2 describe-volumes --region "$region" --filters Name=status,Values=available \
    --query 'Volumes[].[VolumeId,CreateTime,Size]' --output text 2>/dev/null)"
  [[ -z "$vols" ]] && continue
  while IFS=$'\t' read -r vol_id create_time size; do
    [[ -z "$vol_id" ]] && continue
    created_epoch="$(to_epoch "$create_time")"
    if [[ "$created_epoch" -lt "$cutoff_epoch" ]]; then
      days=$(( (now_epoch - created_epoch) / 86400 ))
      echo "ISSUE [$region]: EBS volume '$vol_id' (${size}GB) unattached for ${days} days"
      found=1
    fi
  done <<< "$vols"
done

# --- Unassociated Elastic IPs ---
echo "--- Unassociated Elastic IPs ---"
for region in $regions; do
  eips="$(aws ec2 describe-addresses --region "$region" \
    --query 'Addresses[?AssociationId==`null`].[AllocationId,PublicIp]' --output text 2>/dev/null)"
  [[ -z "$eips" ]] && continue
  while IFS=$'\t' read -r alloc_id ip; do
    [[ -z "$alloc_id" ]] && continue
    echo "ISSUE [$region]: Elastic IP '$ip' ($alloc_id) is not associated with any resource (billed while idle)"
    found=1
  done <<< "$eips"
done

# --- EC2 instances stopped for a long time ---
echo "--- Long-stopped EC2 instances ---"
for region in $regions; do
  stopped="$(aws ec2 describe-instances --region "$region" --filters Name=instance-state-name,Values=stopped \
    --query 'Reservations[].Instances[].[InstanceId,StateTransitionReason]' --output text 2>/dev/null)"
  [[ -z "$stopped" ]] && continue
  while IFS=$'\t' read -r instance_id reason; do
    [[ -z "$instance_id" ]] && continue
    # StateTransitionReason looks like: "User initiated (2026-05-01 10:00:00 GMT)"
    date_str="$(echo "$reason" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}')"
    if [[ -n "$date_str" ]]; then
      stopped_epoch="$(to_epoch "$date_str")"
      if [[ "$stopped_epoch" -lt "$cutoff_epoch" ]]; then
        days=$(( (now_epoch - stopped_epoch) / 86400 ))
        echo "ISSUE [$region]: EC2 instance '$instance_id' has been stopped for ${days} days (still billed for attached EBS)"
        found=1
      fi
    fi
  done <<< "$stopped"
done

if [[ "$found" -eq 0 ]]; then
  echo "No issues found: no stale resources detected."
fi
