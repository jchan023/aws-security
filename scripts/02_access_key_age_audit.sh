#!/usr/bin/env bash
# Flags IAM access keys older than STALE_DAYS (default 90) — the AWS analogue
# of the GCP toolkit's service-account key age check.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

echo "=== Access Key Age Audit: keys older than ${STALE_DAYS} days ==="

cutoff_epoch="$(days_ago_epoch "$STALE_DAYS")"
users="$(aws iam list-users --query 'Users[].UserName' --output text)"
found=0

for user in $users; do
  keys_json="$(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata' --output json)"
  count="$(echo "$keys_json" | jq 'length')"
  [[ "$count" -eq 0 ]] && continue

  for i in $(seq 0 $((count - 1))); do
    key_id="$(echo "$keys_json" | jq -r ".[$i].AccessKeyId")"
    status="$(echo "$keys_json" | jq -r ".[$i].Status")"
    created="$(echo "$keys_json" | jq -r ".[$i].CreateDate")"
    created_epoch="$(to_epoch "$created")"

    if [[ "$created_epoch" -lt "$cutoff_epoch" ]]; then
      age_days=$(( ( $(date +%s) - created_epoch ) / 86400 ))
      echo "ISSUE: user '$user' key '$key_id' (status: $status) is ${age_days} days old (created $created)"
      found=1
    fi
  done
done

if [[ "$found" -eq 0 ]]; then
  echo "No issues found: no access keys older than ${STALE_DAYS} days."
fi
