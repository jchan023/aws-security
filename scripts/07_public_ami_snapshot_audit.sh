#!/usr/bin/env bash
# Flags AMIs and EBS snapshots owned by this account that are shared publicly.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

echo "=== Public AMI / EBS Snapshot Audit ==="
found=0

regions="$(regions_to_scan)"
account_id="$(aws sts get-caller-identity --query 'Account' --output text)"

for region in $regions; do
  public_amis="$(aws ec2 describe-images --region "$region" --owners "$account_id" \
    --query "Images[?Public==\`true\`].ImageId" --output text 2>/dev/null)"
  for ami in $public_amis; do
    echo "ISSUE [$region]: AMI '$ami' is public"
    found=1
  done

  public_snaps="$(aws ec2 describe-snapshots --region "$region" --owner-ids "$account_id" \
    --query "Snapshots[].SnapshotId" --output text 2>/dev/null)"
  for snap in $public_snaps; do
    perm="$(aws ec2 describe-snapshot-attribute --region "$region" --snapshot-id "$snap" \
      --attribute createVolumePermission --query 'CreateVolumePermissions' --output text 2>/dev/null)"
    if echo "$perm" | grep -qw "all"; then
      echo "ISSUE [$region]: EBS snapshot '$snap' is public"
      found=1
    fi
  done
done

if [[ "$found" -eq 0 ]]; then
  echo "No issues found: no public AMIs or EBS snapshots."
fi
