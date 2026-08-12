#!/usr/bin/env bash
# Flags publicly accessible RDS instances and public RDS/manual snapshots.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

echo "=== Public RDS Audit ==="
found=0

regions="$(regions_to_scan)"

for region in $regions; do
  public_instances="$(aws rds describe-db-instances --region "$region" \
    --query "DBInstances[?PubliclyAccessible==\`true\`].DBInstanceIdentifier" --output text 2>/dev/null)"
  for db in $public_instances; do
    echo "ISSUE [$region]: RDS instance '$db' is PubliclyAccessible=true"
    found=1
  done

  snapshots="$(aws rds describe-db-snapshots --region "$region" --snapshot-type manual \
    --query 'DBSnapshots[].DBSnapshotIdentifier' --output text 2>/dev/null)"
  for snap in $snapshots; do
    attrs="$(aws rds describe-db-snapshot-attributes --region "$region" --db-snapshot-identifier "$snap" \
      --query "DBSnapshotAttributesResult.DBSnapshotAttributes[?AttributeName=='restore'].AttributeValues" --output text 2>/dev/null)"
    if echo "$attrs" | grep -qw "all"; then
      echo "ISSUE [$region]: RDS snapshot '$snap' is shared publicly (restore: all)"
      found=1
    fi
  done
done

if [[ "$found" -eq 0 ]]; then
  echo "No issues found: no publicly exposed RDS instances or snapshots."
fi
