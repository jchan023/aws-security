#!/usr/bin/env bash
# Flags S3 buckets that are publicly accessible via ACL, bucket policy,
# or that have Block Public Access disabled.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

echo "=== Public S3 Bucket Audit ==="
found=0

buckets="$(aws s3api list-buckets --query 'Buckets[].Name' --output text)"

for bucket in $buckets; do
  status="$(aws s3api get-bucket-policy-status --bucket "$bucket" --query 'PolicyStatus.IsPublic' --output text 2>/dev/null)"
  if [[ "$status" == "True" ]]; then
    echo "ISSUE: bucket '$bucket' has a bucket policy that grants public access"
    found=1
  fi

  acl_public="$(aws s3api get-bucket-acl --bucket "$bucket" --query "Grants[?Grantee.URI=='http://acs.amazonaws.com/groups/global/AllUsers' || Grantee.URI=='http://acs.amazonaws.com/groups/global/AuthenticatedUsers']" --output text 2>/dev/null)"
  if [[ -n "$acl_public" ]]; then
    echo "ISSUE: bucket '$bucket' has an ACL grant to AllUsers/AuthenticatedUsers"
    found=1
  fi

  pab="$(aws s3api get-public-access-block --bucket "$bucket" --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null)"
  if [[ -z "$pab" ]]; then
    echo "ISSUE: bucket '$bucket' has NO Public Access Block configuration set"
    found=1
  else
    all_blocked="$(echo "$pab" | jq -e '.BlockPublicAcls and .IgnorePublicAcls and .BlockPublicPolicy and .RestrictPublicBuckets' >/dev/null 2>&1 && echo yes || echo no)"
    if [[ "$all_blocked" == "no" ]]; then
      echo "ISSUE: bucket '$bucket' has Public Access Block only partially enabled: $pab"
      found=1
    fi
  fi
done

if [[ "$found" -eq 0 ]]; then
  echo "No issues found: no publicly exposed S3 buckets."
fi
