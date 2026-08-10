#!/usr/bin/env bash
# Flags IAM users/roles/groups with AdministratorAccess or wildcard ("*"/"*")
# managed or inline policies attached — the AWS analogue of the GCP
# Owner/Editor primitive-role check.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

echo "=== Privileged IAM Audit: admin / wildcard policy grants ==="
found=0

check_wildcard_inline() {
  local entity_type="$1" entity_name="$2"
  local policy_names
  policy_names="$(aws iam "list-${entity_type}-policies" --"${entity_type}"-name "$entity_name" --query 'PolicyNames' --output text 2>/dev/null)"
  for pname in $policy_names; do
    doc="$(aws iam "get-${entity_type}-policy" --"${entity_type}"-name "$entity_name" --policy-name "$pname" --query 'PolicyDocument' --output json 2>/dev/null)"
    if echo "$doc" | jq -e '.Statement[] | select(.Effect=="Allow") | select((.Action=="*" or (.Action[]?=="*")) and (.Resource=="*" or (.Resource[]?=="*")))' >/dev/null 2>&1; then
      echo "ISSUE: $entity_type '$entity_name' has inline policy '$pname' granting Action:* Resource:*"
      found=1
    fi
  done
}

for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
  attached="$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyName' --output text)"
  if echo "$attached" | grep -qw "AdministratorAccess"; then
    echo "ISSUE: user '$user' has AdministratorAccess attached directly"
    found=1
  fi
  check_wildcard_inline "user" "$user"
done

for role in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  # Skip AWS service-linked roles — not user-manageable.
  [[ "$role" == AWSServiceRoleFor* ]] && continue
  attached="$(aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyName' --output text)"
  if echo "$attached" | grep -qw "AdministratorAccess"; then
    echo "ISSUE: role '$role' has AdministratorAccess attached directly"
    found=1
  fi
  check_wildcard_inline "role" "$role"
done

for group in $(aws iam list-groups --query 'Groups[].GroupName' --output text); do
  attached="$(aws iam list-attached-group-policies --group-name "$group" --query 'AttachedPolicies[].PolicyName' --output text)"
  if echo "$attached" | grep -qw "AdministratorAccess"; then
    echo "ISSUE: group '$group' has AdministratorAccess attached directly"
    found=1
  fi
  check_wildcard_inline "group" "$group"
done

if [[ "$found" -eq 0 ]]; then
  echo "No issues found: no admin/wildcard policy grants detected."
fi
