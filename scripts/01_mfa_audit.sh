#!/usr/bin/env bash
# Flags IAM users with console/password access but no MFA device enrolled.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

echo "=== MFA Audit: IAM users without MFA ==="

users="$(aws iam list-users --query 'Users[].UserName' --output text)"
found=0

for user in $users; do
  # Skip users with no console login (access-key-only service accounts don't need MFA the same way).
  login_profile="$(aws iam get-login-profile --user-name "$user" 2>/dev/null)"
  [[ -z "$login_profile" ]] && continue

  mfa_devices="$(aws iam list-mfa-devices --user-name "$user" --query 'MFADevices' --output text)"
  if [[ -z "$mfa_devices" ]]; then
    echo "ISSUE: user '$user' has console access but NO MFA device enrolled"
    found=1
  fi
done

if [[ "$found" -eq 0 ]]; then
  echo "No issues found: all console users have MFA enrolled."
fi
