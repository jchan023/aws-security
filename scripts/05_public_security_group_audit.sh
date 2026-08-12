#!/usr/bin/env bash
# Flags security groups with ingress rules open to 0.0.0.0/0 or ::/0,
# especially on sensitive ports (SSH, RDP, DB engines) — the AWS analogue
# of the GCP firewall-rule audit.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

echo "=== Public Security Group Audit ==="
found=0

sensitive_ports="22 3389 3306 5432 1433 27017 6379 9200 5984 11211"

regions="$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)"

for region in $regions; do
  sgs_json="$(aws ec2 describe-security-groups --region "$region" --query 'SecurityGroups' --output json 2>/dev/null)"
  count="$(echo "$sgs_json" | jq 'length')"
  [[ "$count" -eq 0 ]] && continue

  for i in $(seq 0 $((count - 1))); do
    sg_id="$(echo "$sgs_json" | jq -r ".[$i].GroupId")"
    sg_name="$(echo "$sgs_json" | jq -r ".[$i].GroupName")"
    open_rules="$(echo "$sgs_json" | jq -c ".[$i].IpPermissions[] | select((.IpRanges[]?.CidrIp==\"0.0.0.0/0\") or (.Ipv6Ranges[]?.CidrIpv6==\"::/0\"))")"
    [[ -z "$open_rules" ]] && continue

    while IFS= read -r rule; do
      [[ -z "$rule" ]] && continue
      from_port="$(echo "$rule" | jq -r '.FromPort // "all"')"
      to_port="$(echo "$rule" | jq -r '.ToPort // "all"')"
      proto="$(echo "$rule" | jq -r '.IpProtocol')"

      is_sensitive="no"
      if [[ "$from_port" == "all" ]]; then
        is_sensitive="yes (all ports open)"
      else
        for p in $sensitive_ports; do
          if [[ "$p" -ge "$from_port" && "$p" -le "$to_port" ]]; then
            is_sensitive="yes (port $p)"
            break
          fi
        done
      fi

      if [[ "$is_sensitive" != "no" ]]; then
        echo "ISSUE [$region]: SG '$sg_name' ($sg_id) open to internet on $proto $from_port-$to_port — $is_sensitive"
        found=1
      else
        echo "ISSUE [$region]: SG '$sg_name' ($sg_id) open to internet on $proto $from_port-$to_port"
        found=1
      fi
    done <<< "$open_rules"
  done
done

if [[ "$found" -eq 0 ]]; then
  echo "No issues found: no security groups open to the internet."
fi
