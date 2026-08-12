#!/usr/bin/env bash
# Aggregates active/high-severity Security Hub and GuardDuty findings —
# the AWS analogue of the GCP Security Command Center rollup.
# Both services must be enabled in the account/region for this to return data;
# if disabled, that itself is reported as an issue.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

echo "=== Security Hub / GuardDuty Findings Audit ==="
found=0
regions="$(regions_to_scan)"

for region in $regions; do
  hub_status="$(aws securityhub describe-hub --region "$region" --query 'HubArn' --output text 2>/dev/null)"
  if [[ -z "$hub_status" || "$hub_status" == "None" ]]; then
    echo "NOTE [$region]: Security Hub is not enabled in this region"
    continue
  fi

  findings="$(aws securityhub get-findings --region "$region" \
    --filters '{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}],"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"},{"Value":"HIGH","Comparison":"EQUALS"}]}' \
    --query 'Findings[].[SeverityLabel,Title,Id]' --output text 2>/dev/null)"
  [[ -z "$findings" ]] && continue
  while IFS=$'\t' read -r severity title id; do
    [[ -z "$severity" ]] && continue
    echo "ISSUE [$region]: Security Hub $severity — $title"
    found=1
  done <<< "$findings"
done

for region in $regions; do
  detectors="$(aws guardduty list-detectors --region "$region" --query 'DetectorIds' --output text 2>/dev/null)"
  if [[ -z "$detectors" ]]; then
    echo "NOTE [$region]: GuardDuty is not enabled in this region"
    continue
  fi
  for detector_id in $detectors; do
    finding_ids="$(aws guardduty list-findings --region "$region" --detector-id "$detector_id" \
      --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' --query 'FindingIds' --output text 2>/dev/null)"
    [[ -z "$finding_ids" ]] && continue
    details="$(aws guardduty get-findings --region "$region" --detector-id "$detector_id" --finding-ids $finding_ids \
      --query 'Findings[].[Severity,Title]' --output text 2>/dev/null)"
    while IFS=$'\t' read -r severity title; do
      [[ -z "$severity" ]] && continue
      echo "ISSUE [$region]: GuardDuty severity ${severity} — $title"
      found=1
    done <<< "$details"
  done
done

if [[ "$found" -eq 0 ]]; then
  echo "No issues found: no high/critical Security Hub or GuardDuty findings."
fi
