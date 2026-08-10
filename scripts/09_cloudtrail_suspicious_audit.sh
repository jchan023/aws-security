#!/usr/bin/env bash
# Scans CloudTrail for the last LOOKBACK_HOURS for privilege-escalation-shaped
# events, root account usage, and anti-forensics activity (disabling logging,
# deleting trails) — the AWS analogue of the GCP audit-log review script.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

echo "=== CloudTrail Suspicious Activity Audit: last ${LOOKBACK_HOURS}h ==="
found=0

start_time="$(date -u -d "-${LOOKBACK_HOURS} hours" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-"${LOOKBACK_HOURS}"H +%Y-%m-%dT%H:%M:%SZ)"

watch_events="AttachUserPolicy AttachRolePolicy AttachGroupPolicy PutUserPolicy PutRolePolicy PutGroupPolicy CreateAccessKey CreateLoginProfile UpdateLoginProfile CreatePolicyVersion SetDefaultPolicyVersion StopLogging DeleteTrail UpdateTrail PutEventSelectors DeleteFlowLogs DisableSecurityHub DeleteDetector ConsoleLogin"

for event_name in $watch_events; do
  events="$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$event_name" \
    --start-time "$start_time" \
    --query 'Events[].[EventTime,Username,EventName,EventId]' --output text 2>/dev/null)"
  [[ -z "$events" ]] && continue

  while IFS=$'\t' read -r event_time username event_id_or_name maybe_id; do
    [[ -z "$event_time" ]] && continue
    echo "ISSUE: [$event_time] '$event_name' called by '$username' (event: $event_id_or_name $maybe_id)"
    found=1
  done <<< "$events"
done

# Root account usage is always worth a flag regardless of what it did.
root_events="$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --start-time "$start_time" \
  --query 'Events[].[EventTime,EventName]' --output text 2>/dev/null)"
if [[ -n "$root_events" ]]; then
  while IFS=$'\t' read -r event_time event_name; do
    [[ -z "$event_time" ]] && continue
    echo "ISSUE: [$event_time] ROOT account activity: '$event_name'"
    found=1
  done <<< "$root_events"
fi

if [[ "$found" -eq 0 ]]; then
  echo "No issues found: no suspicious CloudTrail activity in the lookback window."
fi
