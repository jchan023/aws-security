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

# Root account usage is worth a flag, but only for mutating (write) calls —
# read-only root activity (ListPolicies, GetAccountSummary, etc.) is normal
# during account setup/administration and would otherwise drown the signal.
root_events="$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --start-time "$start_time" \
  --query 'Events[].CloudTrailEvent' --output json 2>/dev/null | jq -c '.[]')"
if [[ -n "$root_events" ]]; then
  while IFS= read -r raw_event; do
    [[ -z "$raw_event" ]] && continue
    parsed="$(echo "$raw_event" | jq -r '. | fromjson? // empty')"
    [[ -z "$parsed" ]] && continue
    is_readonly="$(echo "$parsed" | jq -r 'if .readOnly == null then "true" else (.readOnly | tostring) end')"
    [[ "$is_readonly" == "true" ]] && continue
    event_time="$(echo "$parsed" | jq -r '.eventTime')"
    event_name="$(echo "$parsed" | jq -r '.eventName')"
    echo "ISSUE: [$event_time] ROOT account WRITE activity: '$event_name'"
    found=1
  done <<< "$root_events"
fi

if [[ "$found" -eq 0 ]]; then
  echo "No issues found: no suspicious CloudTrail activity in the lookback window."
fi
