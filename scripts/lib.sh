#!/usr/bin/env bash
# Shared helpers sourced by every audit script.

STALE_DAYS="${STALE_DAYS:-90}"
LOOKBACK_HOURS="${LOOKBACK_HOURS:-24}"

# Regions to scan for the account/region-*setting* checks (10, 11) only -
# GuardDuty/Security Hub enablement, EBS encryption-by-default, AWS Config
# recording. These aren't resource lookups; every enabled region always
# reports some status regardless of whether you use it, so scanning all
# ~17 is pure noise, not safety - scoping to where you actually operate is
# a deliberate, safe choice. Defaults to just AWS_DEFAULT_REGION; set
# AWS_REGIONS to a space-separated list to widen it, e.g.
# "us-east-1 us-west-2".
#
# Deliberately NOT used by the resource-existence checks (05, 06, 07, 08 -
# security groups, RDS, AMIs/snapshots, stale resources): those scan every
# enabled region unconditionally via `aws ec2 describe-regions` directly,
# not this function, because silently skipping a region there means
# silently missing a real misconfigured resource if you ever deploy
# somewhere new. They're already cheap/silent when a region is empty, so
# there's no noise cost to full coverage - only a safety cost to narrowing
# it.
regions_to_scan() {
  if [[ -n "${AWS_REGIONS:-}" ]]; then
    echo "$AWS_REGIONS"
  else
    echo "${AWS_DEFAULT_REGION:-us-east-1}"
  fi
}

# Portable "days ago" epoch seconds (works on both GNU date and BSD/macOS date).
days_ago_epoch() {
  local days="$1"
  if date -d "-${days} days" +%s >/dev/null 2>&1; then
    date -d "-${days} days" +%s
  else
    date -v-"${days}"d +%s
  fi
}

to_epoch() {
  local ts="$1"
  if date -d "$ts" +%s >/dev/null 2>&1; then
    date -d "$ts" +%s
  else
    date -j -f "%Y-%m-%dT%H:%M:%S" "${ts%%.*}" +%s 2>/dev/null || echo 0
  fi
}
