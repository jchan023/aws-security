#!/usr/bin/env bash
# Shared helpers sourced by every audit script.

STALE_DAYS="${STALE_DAYS:-90}"
LOOKBACK_HOURS="${LOOKBACK_HOURS:-24}"

# Regions to scan for the region-looping checks (05, 06, 07, 08, 10, 11).
# Defaults to just AWS_DEFAULT_REGION (a single-region account has no
# reason to pay the time cost of scanning all ~17 enabled regions for
# resources that will never exist there). Set AWS_REGIONS to a
# space-separated list to widen it, e.g. "us-east-1 us-west-2".
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
