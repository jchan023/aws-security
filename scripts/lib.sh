#!/usr/bin/env bash
# Shared helpers sourced by every audit script.

STALE_DAYS="${STALE_DAYS:-90}"
LOOKBACK_HOURS="${LOOKBACK_HOURS:-24}"

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
