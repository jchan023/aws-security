#!/usr/bin/env python3
"""
Builds the categorized findings email body: New Findings, Existing Findings
(with first-seen date), Drift, Accepted Risk, All Clear.

"Drift" is 11_account_baseline_audit.txt specifically (account-level
security baseline settings - password policy, S3 account Block Public
Access, EBS default encryption, CloudTrail, AWS Config) - ongoing
configuration posture, shown as-is every run rather than new/existing
tracked, same as gcp-security's org_policy_audit.sh handling. Every other
findings/*.txt file with real findings has each line tracked individually
in a history file (restored/saved via GitHub Actions cache across runs,
since this repo is public and a committed history would leak account IDs,
resource names, and misconfiguration details - see README) so a finding
that's been open for a week doesn't get re-announced as new every single
day.

"Accepted Risk" is for findings that are real but deliberately not
actionable right now - e.g. a Security Hub control recommending Inspector
scanning for a resource type (EC2/ECR/Lambda) this account doesn't use yet.
Rather than silently deleting these or letting them pollute New/Existing
forever, accepted-findings.json (repo root, committed - these are
deliberate, reviewable decisions, unlike the gitignored history cache)
lists them explicitly with a reason, and they get their own always-visible
section instead of being treated as unresolved. A finding only counts as
accepted if BOTH check names match, and the entry's substring is found in
the string - so tightening or renaming a check's message won't silently
resurrect (or silently keep suppressing) something without a human
noticing when they next add an entry.

Only lines starting with "ISSUE" are treated as trackable findings - the
audit scripts also print header lines ("=== ... ==="), section dividers
("--- ... ---"), and informational "NOTE:" lines (e.g. a region where
GuardDuty/Security Hub isn't enabled) that aren't actionable and would
otherwise show up as permanent phantom "findings" in every run. The prefix
check is "ISSUE" without a trailing colon on purpose - scripts use both
"ISSUE: <text>" and "ISSUE [region]: <text>" (region-scoped checks put the
region before the colon), and requiring "ISSUE:" specifically silently
dropped every region-tagged finding from the email.

A findings/*.txt file with zero ISSUE lines counts as All Clear for that
check, regardless of how many NOTE/header lines it has. A file whose
issues are ALL accepted does NOT count as All Clear - it genuinely has
findings, they're just deliberately deprioritized, and conflating the two
would hide that a decision was made at all.
"""
import json
import os
from datetime import date

FINDINGS_DIR = "findings"
HISTORY_PATH = ".findings-history/history.json"
ACCEPTED_PATH = "accepted-findings.json"
DRIFT_FILE = "11_account_baseline_audit.txt"

TODAY = date.today().isoformat()


def load_history():
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH) as f:
            return json.load(f)
    return {}


def save_history(history):
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
    with open(HISTORY_PATH, "w") as f:
        json.dump(history, f, indent=2, sort_keys=True)


def load_accepted():
    if os.path.exists(ACCEPTED_PATH):
        with open(ACCEPTED_PATH) as f:
            return json.load(f)
    return []


def find_acceptance(accepted, check, line):
    for entry in accepted:
        if entry.get("check") == check and entry.get("match", "") in line:
            return entry
    return None


def section(title, items):
    if not items:
        return f"{title}\n(none)\n"
    body = "\n".join(f"- {i}" for i in items)
    return f"{title}\n{body}\n"


def main():
    history = load_history()
    accepted = load_accepted()
    new_items, existing_items, drift_items, accepted_items, clear_items = [], [], [], [], []
    seen_keys = set()

    for fname in sorted(os.listdir(FINDINGS_DIR)):
        if not fname.endswith(".txt"):
            continue
        check = fname[:-4]
        with open(os.path.join(FINDINGS_DIR, fname)) as f:
            content = f.read().strip()
        if not content:
            continue

        issues = [line for line in content.splitlines() if line.startswith("ISSUE")]

        if not issues:
            clear_items.append(f"{check}: No issues found")
            continue

        for line in issues:
            acceptance = find_acceptance(accepted, check, line)
            if acceptance:
                accepted_items.append(f"{check}: {line}  (accepted {acceptance.get('accepted_date', '?')}: {acceptance['reason']})")
                continue

            if fname == DRIFT_FILE:
                drift_items.append(f"{check}: {line}")
                continue

            key = f"{check}|{line}"
            seen_keys.add(key)
            if key in history:
                existing_items.append(f"{check}: {line}  (first seen {history[key]})")
            else:
                history[key] = TODAY
                new_items.append(f"{check}: {line}")

    # Drop history entries for findings that no longer appear at all - if
    # one comes back later it correctly shows as new again, rather than
    # resurrecting a stale first-seen date.
    history = {k: v for k, v in history.items() if k in seen_keys}
    save_history(history)

    report = "\n".join([
        section("New Findings", new_items),
        section("Existing Findings", existing_items),
        section("Drift", drift_items),
        section("Accepted Risk", accepted_items),
        section("All Clear", clear_items),
    ])
    print(report)

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as f:
            f.write(f"new_count={len(new_items)}\n")
            f.write(f"existing_count={len(existing_items)}\n")
            f.write(f"drift_count={len(drift_items)}\n")
            f.write(f"accepted_count={len(accepted_items)}\n")


if __name__ == "__main__":
    main()
