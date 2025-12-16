#!/bin/bash
# CIS 1.3.1.4 Audit - Level 2 (ENFORCE ONLY)

set -euo pipefail

command -v apparmor_status >/dev/null 2>&1 || { echo "FAIL: apparmor_status not found"; exit 1; }
systemctl is-active --quiet apparmor 2>/dev/null || { echo "FAIL: AppArmor not running"; exit 1; }

fail=0

# Check profiles - MUST be enforce only (excluding snap profiles)
loaded=$(apparmor_status | grep "profiles are loaded" | awk '{print $1}' || echo "0")
enforce=$(apparmor_status | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
complain=$(apparmor_status | grep "profiles are in complain mode" | awk '{print $1}' || echo "0")

# Count non-snap profiles in complain mode
non_snap_complain=0
if [[ "$complain" -gt 0 ]]; then
    non_snap_complain=$(apparmor_status | sed -n '/profiles are in complain mode/,/profiles are in enforce mode/p' | grep "^   " | grep -v "snap\." | wc -l || echo "0")
fi

if [[ "$loaded" -eq 0 ]]; then
    echo "FAIL: No profiles loaded"
    fail=1
elif [[ "$non_snap_complain" -gt 0 ]]; then
    echo "FAIL: $non_snap_complain non-snap profiles in complain mode (Level 2 requires enforce only)"
    fail=1
else
    echo "PASS: All non-snap profiles in enforce mode (Total: $loaded loaded, $complain snap profiles in complain mode - ignored)"
fi

# Check unconfined
unconfined=$(apparmor_status | grep "processes are unconfined but have a profile defined" | awk '{print $1}' || echo "0")

if [[ "$unconfined" -gt 0 ]]; then
    echo "FAIL: $unconfined unconfined processes"
    fail=1
else
    echo "PASS: No unconfined processes"
fi

[[ $fail -eq 0 ]] && { echo "Level 2 PASS"; exit 0; } || { echo "Level 2 FAIL"; exit 1; }