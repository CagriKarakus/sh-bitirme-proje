#!/bin/bash

set -euo pipefail

if ! command -v apparmor_status >/dev/null 2>&1; then
    echo "ERROR: apparmor_status not found"
    exit 1
fi

if ! systemctl is-active --quiet apparmor 2>/dev/null; then
    echo "ERROR: AppArmor not running"
    exit 1
fi

fail=0

# Profiles kontrolü
loaded=$(apparmor_status | grep "profiles are loaded" | awk '{print $1}' || echo "0")
[[ "$loaded" -eq 0 ]] && { echo "FAIL: No profiles loaded"; fail=1; } || echo "PASS: $loaded profiles loaded"

# Unconfined kontrolü
unconfined=$(apparmor_status | grep "processes are unconfined but have a profile defined" | awk '{print $1}' || echo "0")
[[ "$unconfined" -gt 0 ]] && { echo "FAIL: $unconfined unconfined processes"; fail=1; } || echo "PASS: No unconfined processes"

[[ $fail -eq 0 ]] && { echo "AUDIT PASSED"; exit 0; } || { echo "AUDIT FAILED"; exit 1; }