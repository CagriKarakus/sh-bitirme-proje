#!/bin/bash

set -euo pipefail

[[ $EUID -ne 0 ]] && { echo "ERROR: Run as root"; exit 1; }

# Install utils if needed
command -v aa-enforce >/dev/null 2>&1 || apt-get install -y apparmor-utils >/dev/null 2>&1

# Start service
systemctl is-active --quiet apparmor || systemctl start apparmor
systemctl enable apparmor >/dev/null 2>&1

# Set all profiles to enforce mode
echo "Setting profiles to enforce mode..."
aa-enforce /etc/apparmor.d/* 2>&1 | grep -v "Warning" || true

# Reload
systemctl reload apparmor

# Check for unconfined
unconfined=$(apparmor_status | grep "processes are unconfined but have a profile defined" | awk '{print $1}' || echo "0")

if [[ "$unconfined" -gt 0 ]]; then
    echo "⚠ WARNING: $unconfined unconfined processes - restart required"
    apparmor_status | grep -A 20 "processes are unconfined" | grep "^   " || true
else
    echo "✓ All processes confined"
fi

echo "✓ Remediation completed"