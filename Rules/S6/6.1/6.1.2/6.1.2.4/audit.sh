#!/bin/bash

# 6.1.2.4 Ensure journald Storage is configured (Automated)

echo "Checking journald Storage configuration..."

# Check Storage setting
storage=$(grep -E "^Storage=" /etc/systemd/journald.conf 2>/dev/null)

echo "Storage: ${storage:-Not configured (default: auto)}"

if [ -n "$storage" ]; then
    if echo "$storage" | grep -Eqi "persistent|auto"; then
        echo "PASS: Storage is configured to persistent or auto"
        exit 0
    else
        echo "FAIL: Storage is not configured to persistent or auto"
        exit 1
    fi
else
    echo "WARNING: Storage is not explicitly configured (default: auto)"
    echo "Consider setting Storage=persistent for persistent logging"
    exit 1
fi
