#!/bin/bash

# 6.1.1.3 Ensure journald log file rotation is configured (Manual)

echo "Checking journald log file rotation configuration..."

# Check SystemMaxUse setting
max_use=$(grep -E "^SystemMaxUse=" /etc/systemd/journald.conf 2>/dev/null)
# Check SystemKeepFree setting
keep_free=$(grep -E "^SystemKeepFree=" /etc/systemd/journald.conf 2>/dev/null)
# Check RuntimeMaxUse setting
runtime_max=$(grep -E "^RuntimeMaxUse=" /etc/systemd/journald.conf 2>/dev/null)
# Check MaxFileSec setting
max_file_sec=$(grep -E "^MaxFileSec=" /etc/systemd/journald.conf 2>/dev/null)

echo "SystemMaxUse: ${max_use:-Not configured (using default)}"
echo "SystemKeepFree: ${keep_free:-Not configured (using default)}"
echo "RuntimeMaxUse: ${runtime_max:-Not configured (using default)}"
echo "MaxFileSec: ${max_file_sec:-Not configured (using default)}"

if [ -n "$max_use" ] || [ -n "$keep_free" ] || [ -n "$max_file_sec" ]; then
    echo "PASS: Log rotation settings are configured"
    exit 0
else
    echo "WARNING: No explicit log rotation settings found (using defaults)"
    echo "Review if defaults are appropriate for your environment"
    exit 1
fi
