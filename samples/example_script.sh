#!/usr/bin/env bash
###############################################################################
#
# Generated remediation bundle
#
# Source registry : rules\index.json
# Generated on    : 2025-11-26 17:15:44 UTC
# Rule count      : 2
#
# This script concatenates audit and remediation content for selected rules.
# Each rule block includes its audit instructions followed by remediation steps.
#
###############################################################################

###############################################################################
# BEGIN fix (1 / 2) for '1.1.3.1 Ensure var is a separate partition'
###############################################################################
(>&2 echo "Remediating rule 1/2: '1.1.3.1 Ensure var is a separate partition'")

# --- Audit ---
#!/bin/bash
if mountpoint -q /var; then
    echo "/var is a separate partition"
    exit 0
else
    echo "/var is NOT a separate partition"
    exit 1
fi

# --- Remediation ---
#!/bin/bash
echo "Manual intervention required: Create a separate partition for /var"

# END fix for '1.1.3.1 Ensure var is a separate partition'

###############################################################################
# BEGIN fix (2 / 2) for '1.1.3.2 Ensure nodev option set on var partition'
###############################################################################
(>&2 echo "Remediating rule 2/2: '1.1.3.2 Ensure nodev option set on var partition'")

# --- Audit ---
#!/bin/bash
if mount | grep " on /var " | grep -q "nodev"; then
    echo "nodev is set on /var"
    exit 0
else
    echo "nodev is NOT set on /var"
    exit 1
fi

# --- Remediation ---
#!/bin/bash
mount -o remount,nodev /var

# END fix for '1.1.3.2 Ensure nodev option set on var partition'


###############################################################################
# End of generated remediation bundle
###############################################################################
(>&2 echo "Completed rendering 2 rule block(s) from rules\index.json")
