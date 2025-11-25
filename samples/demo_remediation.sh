#!/usr/bin/env bash
###############################################################################
#
# Generated remediation bundle
#
# Source registry : rules/index.json
# Generated on    : 2025-11-25 11:22:46 UTC
# Rule count      : 3
#
# This script concatenates audit and remediation content for selected rules.
# Each rule block includes its audit instructions followed by remediation steps.
#
###############################################################################

###############################################################################
# BEGIN fix (1 / 3) for '1.1.3.1 Ensure var is a separate partition'
###############################################################################
(>&2 echo "Remediating rule 1/3: '1.1.3.1 Ensure var is a separate partition'")

# --- Audit ---
: <<'__AUDIT_1__'  # Audit transcript (not executed)
#!/bin/bash
if mountpoint -q /var; then
    echo "/var is a separate partition"
    exit 0
else
    echo "/var is NOT a separate partition"
    exit 1
fi
__AUDIT_1__
# --- Remediation ---
#!/bin/bash
echo "Manual intervention required: Create a separate partition for /var"

# END fix for '1.1.3.1 Ensure var is a separate partition'

###############################################################################
# BEGIN fix (2 / 3) for '1.1.3.2 Ensure nodev option set on var partition'
###############################################################################
(>&2 echo "Remediating rule 2/3: '1.1.3.2 Ensure nodev option set on var partition'")

# --- Audit ---
: <<'__AUDIT_2__'  # Audit transcript (not executed)
#!/bin/bash
if mount | grep " on /var " | grep -q "nodev"; then
    echo "nodev is set on /var"
    exit 0
else
    echo "nodev is NOT set on /var"
    exit 1
fi
__AUDIT_2__
# --- Remediation ---
#!/bin/bash
mount -o remount,nodev /var

# END fix for '1.1.3.2 Ensure nodev option set on var partition'

###############################################################################
# BEGIN fix (3 / 3) for '1.1.3.3 Ensure nosuid option set on var partition'
###############################################################################
(>&2 echo "Remediating rule 3/3: '1.1.3.3 Ensure nosuid option set on var partition'")

# --- Audit ---
: <<'__AUDIT_3__'  # Audit transcript (not executed)
#!/bin/bash
if mount | grep " on /var " | grep -q "nosuid"; then
    echo "nosuid is set on /var"
    exit 0
else
    echo "nosuid is NOT set on /var"
    exit 1
fi
__AUDIT_3__
# --- Remediation ---
#!/bin/bash
mount -o remount,nosuid /var

# END fix for '1.1.3.3 Ensure nosuid option set on var partition'


###############################################################################
# End of generated remediation bundle
###############################################################################
(>&2 echo "Completed rendering 3 rule block(s) from rules/index.json")
