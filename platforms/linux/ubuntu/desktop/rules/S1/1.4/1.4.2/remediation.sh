#!/bin/bash

# 1.4.2 Ensure permissions on bootloader config are configured (Automated)
# Remediation: Set correct ownership and permissions on grub configuration file
# This sets owner:group to root:root and permissions to 0600 (rw-------)

echo "=== 1.4.2 Bootloader Config Permissions Remediation ==="
echo ""

# Variables
GRUB_CFG="/boot/grub/grub.cfg"

# Check if GRUB configuration file exists
if [ ! -f "$GRUB_CFG" ]; then
    echo "[ERROR] GRUB configuration file not found: $GRUB_CFG"
    echo "Note: GRUB2 may not be installed on your system or may be in a different location."
    exit 1
fi

echo "Current permissions:"
stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' "$GRUB_CFG"
echo ""

echo "Applying remediation..."
echo ""

# Set ownership to root:root
echo "1. Setting ownership to root:root..."
chown root:root "$GRUB_CFG"
if [ $? -eq 0 ]; then
    echo "   [OK] Ownership set successfully"
else
    echo "   [ERROR] Failed to set ownership"
    exit 1
fi

# Set permissions to 0600 (remove execute for user, remove all for group and others)
echo "2. Setting permissions to 0600..."
chmod u-x,go-rwx "$GRUB_CFG"
if [ $? -eq 0 ]; then
    echo "   [OK] Permissions set successfully"
else
    echo "   [ERROR] Failed to set permissions"
    exit 1
fi

echo ""
echo "New permissions:"
stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' "$GRUB_CFG"
echo ""
echo "[SUCCESS] Remediation completed successfully."
