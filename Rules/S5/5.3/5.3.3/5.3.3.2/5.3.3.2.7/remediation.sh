#!/bin/bash

# Enable password quality enforcement
echo "Enabling password quality enforcement..."

# Remove enforcing = 0 if present
sed -i '/^enforcing\s*=\s*0/d' /etc/security/pwquality.conf

# Ensure enforcing is enabled
if ! grep -qi '^enforcing\s*=' /etc/security/pwquality.conf 2>/dev/null; then
    echo "enforcing = 1" >> /etc/security/pwquality.conf
fi

echo "SUCCESS: Password quality enforcement enabled"
