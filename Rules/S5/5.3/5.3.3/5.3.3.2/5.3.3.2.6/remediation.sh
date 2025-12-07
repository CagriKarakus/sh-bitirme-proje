#!/bin/bash

# Enable dictionary check
echo "Enabling dictionary check..."

# Remove dictcheck = 0 if present
sed -i '/^dictcheck\s*=\s*0/d' /etc/security/pwquality.conf

# Ensure dictcheck is enabled
if ! grep -qi '^dictcheck\s*=' /etc/security/pwquality.conf 2>/dev/null; then
    echo "dictcheck = 1" >> /etc/security/pwquality.conf
fi

echo "SUCCESS: dictcheck enabled"
