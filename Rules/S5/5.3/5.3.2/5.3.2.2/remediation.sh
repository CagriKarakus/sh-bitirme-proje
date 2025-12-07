#!/bin/bash

# Enable pam_faillock module
echo "Enabling pam_faillock module..."

# Check if already enabled
if grep -q 'pam_faillock\.so' /etc/pam.d/common-auth 2>/dev/null; then
    echo "INFO: pam_faillock already enabled"
    grep pam_faillock /etc/pam.d/common-auth
    exit 0
fi

# Manual configuration (most reliable method)
echo "Configuring pam_faillock manually..."

# Backup files
cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak.$(date +%s)
cp /etc/pam.d/common-account /etc/pam.d/common-account.bak.$(date +%s)

# Create a temporary file with the new common-auth
cat > /tmp/pam_faillock_auth.tmp << 'EOF'
auth    required                        pam_faillock.so preauth
EOF

# Insert pam_faillock preauth before the first auth line
sed -i '0,/^auth/{s/^auth/auth    required                        pam_faillock.so preauth\n&/}' /etc/pam.d/common-auth

# Add authfail after pam_unix.so success line
sed -i '/pam_unix.so/a auth    [default=die]                   pam_faillock.so authfail' /etc/pam.d/common-auth

# Add authsucc at the end of auth section
sed -i '/pam_deny.so/i auth    sufficient                      pam_faillock.so authsucc' /etc/pam.d/common-auth

# Add to common-account if not present
if ! grep -q 'pam_faillock\.so' /etc/pam.d/common-account 2>/dev/null; then
    echo "account required                        pam_faillock.so" >> /etc/pam.d/common-account
fi

# Verify
if grep -q 'pam_faillock\.so' /etc/pam.d/common-auth; then
    echo "SUCCESS: pam_faillock module configured"
    echo ""
    echo "Configuration in common-auth:"
    grep pam_faillock /etc/pam.d/common-auth
else
    echo "FAIL: Could not configure pam_faillock"
    exit 1
fi
