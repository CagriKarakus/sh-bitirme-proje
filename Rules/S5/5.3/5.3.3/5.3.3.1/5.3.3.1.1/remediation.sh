#!/bin/bash

# Configure password failed attempts lockout
echo "Configuring password lockout..."

if grep -qi '^deny\s*=' /etc/security/faillock.conf 2>/dev/null; then
    sed -i 's/^deny\s*=.*/deny = 5/' /etc/security/faillock.conf
else
    echo "deny = 5" >> /etc/security/faillock.conf
fi

echo "SUCCESS: Password lockout set to 5 attempts"
