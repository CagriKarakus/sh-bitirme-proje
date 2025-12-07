#!/bin/bash

# Configure root account lockout
echo "Configuring root account lockout..."

# Add even_deny_root if not present
if ! grep -qi '^even_deny_root' /etc/security/faillock.conf 2>/dev/null; then
    echo "even_deny_root" >> /etc/security/faillock.conf
fi

# Configure root_unlock_time
if grep -qi '^root_unlock_time\s*=' /etc/security/faillock.conf 2>/dev/null; then
    sed -i 's/^root_unlock_time\s*=.*/root_unlock_time = 60/' /etc/security/faillock.conf
else
    echo "root_unlock_time = 60" >> /etc/security/faillock.conf
fi

echo "SUCCESS: Root lockout configured (60 second unlock time)"
