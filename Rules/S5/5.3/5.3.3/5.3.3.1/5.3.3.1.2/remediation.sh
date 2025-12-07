#!/bin/bash

# Configure password unlock time
echo "Configuring password unlock time..."

if grep -qi '^unlock_time\s*=' /etc/security/faillock.conf 2>/dev/null; then
    sed -i 's/^unlock_time\s*=.*/unlock_time = 900/' /etc/security/faillock.conf
else
    echo "unlock_time = 900" >> /etc/security/faillock.conf
fi

echo "SUCCESS: Password unlock time set to 900 seconds (15 minutes)"
