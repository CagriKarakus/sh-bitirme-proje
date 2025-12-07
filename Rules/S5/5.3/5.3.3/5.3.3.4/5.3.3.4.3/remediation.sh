#!/bin/bash

# Configure strong password hashing
echo "Configuring strong password hashing..."

if grep -Pi -- '^\h*password\h+.*pam_unix\.so' /etc/pam.d/common-password | grep -qE '(sha512|yescrypt)'; then
    echo "INFO: Strong hashing already configured"
else
    # Add yescrypt if not present
    sed -i '/pam_unix.so/s/$/ yescrypt/' /etc/pam.d/common-password
    echo "SUCCESS: yescrypt hashing configured"
fi
