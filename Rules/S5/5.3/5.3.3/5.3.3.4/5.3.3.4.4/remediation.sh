#!/bin/bash

# Configure use_authtok for pam_unix
echo "Configuring use_authtok for pam_unix..."

if grep -Pi -- '^\h*password\h+.*pam_unix\.so.*\buse_authtok\b' /etc/pam.d/common-password &>/dev/null; then
    echo "INFO: use_authtok already configured"
else
    sed -i '/pam_unix.so/s/$/ use_authtok/' /etc/pam.d/common-password
    echo "SUCCESS: use_authtok configured for pam_unix"
fi
