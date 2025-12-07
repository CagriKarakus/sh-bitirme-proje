#!/bin/bash

# Remove nullok from pam_unix
echo "Removing nullok from pam_unix..."

sed -i 's/\s*nullok//g' /etc/pam.d/common-password
sed -i 's/\s*nullok//g' /etc/pam.d/common-auth

echo "SUCCESS: nullok removed from pam_unix configuration"
