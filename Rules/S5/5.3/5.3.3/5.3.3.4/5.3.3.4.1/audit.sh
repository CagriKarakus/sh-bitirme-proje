#!/bin/bash

# Check if pam_unix includes nullok
result=$(grep -Pi -- '^\h*[^#\n\r]+\h+pam_unix\.so\b.*\bnullok\b' /etc/pam.d/common-{password,auth} 2>/dev/null)

if [ -z "$result" ]; then
    echo "PASS: pam_unix does not include nullok"
    exit 0
else
    echo "FAIL: pam_unix includes nullok"
    echo "$result"
    exit 1
fi
