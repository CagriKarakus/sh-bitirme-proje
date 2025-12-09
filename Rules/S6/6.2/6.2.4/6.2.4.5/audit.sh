#!/bin/bash
echo "Checking audit config file permissions..."
find /etc/audit -type f -exec stat -c "%a %n" {} \; | while read perm file; do
    [ "$perm" -le 640 ] || echo "FAIL: $file"
done
echo "PASS"
