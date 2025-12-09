#!/bin/bash
echo "Checking audit log file permissions..."
find /var/log/audit -type f -exec stat -c "%a %n" {} \; | while read perm file; do
    [ "$perm" -le 600 ] || echo "FAIL: $file has $perm"
done
exit 0
