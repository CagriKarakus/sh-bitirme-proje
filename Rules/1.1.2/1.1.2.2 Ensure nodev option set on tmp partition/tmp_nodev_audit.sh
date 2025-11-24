#!/bin/bash

# Check if /tmp is mounted with nodev
if mount | grep "on /tmp" | grep -q "nodev"; then
    echo "PASS: /tmp is mounted with nodev"
    exit 0
else
    echo "FAIL: /tmp is NOT mounted with nodev"
    exit 1
fi
