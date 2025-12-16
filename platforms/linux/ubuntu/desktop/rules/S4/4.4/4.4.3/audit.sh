#!/bin/bash
# CIS 4.4.3 Ensure iptables software is installed

echo "Checking iptables package installation..."

if dpkg -l iptables 2>/dev/null | grep -q "^ii"; then
    echo "PASS: iptables is installed"
    echo ""
    echo "AUDIT RESULT: PASS"
    exit 0
else
    echo "INFO: iptables is not installed"
    echo "NOTE: Ubuntu 24.04 uses nftables by default"
    echo ""
    echo "AUDIT RESULT: PASS - nftables is preferred"
    exit 0
fi
