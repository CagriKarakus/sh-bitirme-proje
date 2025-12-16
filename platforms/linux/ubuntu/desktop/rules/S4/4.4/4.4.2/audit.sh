#!/bin/bash
# CIS 4.4.2 Configure ip6tables (IPv6)

echo "Checking ip6tables configuration..."

# Check if ip6tables is installed
if command -v ip6tables &>/dev/null; then
    echo "INFO: ip6tables is available"
    echo ""
    echo "Current ip6tables policies:"
    ip6tables -L -n | head -10
else
    echo "INFO: ip6tables is not installed"
fi

echo ""
echo "AUDIT RESULT: MANUAL - Review ip6tables configuration"
echo "NOTE: Ubuntu 24.04 defaults to nftables for IPv6"
exit 0
