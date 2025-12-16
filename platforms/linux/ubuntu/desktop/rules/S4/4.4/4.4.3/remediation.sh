#!/bin/bash
# CIS 4.4.3 Ensure iptables software is installed

echo "Applying remediation for CIS 4.4.3..."

apt-get install -y iptables

echo "iptables installed"
echo "Remediation complete for CIS 4.4.3"
echo "NOTE: Consider using nftables instead on Ubuntu 24.04"
