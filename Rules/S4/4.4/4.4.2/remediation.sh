#!/bin/bash
# CIS 4.4.2 Configure ip6tables (IPv6)

echo "Applying remediation for CIS 4.4.2..."

# Flush existing rules
ip6tables -F

# Set default policies
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT ACCEPT

# Allow loopback
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -s ::1 -j DROP

# Allow established connections
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
ip6tables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

echo "Basic ip6tables rules configured"
echo "Remediation complete for CIS 4.4.2"
