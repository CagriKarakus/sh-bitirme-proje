#!/usr/bin/env bash
# ============================================================================
# CIS Ubuntu Desktop Hardening Script
# Generated for 4 rules
# Date: 2026-03-04 10:58:23
# WARNING: Review each rule before applying to production systems.
# ============================================================================

set -euo pipefail

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
NC="\033[0m"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL=0

apply_rule() {
    local rule_id="$1"
    local title="$2"
    TOTAL=$((TOTAL + 1))
    echo ""
    echo -e "${CYAN}[APPLY] ${rule_id}: ${title}${NC}"
    if "$3"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "${GREEN}[OK] ${rule_id} applied successfully${NC}"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "${RED}[FAIL] ${rule_id} failed${NC}"
    fi
}

# Check root
if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must be run as root${NC}"
    exit 1
fi

echo "================================================================"
echo "  CIS Ubuntu Desktop Hardening – 4 Rules"
echo "================================================================"

# ── CIS 2.1.1: Section 2 Services ──
rule_2_1_1() {
    # CIS Benchmark 2.1.1 - Ensure autofs services are not in use
    # Remediation Script
    
    echo "Applying remediation for CIS 2.1.1 - Ensure autofs services are not in use..."
    
    # Stop autofs service if running
    if systemctl is-active autofs.service 2>/dev/null | grep -q "^active"; then
        echo "Stopping autofs.service..."
        systemctl stop autofs.service
    fi
    
    # Mask autofs service
    echo "Masking autofs.service..."
    systemctl mask autofs.service 2>/dev/null
    
    # Remove autofs package if installed
    if dpkg-query -W -f='${db:Status-Status}' autofs 2>/dev/null | grep -q "installed"; then
        echo "Removing autofs package..."
        apt purge -y autofs
    fi
    
    echo ""
    echo "Remediation complete for CIS 2.1.1 - Ensure autofs services are not in use"
}
apply_rule "2.1.1" "2.1.1" rule_2_1_1

# ── CIS 2.1.2: Section 2 Services ──
rule_2_1_2() {
    # CIS Benchmark 2.1.2 - Ensure avahi daemon services are not in use
    # Remediation Script
    
    echo "Applying remediation for CIS 2.1.2..."
    
    systemctl stop avahi-daemon.service 2>/dev/null
    systemctl stop avahi-daemon.socket 2>/dev/null
    systemctl mask avahi-daemon.service 2>/dev/null
    systemctl mask avahi-daemon.socket 2>/dev/null
    
    if dpkg-query -W -f='${db:Status-Status}' avahi-daemon 2>/dev/null | grep -q "installed"; then
        apt purge -y avahi-daemon
    fi
    
    echo "Remediation complete for CIS 2.1.2"
}
apply_rule "2.1.2" "2.1.2" rule_2_1_2

# ── CIS 2.1.9: Section 2 Services ──
rule_2_1_9() {
    # CIS Benchmark 2.1.9 - Ensure network file system services are not in use
    echo "Applying remediation for CIS 2.1.9..."
    systemctl stop nfs-server.service 2>/dev/null
    systemctl mask nfs-server.service 2>/dev/null
    dpkg-query -W -f='${db:Status-Status}' nfs-kernel-server 2>/dev/null | grep -q "installed" && apt purge -y nfs-kernel-server
    echo "Remediation complete for CIS 2.1.9"
}
apply_rule "2.1.9" "2.1.9" rule_2_1_9

# ── CIS 2.1.8: Section 2 Services ──
rule_2_1_8() {
    # CIS Benchmark 2.1.8 - Ensure message access agent services are not in use
    echo "Applying remediation for CIS 2.1.8..."
    systemctl stop dovecot.service 2>/dev/null
    systemctl mask dovecot.service 2>/dev/null
    apt purge -y dovecot-imapd dovecot-pop3d 2>/dev/null
    echo "Remediation complete for CIS 2.1.8"
}
apply_rule "2.1.8" "2.1.8" rule_2_1_8

# ── Summary ──
echo ""
echo "================================================================"
echo -e "Applied: ${GREEN}${PASS_COUNT}${NC}  |  Failed: ${RED}${FAIL_COUNT}${NC}  |  Total: ${TOTAL}"
echo "================================================================"

