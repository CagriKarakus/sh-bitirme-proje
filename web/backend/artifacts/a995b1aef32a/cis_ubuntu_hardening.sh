#!/usr/bin/env bash
# ============================================================================
# CIS Ubuntu Desktop Hardening Script
# Generated for 1 rules
# Date: 2026-02-26 13:29:10
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
echo "  CIS Ubuntu Desktop Hardening – 1 Rules"
echo "================================================================"

# ── CIS 7.1.1: S7 ──
rule_7_1_1() {
    
    # 7.1.1 Ensure permissions on /etc/passwd are configured (Automated)
    
    echo "Configuring permissions on /etc/passwd..."
    
    chown root:root /etc/passwd
    chmod u-x,go-wx /etc/passwd
    
    echo "/etc/passwd permissions have been configured"
}
apply_rule "7.1.1" "7.1.1" rule_7_1_1

# ── Summary ──
echo ""
echo "================================================================"
echo -e "Applied: ${GREEN}${PASS_COUNT}${NC}  |  Failed: ${RED}${FAIL_COUNT}${NC}  |  Total: ${TOTAL}"
echo "================================================================"

