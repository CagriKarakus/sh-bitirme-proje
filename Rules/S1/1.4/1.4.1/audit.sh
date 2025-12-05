#!/bin/bash

# 1.4.1 Ensure bootloader password is set (Automated)
# Level: Level 1 - Server & Workstation

echo "=== 1.4.1 Bootloader Password Check ==="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Variables
GRUB_CFG="/boot/grub/grub.cfg"
PASSED=0
FAILED=0

# Check if GRUB configuration file exists
if [ ! -f "$GRUB_CFG" ]; then
    echo -e "${RED}[FAIL]${NC} GRUB configuration file not found: $GRUB_CFG"
    echo "Note: GRUB2 may not be installed on your system or may be in a different location."
    exit 1
fi

echo "1. Superuser Setting Check:"
echo "   Command: grep \"^set superusers\" $GRUB_CFG"
echo ""

SUPERUSER_CHECK=$(grep "^set superusers" "$GRUB_CFG" 2>/dev/null)

if [ -n "$SUPERUSER_CHECK" ]; then
    echo -e "${GREEN}[PASS]${NC} Superuser is defined:"
    echo "   $SUPERUSER_CHECK"
    ((PASSED++))
else
    echo -e "${RED}[FAIL]${NC} Superuser is not defined!"
    echo "   Expected: set superusers=\"<username>\""
    ((FAILED++))
fi

echo ""
echo "2. Encrypted Password Check:"
echo "   Command: awk -F. '/^\s*password/ {print \$1\".\"\$2\".\"\$3}' $GRUB_CFG"
echo ""

PASSWORD_CHECK=$(awk -F. '/^\s*password/ {print $1"."$2"."$3}' "$GRUB_CFG" 2>/dev/null)

if echo "$PASSWORD_CHECK" | grep -q "password_pbkdf2"; then
    echo -e "${GREEN}[PASS]${NC} Encrypted password is defined:"
    echo "$PASSWORD_CHECK" | while read -r line; do
        echo "   $line"
    done
    ((PASSED++))
else
    echo -e "${RED}[FAIL]${NC} Encrypted password not found!"
    echo "   Expected: password_pbkdf2 <user>.pbkdf2.sha512"
    ((FAILED++))
fi

echo ""
echo "=== Summary ==="
echo -e "${GREEN}Successful Checks: $PASSED${NC}"
echo -e "${RED}Failed Checks: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}Result: COMPLIANT${NC}"
    echo "Bootloader password protection is properly configured."
    exit 0
else
    echo -e "${RED}Result: NON-COMPLIANT${NC}"
    echo "Bootloader password protection must be configured!"
    exit 1
fi