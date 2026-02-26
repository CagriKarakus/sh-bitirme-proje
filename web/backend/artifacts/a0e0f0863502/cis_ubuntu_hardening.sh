#!/usr/bin/env bash
# ============================================================================
# CIS Ubuntu Desktop Hardening Script
# Generated for 2 rules
# Date: 2026-02-26 13:19:04
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
echo "  CIS Ubuntu Desktop Hardening – 2 Rules"
echo "================================================================"

# ── CIS 1.1.1.1: Section 1 Initial Setup ──
rule_1_1_1_1() {
    # CIS 1.1.1.1 Remediation - Disable cramfs kernel module
    
    mod_name="cramfs"
    rule_id="1.1.1.1"
    conf_dir="/etc/modprobe.d"
    conf_file="${conf_dir}/cis-${mod_name}.conf"
    kernel_ver="$(uname -r)"
    
    # Managed block markers
    BLOCK_START="# BEGIN CIS ${rule_id} - Managed by CIS remediation"
    BLOCK_END="# END CIS ${rule_id}"
    
    echo "[REMEDIATE] Disabling ${mod_name} kernel module..."
    
    # Check if module is built into the kernel
    if grep -qw "${mod_name}" "/lib/modules/${kernel_ver}/modules.builtin" 2>/dev/null; then
        echo "[SKIP] ${mod_name} is built into the kernel - cannot be disabled"
        return 0
    fi
    
    # Check if the module exists
    if ! find "/lib/modules/${kernel_ver}" -type f -name "${mod_name}.ko*" 2>/dev/null | grep -q .; then
        echo "[SKIP] ${mod_name} module not found on system"
        return 0
    fi
    
    # Create modprobe.d directory if it doesn't exist
    if [[ ! -d "${conf_dir}" ]]; then
        mkdir -p "${conf_dir}"
        echo "[CREATED] ${conf_dir} directory"
    fi
    
    # Function to update or add managed block
    update_managed_block() {
        local file="$1"
        local block_content="$2"
        
        if [[ -f "$file" ]]; then
            # Remove existing managed block if present
            if grep -q "^${BLOCK_START}" "$file"; then
                sed -i "/^${BLOCK_START}/,/^${BLOCK_END}/d" "$file"
                echo "[INFO] Removed existing managed block from ${file}"
            fi
        fi
        
        # Append new managed block
        {
            echo ""
            echo "${BLOCK_START}"
            echo "${block_content}"
            echo "${BLOCK_END}"
        } >> "$file"
    }
    
    # Content to add
    block_content="install ${mod_name} /bin/false
    blacklist ${mod_name}"
    
    # Update configuration file with managed block
    update_managed_block "${conf_file}" "${block_content}"
    echo "[CONFIGURED] ${conf_file} updated with managed block"
    
    # Unload module if currently loaded
    if lsmod | grep -qw "^${mod_name}"; then
        if modprobe -r "${mod_name}" 2>/dev/null; then
            echo "[UNLOADED] ${mod_name} module removed from kernel"
        else
            echo "[WARNING] Could not unload ${mod_name} - may be in use (will be disabled on reboot)"
        fi
    else
        echo "[OK] ${mod_name} module not currently loaded"
    fi
    
    # Update initramfs/initrd if available
    if command -v update-initramfs >/dev/null 2>&1; then
        echo "[UPDATE] Updating initramfs..."
        update-initramfs -u -k all >/dev/null 2>&1 || true
    elif command -v dracut >/dev/null 2>&1; then
        echo "[UPDATE] Updating initramfs with dracut..."
        dracut -f >/dev/null 2>&1 || true
    fi
    
    echo "[SUCCESS] ${mod_name} module has been disabled"
}
apply_rule "1.1.1.1" "1.1.1.1" rule_1_1_1_1

# ── CIS 1.1.1.2: Section 1 Initial Setup ──
rule_1_1_1_2() {
    # CIS 1.1.1.2 Remediation - Disable freevxfs kernel module
    
    mod_name="freevxfs"
    rule_id="1.1.1.2"
    conf_dir="/etc/modprobe.d"
    conf_file="${conf_dir}/cis-${mod_name}.conf"
    kernel_ver="$(uname -r)"
    
    # Managed block markers
    BLOCK_START="# BEGIN CIS ${rule_id} - Managed by CIS remediation"
    BLOCK_END="# END CIS ${rule_id}"
    
    echo "[REMEDIATE] Disabling ${mod_name} kernel module..."
    
    # Check if module is built into the kernel
    if grep -qw "${mod_name}" "/lib/modules/${kernel_ver}/modules.builtin" 2>/dev/null; then
        echo "[SKIP] ${mod_name} is built into the kernel - cannot be disabled"
        return 0
    fi
    
    # Check if the module exists
    if ! find "/lib/modules/${kernel_ver}" -type f -name "${mod_name}.ko*" 2>/dev/null | grep -q .; then
        echo "[SKIP] ${mod_name} module not found on system"
        return 0
    fi
    
    # Create modprobe.d directory if it doesn't exist
    if [[ ! -d "${conf_dir}" ]]; then
        mkdir -p "${conf_dir}"
        echo "[CREATED] ${conf_dir} directory"
    fi
    
    # Function to update or add managed block
    update_managed_block() {
        local file="$1"
        local block_content="$2"
        
        if [[ -f "$file" ]]; then
            # Remove existing managed block if present
            if grep -q "^${BLOCK_START}" "$file"; then
                sed -i "/^${BLOCK_START}/,/^${BLOCK_END}/d" "$file"
                echo "[INFO] Removed existing managed block from ${file}"
            fi
        fi
        
        # Append new managed block
        {
            echo ""
            echo "${BLOCK_START}"
            echo "${block_content}"
            echo "${BLOCK_END}"
        } >> "$file"
    }
    
    # Content to add
    block_content="install ${mod_name} /bin/false
    blacklist ${mod_name}"
    
    # Update configuration file with managed block
    update_managed_block "${conf_file}" "${block_content}"
    echo "[CONFIGURED] ${conf_file} updated with managed block"
    
    # Unload module if currently loaded
    if lsmod | grep -qw "^${mod_name}"; then
        if modprobe -r "${mod_name}" 2>/dev/null; then
            echo "[UNLOADED] ${mod_name} module removed from kernel"
        else
            echo "[WARNING] Could not unload ${mod_name} - may be in use (will be disabled on reboot)"
        fi
    else
        echo "[OK] ${mod_name} module not currently loaded"
    fi
    
    # Update initramfs/initrd if available
    if command -v update-initramfs >/dev/null 2>&1; then
        echo "[UPDATE] Updating initramfs..."
        update-initramfs -u -k all >/dev/null 2>&1 || true
    elif command -v dracut >/dev/null 2>&1; then
        echo "[UPDATE] Updating initramfs with dracut..."
        dracut -f >/dev/null 2>&1 || true
    fi
    
    echo "[SUCCESS] ${mod_name} module has been disabled"
}
apply_rule "1.1.1.2" "1.1.1.2" rule_1_1_1_2

# ── Summary ──
echo ""
echo "================================================================"
echo -e "Applied: ${GREEN}${PASS_COUNT}${NC}  |  Failed: ${RED}${FAIL_COUNT}${NC}  |  Total: ${TOTAL}"
echo "================================================================"

