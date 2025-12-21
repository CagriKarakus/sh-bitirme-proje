#!/usr/bin/env bash
###############################################################################
#
# CIS Benchmark Audit & Remediation Script
#
# Generated on    : 2025-12-21 12:32:28
# Source registry : platforms\linux\ubuntu\desktop\rules\index.json
# Rule count      : 50
#
# This script performs:
#   1. Initial audit of all selected rules (BEFORE)
#   2. Remediation for failed rules
#   3. Final audit of all rules (AFTER)
#   4. Generates HTML report with before/after comparison
#
###############################################################################

# Exit on undefined variables only, continue on errors
set -u

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Results storage
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
REPORT_DIR="${REPORT_DIR:-$HOME/cis_report_$TIMESTAMP}"
mkdir -p "$REPORT_DIR"

# Arrays to store results
declare -A BEFORE_RESULTS
declare -A AFTER_RESULTS
declare -A BEFORE_OUTPUT
declare -A AFTER_OUTPUT
declare -A RULE_START_TIME
declare -A RULE_END_TIME
declare -A RULE_DURATION

TOTAL_RULES=50
RULES_LIST=("1.1.1.1" "1.1.1.2" "1.1.1.3" "1.1.1.4" "1.1.1.5" "1.1.1.6" "1.1.1.7" "1.1.1.8" "1.1.1.9" "1.3.1.1" "1.3.1.2" "1.3.1.3" "1.3.1.4" "1.4.1" "1.4.2" "1.5.1" "1.5.2" "1.5.3" "1.5.4" "1.5.5" "1.6.1" "1.6.2" "1.6.3" "1.6.4" "1.6.5" "1.6.6" "1.7.1" "1.7.2" "1.7.3" "1.7.4" "1.7.5" "1.7.6" "1.7.7" "1.7.8" "1.7.9" "1.7.10" "2.1.1" "2.1.2" "2.1.3" "2.1.4" "2.1.5" "2.1.6" "2.1.7" "2.1.8" "2.1.9" "2.1.10" "2.1.11" "2.1.12" "2.1.13" "2.1.14")

# Detailed log file
DETAILED_LOG="$REPORT_DIR/cis_detailed_report.log"

# Function to log with timestamp
log_detailed() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$DETAILED_LOG"
}

# Initialize detailed log
cat > "$DETAILED_LOG" << 'LOGHEADER'
################################################################################
#                                                                              #
#                   CIS BENCHMARK DETAILED EXECUTION REPORT                    #
#                                                                              #
################################################################################

LOGHEADER

log_detailed "Report Directory: $REPORT_DIR"
log_detailed "Total Rules to Check: $TOTAL_RULES"
log_detailed "Execution Started: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed ""

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  CIS Benchmark Audit & Remediation Tool${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""
echo "Report directory: $REPORT_DIR"
echo "Total rules to check: $TOTAL_RULES"
echo ""

###############################################################################
# PHASE 1: INITIAL AUDIT (BEFORE)
###############################################################################
echo -e "${YELLOW}=== PHASE 1: Initial Audit (BEFORE) ===${NC}"
echo ""

log_detailed "================================================================================"
log_detailed "PHASE 1: INITIAL AUDIT (BEFORE)"
log_detailed "================================================================================"
log_detailed ""



# Audit function for rule 1.1.1.1
audit_1_1_1_1() {
    local output
    local exit_code
    
    output=$(
        # CIS 1.1.1.1 Audit - Ensure cramfs kernel module is not available

        mod_name="cramfs"
        conf_dir="/etc/modprobe.d"
        conf_file="${conf_dir}/cramfs.conf"
        kernel_ver="$(uname -r)"

        # Exit codes for integration
        # 0 = PASS, 1 = FAIL, 2 = NOT_APPLICABLE

        audit_result=0

        # Check if module is built into the kernel
        if grep -qw "${mod_name}" "/lib/modules/${kernel_ver}/modules.builtin" 2>/dev/null; then
            echo "[INFO] ${mod_name} is built into the kernel - no action needed"
            exit 2  # Not applicable
        fi

        # Check if the module exists as a loadable module
        if ! find "/lib/modules/${kernel_ver}" -type f -name "${mod_name}.ko*" 2>/dev/null | grep -q .; then
            echo "[INFO] ${mod_name} module not found on system"
            exit 2  # Not applicable
        fi

        echo "[CHECK] Auditing ${mod_name} kernel module configuration..."

        # Check if module is currently loaded
        if lsmod | grep -qw "^${mod_name}"; then
            echo "[FAIL] ${mod_name} module is currently loaded"
            audit_result=1
        else
            echo "[PASS] ${mod_name} module is not loaded"
        fi

        # Check for install directive
        if grep -Prq "^\s*install\s+${mod_name}\s+/(?:usr/)?bin/(?:true|false)\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] install directive configured for ${mod_name}"
        else
            echo "[FAIL] install directive not configured for ${mod_name}"
            audit_result=1
        fi

        # Check for blacklist entry
        if grep -Prq "^\s*blacklist\s+${mod_name}\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] ${mod_name} is blacklisted"
        else
            echo "[FAIL] ${mod_name} is not blacklisted"
            audit_result=1
        fi

        exit $audit_result
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.1.1.1
remediate_1_1_1_1() {
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


# Audit function for rule 1.1.1.2
audit_1_1_1_2() {
    local output
    local exit_code
    
    output=$(
        # CIS 1.1.1.2 Audit - Ensure freevxfs kernel module is not available

        mod_name="freevxfs"
        conf_dir="/etc/modprobe.d"
        conf_file="${conf_dir}/freevxfs.conf"
        kernel_ver="$(uname -r)"

        # Exit codes for integration
        # 0 = PASS, 1 = FAIL, 2 = NOT_APPLICABLE

        audit_result=0

        # Check if module is built into the kernel
        if grep -qw "${mod_name}" "/lib/modules/${kernel_ver}/modules.builtin" 2>/dev/null; then
            echo "[INFO] ${mod_name} is built into the kernel - no action needed"
            exit 2  # Not applicable
        fi

        # Check if the module exists as a loadable module
        if ! find "/lib/modules/${kernel_ver}" -type f -name "${mod_name}.ko*" 2>/dev/null | grep -q .; then
            echo "[INFO] ${mod_name} module not found on system"
            exit 2  # Not applicable
        fi

        echo "[CHECK] Auditing ${mod_name} kernel module configuration..."

        # Check if module is currently loaded
        if lsmod | grep -qw "^${mod_name}"; then
            echo "[FAIL] ${mod_name} module is currently loaded"
            audit_result=1
        else
            echo "[PASS] ${mod_name} module is not loaded"
        fi

        # Check for install directive
        if grep -Prq "^\s*install\s+${mod_name}\s+/(?:usr/)?bin/(?:true|false)\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] install directive configured for ${mod_name}"
        else
            echo "[FAIL] install directive not configured for ${mod_name}"
            audit_result=1
        fi

        # Check for blacklist entry
        if grep -Prq "^\s*blacklist\s+${mod_name}\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] ${mod_name} is blacklisted"
        else
            echo "[FAIL] ${mod_name} is not blacklisted"
            audit_result=1
        fi

        exit $audit_result
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.1.1.2
remediate_1_1_1_2() {
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


# Audit function for rule 1.1.1.3
audit_1_1_1_3() {
    local output
    local exit_code
    
    output=$(
        # CIS 1.1.1.3 Audit - Ensure hfs kernel module is not available

        mod_name="hfs"
        conf_dir="/etc/modprobe.d"
        conf_file="${conf_dir}/hfs.conf"
        kernel_ver="$(uname -r)"

        # Exit codes for integration
        # 0 = PASS, 1 = FAIL, 2 = NOT_APPLICABLE

        audit_result=0

        # Check if module is built into the kernel
        if grep -qw "${mod_name}" "/lib/modules/${kernel_ver}/modules.builtin" 2>/dev/null; then
            echo "[INFO] ${mod_name} is built into the kernel - no action needed"
            exit 2  # Not applicable
        fi

        # Check if the module exists as a loadable module
        if ! find "/lib/modules/${kernel_ver}" -type f -name "${mod_name}.ko*" 2>/dev/null | grep -q .; then
            echo "[INFO] ${mod_name} module not found on system"
            exit 2  # Not applicable
        fi

        echo "[CHECK] Auditing ${mod_name} kernel module configuration..."

        # Check if module is currently loaded
        if lsmod | grep -qw "^${mod_name}"; then
            echo "[FAIL] ${mod_name} module is currently loaded"
            audit_result=1
        else
            echo "[PASS] ${mod_name} module is not loaded"
        fi

        # Check for install directive
        if grep -Prq "^\s*install\s+${mod_name}\s+/(?:usr/)?bin/(?:true|false)\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] install directive configured for ${mod_name}"
        else
            echo "[FAIL] install directive not configured for ${mod_name}"
            audit_result=1
        fi

        # Check for blacklist entry
        if grep -Prq "^\s*blacklist\s+${mod_name}\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] ${mod_name} is blacklisted"
        else
            echo "[FAIL] ${mod_name} is not blacklisted"
            audit_result=1
        fi

        exit $audit_result
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.1.1.3
remediate_1_1_1_3() {
    # CIS 1.1.1.3 Remediation - Disable hfs kernel module

    mod_name="hfs"
    rule_id="1.1.1.3"
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


# Audit function for rule 1.1.1.4
audit_1_1_1_4() {
    local output
    local exit_code
    
    output=$(
        # CIS 1.1.1.4 Audit - Ensure hfsplus kernel module is not available

        mod_name="hfsplus"
        conf_dir="/etc/modprobe.d"
        conf_file="${conf_dir}/hfsplus.conf"
        kernel_ver="$(uname -r)"

        # Exit codes for integration
        # 0 = PASS, 1 = FAIL, 2 = NOT_APPLICABLE

        audit_result=0

        # Check if module is built into the kernel
        if grep -qw "${mod_name}" "/lib/modules/${kernel_ver}/modules.builtin" 2>/dev/null; then
            echo "[INFO] ${mod_name} is built into the kernel - no action needed"
            exit 2  # Not applicable
        fi

        # Check if the module exists as a loadable module
        if ! find "/lib/modules/${kernel_ver}" -type f -name "${mod_name}.ko*" 2>/dev/null | grep -q .; then
            echo "[INFO] ${mod_name} module not found on system"
            exit 2  # Not applicable
        fi

        echo "[CHECK] Auditing ${mod_name} kernel module configuration..."

        # Check if module is currently loaded
        if lsmod | grep -qw "^${mod_name}"; then
            echo "[FAIL] ${mod_name} module is currently loaded"
            audit_result=1
        else
            echo "[PASS] ${mod_name} module is not loaded"
        fi

        # Check for install directive
        if grep -Prq "^\s*install\s+${mod_name}\s+/(?:usr/)?bin/(?:true|false)\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] install directive configured for ${mod_name}"
        else
            echo "[FAIL] install directive not configured for ${mod_name}"
            audit_result=1
        fi

        # Check for blacklist entry
        if grep -Prq "^\s*blacklist\s+${mod_name}\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] ${mod_name} is blacklisted"
        else
            echo "[FAIL] ${mod_name} is not blacklisted"
            audit_result=1
        fi

        exit $audit_result
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.1.1.4
remediate_1_1_1_4() {
    # CIS 1.1.1.4 Remediation - Disable hfsplus kernel module

    mod_name="hfsplus"
    rule_id="1.1.1.4"
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


# Audit function for rule 1.1.1.5
audit_1_1_1_5() {
    local output
    local exit_code
    
    output=$(
        # CIS 1.1.1.5 Audit - Ensure jffs2 kernel module is not available

        mod_name="jffs2"
        conf_dir="/etc/modprobe.d"
        conf_file="${conf_dir}/jffs2.conf"
        kernel_ver="$(uname -r)"

        # Exit codes for integration
        # 0 = PASS, 1 = FAIL, 2 = NOT_APPLICABLE

        audit_result=0

        # Check if module is built into the kernel
        if grep -qw "${mod_name}" "/lib/modules/${kernel_ver}/modules.builtin" 2>/dev/null; then
            echo "[INFO] ${mod_name} is built into the kernel - no action needed"
            exit 2  # Not applicable
        fi

        # Check if the module exists as a loadable module
        if ! find "/lib/modules/${kernel_ver}" -type f -name "${mod_name}.ko*" 2>/dev/null | grep -q .; then
            echo "[INFO] ${mod_name} module not found on system"
            exit 2  # Not applicable
        fi

        echo "[CHECK] Auditing ${mod_name} kernel module configuration..."

        # Check if module is currently loaded
        if lsmod | grep -qw "^${mod_name}"; then
            echo "[FAIL] ${mod_name} module is currently loaded"
            audit_result=1
        else
            echo "[PASS] ${mod_name} module is not loaded"
        fi

        # Check for install directive
        if grep -Prq "^\s*install\s+${mod_name}\s+/(?:usr/)?bin/(?:true|false)\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] install directive configured for ${mod_name}"
        else
            echo "[FAIL] install directive not configured for ${mod_name}"
            audit_result=1
        fi

        # Check for blacklist entry
        if grep -Prq "^\s*blacklist\s+${mod_name}\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] ${mod_name} is blacklisted"
        else
            echo "[FAIL] ${mod_name} is not blacklisted"
            audit_result=1
        fi

        exit $audit_result
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.1.1.5
remediate_1_1_1_5() {
    # CIS 1.1.1.5 Remediation - Disable jffs2 kernel module

    mod_name="jffs2"
    rule_id="1.1.1.5"
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


# Audit function for rule 1.1.1.6
audit_1_1_1_6() {
    local output
    local exit_code
    
    output=$(
        # CIS 1.1.1.6 Audit - Ensure overlayfs kernel module is not available

        mod_name="overlayfs"
        conf_dir="/etc/modprobe.d"
        conf_file="${conf_dir}/overlayfs.conf"
        kernel_ver="$(uname -r)"

        # Exit codes for integration
        # 0 = PASS, 1 = FAIL, 2 = NOT_APPLICABLE

        audit_result=0

        # Check if module is built into the kernel
        if grep -qw "${mod_name}" "/lib/modules/${kernel_ver}/modules.builtin" 2>/dev/null; then
            echo "[INFO] ${mod_name} is built into the kernel - no action needed"
            exit 2  # Not applicable
        fi

        # Check if the module exists as a loadable module
        if ! find "/lib/modules/${kernel_ver}" -type f -name "${mod_name}.ko*" 2>/dev/null | grep -q .; then
            echo "[INFO] ${mod_name} module not found on system"
            exit 2  # Not applicable
        fi

        echo "[CHECK] Auditing ${mod_name} kernel module configuration..."

        # Check if module is currently loaded
        if lsmod | grep -qw "^${mod_name}"; then
            echo "[FAIL] ${mod_name} module is currently loaded"
            audit_result=1
        else
            echo "[PASS] ${mod_name} module is not loaded"
        fi

        # Check for install directive
        if grep -Prq "^\s*install\s+${mod_name}\s+/(?:usr/)?bin/(?:true|false)\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] install directive configured for ${mod_name}"
        else
            echo "[FAIL] install directive not configured for ${mod_name}"
            audit_result=1
        fi

        # Check for blacklist entry
        if grep -Prq "^\s*blacklist\s+${mod_name}\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] ${mod_name} is blacklisted"
        else
            echo "[FAIL] ${mod_name} is not blacklisted"
            audit_result=1
        fi

        exit $audit_result
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.1.1.6
remediate_1_1_1_6() {
    # CIS 1.1.1.6 Remediation - Disable squashfs kernel module

    mod_name="squashfs"
    rule_id="1.1.1.6"
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
            if grep -q "^${BLOCK_START}" "$file"; then
                sed -i "/^${BLOCK_START}/,/^${BLOCK_END}/d" "$file"
                echo "[INFO] Removed existing managed block from ${file}"
            fi
        fi
    
        {
            echo ""
            echo "${BLOCK_START}"
            echo "${block_content}"
            echo "${BLOCK_END}"
        } >> "$file"
    }

    block_content="install ${mod_name} /bin/false
    blacklist ${mod_name}"

    update_managed_block "${conf_file}" "${block_content}"
    echo "[CONFIGURED] ${conf_file} updated with managed block"

    if lsmod | grep -qw "^${mod_name}"; then
        if modprobe -r "${mod_name}" 2>/dev/null; then
            echo "[UNLOADED] ${mod_name} module removed from kernel"
        else
            echo "[WARNING] Could not unload ${mod_name} - may be in use (will be disabled on reboot)"
        fi
    else
        echo "[OK] ${mod_name} module not currently loaded"
    fi

    if command -v update-initramfs >/dev/null 2>&1; then
        echo "[UPDATE] Updating initramfs..."
        update-initramfs -u -k all >/dev/null 2>&1 || true
    elif command -v dracut >/dev/null 2>&1; then
        echo "[UPDATE] Updating initramfs with dracut..."
        dracut -f >/dev/null 2>&1 || true
    fi

    echo "[SUCCESS] ${mod_name} module has been disabled"
}


# Audit function for rule 1.1.1.7
audit_1_1_1_7() {
    local output
    local exit_code
    
    output=$(
        # CIS 1.1.1.7 Audit - Ensure squashfs kernel module is not available

        mod_name="cramfs"
        conf_dir="/etc/modprobe.d"
        conf_file="${conf_dir}/cramfs.conf"
        kernel_ver="$(uname -r)"

        # Exit codes for integration
        # 0 = PASS, 1 = FAIL, 2 = NOT_APPLICABLE

        audit_result=0

        # Check if module is built into the kernel
        if grep -qw "${mod_name}" "/lib/modules/${kernel_ver}/modules.builtin" 2>/dev/null; then
            echo "[INFO] ${mod_name} is built into the kernel - no action needed"
            exit 2  # Not applicable
        fi

        # Check if the module exists as a loadable module
        if ! find "/lib/modules/${kernel_ver}" -type f -name "${mod_name}.ko*" 2>/dev/null | grep -q .; then
            echo "[INFO] ${mod_name} module not found on system"
            exit 2  # Not applicable
        fi

        echo "[CHECK] Auditing ${mod_name} kernel module configuration..."

        # Check if module is currently loaded
        if lsmod | grep -qw "^${mod_name}"; then
            echo "[FAIL] ${mod_name} module is currently loaded"
            audit_result=1
        else
            echo "[PASS] ${mod_name} module is not loaded"
        fi

        # Check for install directive
        if grep -Prq "^\s*install\s+${mod_name}\s+/(?:usr/)?bin/(?:true|false)\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] install directive configured for ${mod_name}"
        else
            echo "[FAIL] install directive not configured for ${mod_name}"
            audit_result=1
        fi

        # Check for blacklist entry
        if grep -Prq "^\s*blacklist\s+${mod_name}\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] ${mod_name} is blacklisted"
        else
            echo "[FAIL] ${mod_name} is not blacklisted"
            audit_result=1
        fi

        exit $audit_result
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.1.1.7
remediate_1_1_1_7() {
    # CIS 1.1.1.7 Remediation - Disable udf kernel module

    mod_name="udf"
    rule_id="1.1.1.7"
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
            if grep -q "^${BLOCK_START}" "$file"; then
                sed -i "/^${BLOCK_START}/,/^${BLOCK_END}/d" "$file"
                echo "[INFO] Removed existing managed block from ${file}"
            fi
        fi
    
        {
            echo ""
            echo "${BLOCK_START}"
            echo "${block_content}"
            echo "${BLOCK_END}"
        } >> "$file"
    }

    block_content="install ${mod_name} /bin/false
    blacklist ${mod_name}"

    update_managed_block "${conf_file}" "${block_content}"
    echo "[CONFIGURED] ${conf_file} updated with managed block"

    if lsmod | grep -qw "^${mod_name}"; then
        if modprobe -r "${mod_name}" 2>/dev/null; then
            echo "[UNLOADED] ${mod_name} module removed from kernel"
        else
            echo "[WARNING] Could not unload ${mod_name} - may be in use (will be disabled on reboot)"
        fi
    else
        echo "[OK] ${mod_name} module not currently loaded"
    fi

    if command -v update-initramfs >/dev/null 2>&1; then
        echo "[UPDATE] Updating initramfs..."
        update-initramfs -u -k all >/dev/null 2>&1 || true
    elif command -v dracut >/dev/null 2>&1; then
        echo "[UPDATE] Updating initramfs with dracut..."
        dracut -f >/dev/null 2>&1 || true
    fi

    echo "[SUCCESS] ${mod_name} module has been disabled"
}


# Audit function for rule 1.1.1.8
audit_1_1_1_8() {
    local output
    local exit_code
    
    output=$(
        # CIS 1.1.1.8 Audit - Ensure udf kernel module is not available

        mod_name="udf"
        conf_dir="/etc/modprobe.d"
        conf_file="${conf_dir}/udf.conf"
        kernel_ver="$(uname -r)"

        # Exit codes for integration
        # 0 = PASS, 1 = FAIL, 2 = NOT_APPLICABLE

        audit_result=0

        # Check if module is built into the kernel
        if grep -qw "${mod_name}" "/lib/modules/${kernel_ver}/modules.builtin" 2>/dev/null; then
            echo "[INFO] ${mod_name} is built into the kernel - no action needed"
            exit 2  # Not applicable
        fi

        # Check if the module exists as a loadable module
        if ! find "/lib/modules/${kernel_ver}" -type f -name "${mod_name}.ko*" 2>/dev/null | grep -q .; then
            echo "[INFO] ${mod_name} module not found on system"
            exit 2  # Not applicable
        fi

        echo "[CHECK] Auditing ${mod_name} kernel module configuration..."

        # Check if module is currently loaded
        if lsmod | grep -qw "^${mod_name}"; then
            echo "[FAIL] ${mod_name} module is currently loaded"
            audit_result=1
        else
            echo "[PASS] ${mod_name} module is not loaded"
        fi

        # Check for install directive
        if grep -Prq "^\s*install\s+${mod_name}\s+/(?:usr/)?bin/(?:true|false)\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] install directive configured for ${mod_name}"
        else
            echo "[FAIL] install directive not configured for ${mod_name}"
            audit_result=1
        fi

        # Check for blacklist entry
        if grep -Prq "^\s*blacklist\s+${mod_name}\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] ${mod_name} is blacklisted"
        else
            echo "[FAIL] ${mod_name} is not blacklisted"
            audit_result=1
        fi

        exit $audit_result
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.1.1.8
remediate_1_1_1_8() {
    # CIS 1.1.1.8 Remediation - Disable usb-storage kernel module

    mod_name="usb-storage"
    rule_id="1.1.1.8"
    conf_dir="/etc/modprobe.d"
    conf_file="${conf_dir}/cis-usb-storage.conf"
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
    if ! find "/lib/modules/${kernel_ver}" -type f -name "usb_storage.ko*" -o -name "usb-storage.ko*" 2>/dev/null | grep -q .; then
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
            if grep -q "^${BLOCK_START}" "$file"; then
                sed -i "/^${BLOCK_START}/,/^${BLOCK_END}/d" "$file"
                echo "[INFO] Removed existing managed block from ${file}"
            fi
        fi
    
        {
            echo ""
            echo "${BLOCK_START}"
            echo "${block_content}"
            echo "${BLOCK_END}"
        } >> "$file"
    }

    block_content="install ${mod_name} /bin/false
    blacklist ${mod_name}"

    update_managed_block "${conf_file}" "${block_content}"
    echo "[CONFIGURED] ${conf_file} updated with managed block"

    if lsmod | grep -qw "^usb_storage"; then
        if modprobe -r "${mod_name}" 2>/dev/null; then
            echo "[UNLOADED] ${mod_name} module removed from kernel"
        else
            echo "[WARNING] Could not unload ${mod_name} - may be in use (will be disabled on reboot)"
        fi
    else
        echo "[OK] ${mod_name} module not currently loaded"
    fi

    if command -v update-initramfs >/dev/null 2>&1; then
        echo "[UPDATE] Updating initramfs..."
        update-initramfs -u -k all >/dev/null 2>&1 || true
    elif command -v dracut >/dev/null 2>&1; then
        echo "[UPDATE] Updating initramfs with dracut..."
        dracut -f >/dev/null 2>&1 || true
    fi

    echo "[SUCCESS] ${mod_name} module has been disabled"
}


# Audit function for rule 1.1.1.9
audit_1_1_1_9() {
    local output
    local exit_code
    
    output=$(
        # CIS 1.1.1.9 Audit - Ensure usb-storage kernel module is not available

        mod_name="usb-storage"
        conf_dir="/etc/modprobe.d"
        conf_file="${conf_dir}/usb-storage.conf"
        kernel_ver="$(uname -r)"

        # Exit codes for integration
        # 0 = PASS, 1 = FAIL, 2 = NOT_APPLICABLE

        audit_result=0

        # Check if module is built into the kernel
        if grep -qw "${mod_name}" "/lib/modules/${kernel_ver}/modules.builtin" 2>/dev/null; then
            echo "[INFO] ${mod_name} is built into the kernel - no action needed"
            exit 2  # Not applicable
        fi

        # Check if the module exists as a loadable module
        if ! find "/lib/modules/${kernel_ver}" -type f -name "${mod_name}.ko*" 2>/dev/null | grep -q .; then
            echo "[INFO] ${mod_name} module not found on system"
            exit 2  # Not applicable
        fi

        echo "[CHECK] Auditing ${mod_name} kernel module configuration..."

        # Check if module is currently loaded
        if lsmod | grep -qw "^${mod_name}"; then
            echo "[FAIL] ${mod_name} module is currently loaded"
            audit_result=1
        else
            echo "[PASS] ${mod_name} module is not loaded"
        fi

        # Check for install directive
        if grep -Prq "^\s*install\s+${mod_name}\s+/(?:usr/)?bin/(?:true|false)\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] install directive configured for ${mod_name}"
        else
            echo "[FAIL] install directive not configured for ${mod_name}"
            audit_result=1
        fi

        # Check for blacklist entry
        if grep -Prq "^\s*blacklist\s+${mod_name}\s*" "${conf_dir}/" 2>/dev/null; then
            echo "[PASS] ${mod_name} is blacklisted"
        else
            echo "[FAIL] ${mod_name} is not blacklisted"
            audit_result=1
        fi

        exit $audit_result
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.1.1.9
remediate_1_1_1_9() {
    # CIS 1.1.1.9 Remediation - Disable dccp kernel module

    mod_name="dccp"
    rule_id="1.1.1.9"
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
            if grep -q "^${BLOCK_START}" "$file"; then
                sed -i "/^${BLOCK_START}/,/^${BLOCK_END}/d" "$file"
                echo "[INFO] Removed existing managed block from ${file}"
            fi
        fi
    
        {
            echo ""
            echo "${BLOCK_START}"
            echo "${block_content}"
            echo "${BLOCK_END}"
        } >> "$file"
    }

    block_content="install ${mod_name} /bin/false
    blacklist ${mod_name}"

    update_managed_block "${conf_file}" "${block_content}"
    echo "[CONFIGURED] ${conf_file} updated with managed block"

    if lsmod | grep -qw "^${mod_name}"; then
        if modprobe -r "${mod_name}" 2>/dev/null; then
            echo "[UNLOADED] ${mod_name} module removed from kernel"
        else
            echo "[WARNING] Could not unload ${mod_name} - may be in use (will be disabled on reboot)"
        fi
    else
        echo "[OK] ${mod_name} module not currently loaded"
    fi

    if command -v update-initramfs >/dev/null 2>&1; then
        echo "[UPDATE] Updating initramfs..."
        update-initramfs -u -k all >/dev/null 2>&1 || true
    elif command -v dracut >/dev/null 2>&1; then
        echo "[UPDATE] Updating initramfs with dracut..."
        dracut -f >/dev/null 2>&1 || true
    fi

    echo "[SUCCESS] ${mod_name} module has been disabled"
}


# Audit function for rule 1.3.1.1
audit_1_3_1_1() {
    local output
    local exit_code
    
    output=$(
        if dpkg-query -s apparmor &>/dev/null; then
            if dpkg-query -s apparmor-utils &>/dev/null; then
                echo "apparmor and apparmor-utils are installed"
                exit 0  # Her ikisi de kurulu - BAŞARILI
            else
                echo "apparmor is installed but apparmor-utils is NOT installed"
                exit 1  # apparmor-utils eksik - BAŞARISIZ
            fi
        else
            echo "apparmor is NOT installed"
            exit 1  # apparmor eksik - BAŞARISIZ
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.3.1.1
remediate_1_3_1_1() {
    apt-get install -y apparmor apparmor-utils
}


# Audit function for rule 1.3.1.2
audit_1_3_1_2() {
    local output
    local exit_code
    
    output=$(
        if grep "^[[:space:]]*linux" /boot/grub/grub.cfg | grep -qv "apparmor=1"; then
            exit 1
        else
            if grep "^[[:space:]]*linux" /boot/grub/grub.cfg | grep -qv "security=apparmor"; then
                exit 1
            else
                exit 0
            fi
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.3.1.2
remediate_1_3_1_2() {
    # CIS 1.3.1.2 Remediation - Ensure AppArmor is enabled in bootloader

    GRUB_FILE="/etc/default/grub"

    # Backup if not already backed up
    if [[ ! -f "${GRUB_FILE}.original" ]]; then
        cp "$GRUB_FILE" "${GRUB_FILE}.original" || {
            echo "ERROR: Could not backup grub config"
            return 1
        }
    fi

    current=$(grep '^GRUB_CMDLINE_LINUX=' "$GRUB_FILE" 2>/dev/null | sed 's/^GRUB_CMDLINE_LINUX="\(.*\)"$/\1/' || echo "")

    new="$current"
    changed=""

    if [[ ! "$new" =~ (^|[[:space:]])apparmor=1([[:space:]]|$) ]]; then
        new="$new apparmor=1"
        changed=1
    fi

    if [[ ! "$new" =~ (^|[[:space:]])security=apparmor([[:space:]]|$) ]]; then
        new="$new security=apparmor"
        changed=1
    fi

    if [[ -n "$changed" ]]; then
        new=$(echo "$new" | xargs)
    
        # Update existing line or add new one
        if grep -q '^GRUB_CMDLINE_LINUX=' "$GRUB_FILE"; then
            sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$new\"|" "$GRUB_FILE"
        else
            echo "GRUB_CMDLINE_LINUX=\"$new\"" >> "$GRUB_FILE"
        fi
    
        # Update GRUB
        if command -v update-grub >/dev/null 2>&1; then
            update-grub 2>/dev/null || true
        elif command -v grub2-mkconfig >/dev/null 2>&1; then
            grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || \
                grub2-mkconfig -o /boot/grub/grub.cfg 2>/dev/null || true
        fi
    
        echo "SUCCESS: AppArmor bootloader parameters configured. Reboot required."
    else
        echo "ALREADY CONFIGURED: AppArmor bootloader parameters already present"
    fi
}


# Audit function for rule 1.3.1.3
audit_1_3_1_3() {
    local output
    local exit_code
    
    output=$(
        # CIS 1.3.1.3 Audit - Ensure all AppArmor Profiles are in enforce or complain mode

        # Check if apparmor_status is available
        if ! command -v apparmor_status >/dev/null 2>&1; then
            echo "ERROR: apparmor_status not found"
            exit 1
        fi

        # Check if AppArmor is running
        if ! systemctl is-active --quiet apparmor 2>/dev/null; then
            echo "ERROR: AppArmor not running"
            exit 1
        fi

        fail=0

        # Profile check
        loaded=$(apparmor_status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}' || echo "0")
        if [[ "$loaded" -eq 0 ]]; then
            echo "FAIL: No profiles loaded"
            fail=1
        else
            echo "PASS: $loaded profiles loaded"
        fi

        # Unconfined check
        unconfined=$(apparmor_status 2>/dev/null | grep "processes are unconfined but have a profile defined" | awk '{print $1}' || echo "0")
        if [[ "$unconfined" -gt 0 ]]; then
            echo "FAIL: $unconfined unconfined processes"
            fail=1
        else
            echo "PASS: No unconfined processes"
        fi

        if [[ $fail -eq 0 ]]; then
            echo "AUDIT PASSED"
            exit 0
        else
            echo "AUDIT FAILED"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.3.1.3
remediate_1_3_1_3() {
    # CIS 1.3.1.3 Remediation - Ensure AppArmor profiles are in enforce or complain mode

    # Check for root
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Must run as root"
        return 1
    fi

    # Install utils if needed
    if ! command -v aa-enforce >/dev/null 2>&1; then
        apt-get install -y apparmor-utils >/dev/null 2>&1 || {
            echo "ERROR: Could not install apparmor-utils"
            return 1
        }
    fi

    # Start service if not running
    if ! systemctl is-active --quiet apparmor; then
        systemctl start apparmor || {
            echo "ERROR: Could not start apparmor service"
            return 1
        }
    fi

    # Enable service
    systemctl enable apparmor >/dev/null 2>&1 || true

    # Set all profiles to enforce mode
    echo "Setting profiles to enforce mode..."
    aa-enforce /etc/apparmor.d/* 2>&1 | grep -v "Warning" || true

    # Reload
    systemctl reload apparmor || true

    # Check for unconfined
    unconfined=$(apparmor_status 2>/dev/null | grep "processes are unconfined but have a profile defined" | awk '{print $1}' || echo "0")

    if [[ "$unconfined" -gt 0 ]]; then
        echo "WARNING: $unconfined unconfined processes - restart may be required"
        apparmor_status 2>/dev/null | grep -A 20 "processes are unconfined" | grep "^   " || true
    else
        echo "SUCCESS: All processes confined"
    fi

    echo "SUCCESS: Remediation completed"
}


# Audit function for rule 1.3.1.4
audit_1_3_1_4() {
    local output
    local exit_code
    
    output=$(
        # CIS 1.3.1.4 Audit - Level 2 (ENFORCE ONLY)

        # Check if apparmor_status is available
        if ! command -v apparmor_status >/dev/null 2>&1; then
            echo "FAIL: apparmor_status not found"
            exit 1
        fi

        # Check if AppArmor is running
        if ! systemctl is-active --quiet apparmor 2>/dev/null; then
            echo "FAIL: AppArmor not running"
            exit 1
        fi

        fail=0

        # Check profiles - MUST be enforce only (excluding snap profiles)
        loaded=$(apparmor_status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}' || echo "0")
        enforce=$(apparmor_status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
        complain=$(apparmor_status 2>/dev/null | grep "profiles are in complain mode" | awk '{print $1}' || echo "0")

        # Count non-snap profiles in complain mode
        non_snap_complain=0
        if [[ "$complain" -gt 0 ]]; then
            non_snap_complain=$(apparmor_status 2>/dev/null | sed -n '/profiles are in complain mode/,/profiles are in enforce mode/p' | grep "^   " | grep -v "snap\." | wc -l || echo "0")
        fi

        if [[ "$loaded" -eq 0 ]]; then
            echo "FAIL: No profiles loaded"
            fail=1
        elif [[ "$non_snap_complain" -gt 0 ]]; then
            echo "FAIL: $non_snap_complain non-snap profiles in complain mode (Level 2 requires enforce only)"
            fail=1
        else
            echo "PASS: All non-snap profiles in enforce mode (Total: $loaded loaded, $complain snap profiles in complain mode - ignored)"
        fi

        # Check unconfined
        unconfined=$(apparmor_status 2>/dev/null | grep "processes are unconfined but have a profile defined" | awk '{print $1}' || echo "0")

        if [[ "$unconfined" -gt 0 ]]; then
            echo "FAIL: $unconfined unconfined processes"
            fail=1
        else
            echo "PASS: No unconfined processes"
        fi

        if [[ $fail -eq 0 ]]; then
            echo "Level 2 PASS"
            exit 0
        else
            echo "Level 2 FAIL"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.3.1.4
remediate_1_3_1_4() {
    # CIS 1.3.1.4 Remediation - Level 2 (ENFORCE ONLY)

    # Check for root
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: Must run as root"
        return 1
    fi

    # Install utils if needed
    if ! command -v aa-enforce >/dev/null 2>&1; then
        apt-get install -y apparmor-utils >/dev/null 2>&1 || {
            echo "ERROR: Could not install apparmor-utils"
            return 1
        }
    fi

    # Ensure service is running
    if ! systemctl is-active --quiet apparmor; then
        systemctl start apparmor || {
            echo "ERROR: Could not start apparmor service"
            return 1
        }
    fi

    # Enable service
    systemctl enable apparmor >/dev/null 2>&1 || true

    # Remove any symlinks from force-complain directory
    if [[ -d /etc/apparmor.d/force-complain ]]; then
        echo "Removing profiles from force-complain directory..."
        rm -f /etc/apparmor.d/force-complain/* 2>/dev/null || true
    fi

    # Set ALL profiles to enforce mode (Level 2 requirement - excluding snap profiles)
    echo "Setting profiles to ENFORCE mode (Level 2)..."
    for profile in /etc/apparmor.d/*; do
        if [[ -f "$profile" ]]; then
            profile_name=$(basename "$profile")
            # Skip snap profiles
            [[ "$profile_name" == snap.* ]] && continue
            echo "Setting $profile_name to enforce mode."
            aa-enforce "$profile" 2>&1 | grep -v "Warning" || true
        fi
    done

    # Reload AppArmor
    systemctl reload apparmor || true

    # Wait a moment for reload to complete
    sleep 1

    # Verify no complain mode profiles remain
    complain=$(apparmor_status 2>/dev/null | grep "profiles are in complain mode" | awk '{print $1}' || echo "0")
    if [[ "$complain" -gt 0 ]]; then
        echo "WARNING: $complain profiles still in complain mode"
        echo "Profiles in complain mode:"
        apparmor_status 2>/dev/null | sed -n '/profiles are in complain mode/,/profiles are in enforce mode/p' | grep "^   " || true
    else
        echo "SUCCESS: All profiles in enforce mode"
    fi

    # Check for unconfined processes
    unconfined=$(apparmor_status 2>/dev/null | grep "processes are unconfined but have a profile defined" | awk '{print $1}' || echo "0")
    if [[ "$unconfined" -gt 0 ]]; then
        echo "WARNING: $unconfined unconfined processes - restart may be required"
        apparmor_status 2>/dev/null | sed -n '/processes are unconfined/,/^$/p' | grep "^   " || true
    else
        echo "SUCCESS: All processes confined"
    fi

    echo "SUCCESS: Level 2 remediation completed"
}


# Audit function for rule 1.4.1
audit_1_4_1() {
    local output
    local exit_code
    
    output=$(
        # CIS Ubuntu 24.04 Benchmark
        # 1.4.1 Ensure bootloader password is set (Automated)
        # Profile: Level 1 - Server, Level 1 - Workstation

        # Color codes for output
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[1;33m'
        NC='\033[0m' # No Color

        # Initialize counters
        PASSED=0
        FAILED=0

        echo "======================================"
        echo "CIS 1.4.1 - Bootloader Password Audit"
        echo "======================================"
        echo ""

        # Detect GRUB configuration file location
        if [ -f "/boot/grub/grub.cfg" ]; then
            GRUB_CFG="/boot/grub/grub.cfg"
        elif [ -f "/boot/grub2/grub.cfg" ]; then
            GRUB_CFG="/boot/grub2/grub.cfg"
        else
            echo -e "${RED}[FAIL]${NC} GRUB configuration file not found"
            echo "Expected location: /boot/grub/grub.cfg or /boot/grub2/grub.cfg"
            echo "This system may not use GRUB bootloader"
            exit 1
        fi

        echo "Using GRUB config: $GRUB_CFG"
        echo ""

        # Check 1: Superuser configuration
        echo "Check 1: Superuser Configuration"
        echo "---------------------------------------"

        SUPERUSER_LINE=$(grep "^set superusers" "$GRUB_CFG" 2>/dev/null)

        if [ -n "$SUPERUSER_LINE" ]; then
            # Extract username from the line
            SUPERUSER=$(echo "$SUPERUSER_LINE" | sed 's/^set superusers="\(.*\)"/\1/')
    
            if [ -n "$SUPERUSER" ]; then
                echo -e "${GREEN}[PASS]${NC} Superuser is configured"
                echo "  Found: $SUPERUSER_LINE"
                ((PASSED++))
            else
                echo -e "${RED}[FAIL]${NC} Superuser is defined but empty"
                echo "  Found: $SUPERUSER_LINE"
                ((FAILED++))
            fi
        else
            echo -e "${RED}[FAIL]${NC} No superuser configured"
            echo "  Expected: set superusers=\"<username>\""
            ((FAILED++))
        fi

        echo ""

        # Check 2: Password hash configuration
        echo "Check 2: Password Hash Configuration"
        echo "---------------------------------------"

        # Fixed regex: Use grep -E for extended regex or escape properly
        # Look for lines starting with optional spaces, then "password"
        PASSWORD_LINES=$(grep -E "^[[:space:]]*password" "$GRUB_CFG" 2>/dev/null)

        if [ -n "$PASSWORD_LINES" ]; then
            # Check if it's PBKDF2 encrypted
            if echo "$PASSWORD_LINES" | grep -q "password_pbkdf2"; then
                echo -e "${GREEN}[PASS]${NC} PBKDF2 password hash found"
        
                # Show only the password type and username, not the full hash
                echo "$PASSWORD_LINES" | while IFS= read -r line; do
                    # Extract username from password line
                    PASSWORD_USER=$(echo "$line" | awk '{print $2}')
                    echo "  User: $PASSWORD_USER (PBKDF2-SHA512)"
                done
        
                ((PASSED++))
            else
                echo -e "${YELLOW}[WARN]${NC} Password found but not using PBKDF2"
                echo "$PASSWORD_LINES" | sed 's/^/  /'
                echo "  Recommendation: Use grub-mkpasswd-pbkdf2 for strong encryption"
                ((FAILED++))
            fi
        else
            echo -e "${RED}[FAIL]${NC} No password configured"
            echo "  Expected: password_pbkdf2 <username> <hash>"
            ((FAILED++))
        fi

        echo ""

        # Additional check: Verify superuser and password user match
        if [ -n "$SUPERUSER" ] && [ -n "$PASSWORD_LINES" ]; then
            PASSWORD_USER=$(echo "$PASSWORD_LINES" | grep "password_pbkdf2" | head -1 | awk '{print $2}')
    
            if [ "$SUPERUSER" = "$PASSWORD_USER" ]; then
                echo -e "${GREEN}[INFO]${NC} Superuser and password user match: $SUPERUSER"
            else
                echo -e "${YELLOW}[WARN]${NC} Superuser ($SUPERUSER) and password user ($PASSWORD_USER) mismatch"
                echo "  This may cause authentication issues"
            fi
            echo ""
        fi

        # Summary
        echo "======================================"
        echo "Summary"
        echo "======================================"
        echo -e "Passed checks: ${GREEN}$PASSED${NC}"
        echo -e "Failed checks: ${RED}$FAILED${NC}"
        echo ""

        if [ $FAILED -eq 0 ]; then
            echo -e "${GREEN}[COMPLIANT]${NC} Bootloader password is properly configured"
            exit 0
        else
            echo -e "${RED}[NON-COMPLIANT]${NC} Bootloader password must be configured"
            echo ""
            echo "Remediation required:"
            echo "1. Create encrypted password: grub-mkpasswd-pbkdf2"
            echo "2. Add configuration to /etc/grub.d/40_custom"
            echo "3. Run: update-grub (Debian/Ubuntu) or grub2-mkconfig (RHEL/CentOS)"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.4.1
remediate_1_4_1() {
    # CIS Ubuntu 24.04 Benchmark
    # 1.4.1 Ensure bootloader password is set (Automated)
    # Remediation Script - Non-Interactive Version
    #
    # NOTE: This rule requires manual intervention to set a GRUB password.
    # The script checks current status and provides instructions.
    # For security reasons, passwords cannot be set non-interactively.

    echo "==========================================="
    echo "CIS 1.4.1 - Bootloader Password Status"
    echo "==========================================="
    echo ""

    # Detect GRUB config location
    GRUB_CFG=""
    for cfg in "/boot/grub/grub.cfg" "/boot/grub2/grub.cfg"; do
        if [ -f "$cfg" ]; then
            GRUB_CFG="$cfg"
            break
        fi
    done

    if [ -z "$GRUB_CFG" ]; then
        echo "[WARNING] GRUB configuration file not found"
        echo "This system may use a different bootloader"
        return 0
    fi

    # Check if password is already configured
    if grep -q "^set superusers=" "$GRUB_CFG" 2>/dev/null && \
       grep -q "^password_pbkdf2" "$GRUB_CFG" 2>/dev/null; then
        echo "[PASS] Bootloader password is already configured"
        echo ""
        echo "Current configuration:"
        grep "^set superusers=" "$GRUB_CFG" | head -1
        echo "(password hash exists)"
        return 0
    fi

    # Password not configured - provide instructions
    echo "[FAIL] Bootloader password is NOT configured"
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                    MANUAL ACTION REQUIRED                        ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "This rule requires setting a GRUB bootloader password interactively."
    echo "For security reasons, this cannot be automated without user input."
    echo ""
    echo "To configure manually, run these commands:"
    echo ""
    echo "  1. Generate password hash:"
    echo "     sudo grub-mkpasswd-pbkdf2"
    echo ""
    echo "  2. Create configuration file:"
    echo "     sudo nano /etc/grub.d/40_custom_password"
    echo ""
    echo "  3. Add the following (replace values with your own):"
    echo "     #!/bin/sh"
    echo "     exec tail -n +3 \$0"
    echo "     set superusers=\"grubadmin\""
    echo "     password_pbkdf2 grubadmin <your-hash-here>"
    echo ""
    echo "  4. Make executable and update GRUB:"
    echo "     sudo chmod 755 /etc/grub.d/40_custom_password"
    echo "     sudo update-grub"
    echo ""
    echo "  5. Test by rebooting and pressing 'e' in GRUB menu"
    echo ""
    echo "WARNING: Store your password securely! If forgotten, you may need"
    echo "         a Live CD/USB to recover access to your system."
    echo ""

    # Return failure to indicate remediation is needed
    return 1
}


# Audit function for rule 1.4.2
audit_1_4_2() {
    local output
    local exit_code
    
    output=$(
        # 1.4.2 Ensure permissions on bootloader config are configured (Automated)
        # Description: The grub configuration file contains information on boot settings 
        # and passwords for unlocking boot options.
        # Rationale: Setting the permissions to read and write for root only prevents 
        # non-root users from seeing the boot parameters or changing them. Non-root users 
        # who read the boot parameters may be able to identify weaknesses in security 
        # upon boot and be able to exploit them.

        echo "=== 1.4.2 Bootloader Config Permissions Check ==="
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

        echo "Checking permissions on $GRUB_CFG..."
        echo "Command: stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' $GRUB_CFG"
        echo ""

        # Get file stats
        FILE_STATS=$(stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' "$GRUB_CFG" 2>/dev/null)
        echo "Current: $FILE_STATS"
        echo "Expected: Access: (0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)"
        echo ""

        # Get individual values
        PERMISSIONS=$(stat -Lc '%a' "$GRUB_CFG" 2>/dev/null)
        OWNER_UID=$(stat -Lc '%u' "$GRUB_CFG" 2>/dev/null)
        GROUP_GID=$(stat -Lc '%g' "$GRUB_CFG" 2>/dev/null)

        # Check 1: Verify Uid is 0 (root)
        echo "1. Owner (Uid) Check:"
        if [ "$OWNER_UID" == "0" ]; then
            echo -e "   ${GREEN}[PASS]${NC} Owner is root (Uid: 0)"
            ((PASSED++))
        else
            echo -e "   ${RED}[FAIL]${NC} Owner is not root (Uid: $OWNER_UID)"
            ((FAILED++))
        fi

        # Check 2: Verify Gid is 0 (root)
        echo ""
        echo "2. Group (Gid) Check:"
        if [ "$GROUP_GID" == "0" ]; then
            echo -e "   ${GREEN}[PASS]${NC} Group is root (Gid: 0)"
            ((PASSED++))
        else
            echo -e "   ${RED}[FAIL]${NC} Group is not root (Gid: $GROUP_GID)"
            ((FAILED++))
        fi

        # Check 3: Verify permissions are 0600 or more restrictive
        echo ""
        echo "3. Permissions Check:"
        # Permissions should be 0600 or more restrictive (0400, 0000)
        if [ "$PERMISSIONS" == "600" ] || [ "$PERMISSIONS" == "400" ] || [ "$PERMISSIONS" == "000" ]; then
            echo -e "   ${GREEN}[PASS]${NC} Permissions are correctly set ($PERMISSIONS)"
            ((PASSED++))
        else
            echo -e "   ${RED}[FAIL]${NC} Permissions are too permissive ($PERMISSIONS)"
            echo "   Expected: 600 or more restrictive"
            ((FAILED++))
        fi

        echo ""
        echo "=== Summary ==="
        echo -e "${GREEN}Successful Checks: $PASSED${NC}"
        echo -e "${RED}Failed Checks: $FAILED${NC}"
        echo ""

        if [ $FAILED -eq 0 ]; then
            echo -e "${GREEN}Result: COMPLIANT${NC}"
            echo "Bootloader configuration permissions are properly set."
            exit 0
        else
            echo -e "${RED}Result: NON-COMPLIANT${NC}"
            echo "Bootloader configuration permissions must be corrected!"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.4.2
remediate_1_4_2() {
    # 1.4.2 Ensure permissions on bootloader config are configured (Automated)
    # Remediation: Set correct ownership and permissions on grub configuration file

    echo "=== 1.4.2 Bootloader Config Permissions Remediation ==="
    echo ""

    # Check possible GRUB config locations
    GRUB_CFG=""
    for cfg in "/boot/grub/grub.cfg" "/boot/grub2/grub.cfg" "/boot/efi/EFI/*/grub.cfg"; do
        if [ -f "$cfg" ]; then
            GRUB_CFG="$cfg"
            break
        fi
    done

    # Check if GRUB configuration file exists
    if [ -z "$GRUB_CFG" ] || [ ! -f "$GRUB_CFG" ]; then
        echo "[WARNING] GRUB configuration file not found"
        echo "Checked: /boot/grub/grub.cfg, /boot/grub2/grub.cfg"
        echo "Note: GRUB2 may not be installed or configured differently"
        return 0  # Not an error, might be a different bootloader
    fi

    echo "Found GRUB config: $GRUB_CFG"
    echo ""
    echo "Current permissions:"
    stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' "$GRUB_CFG"
    echo ""

    echo "Applying remediation..."
    echo ""

    # Set ownership to root:root
    echo "1. Setting ownership to root:root..."
    if chown root:root "$GRUB_CFG"; then
        echo "   [OK] Ownership set successfully"
    else
        echo "   [ERROR] Failed to set ownership"
        return 1
    fi

    # Set permissions to 0600
    echo "2. Setting permissions to 0600..."
    if chmod u-x,go-rwx "$GRUB_CFG"; then
        echo "   [OK] Permissions set successfully"
    else
        echo "   [ERROR] Failed to set permissions"
        return 1
    fi

    echo ""
    echo "New permissions:"
    stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' "$GRUB_CFG"
    echo ""
    echo "[SUCCESS] Remediation completed successfully."
}


# Audit function for rule 1.5.1
audit_1_5_1() {
    local output
    local exit_code
    
    output=$(
        # 1.5.1 Ensure address space layout randomization is enabled (Automated)
        # Description: Address space layout randomization (ASLR) is an exploit mitigation 
        # technique which randomly arranges the address space of key data areas of a process.
        # Rationale: Randomly placing virtual memory regions will make it difficult to write 
        # memory page exploits as the memory placement will be consistently shifting.

        {
            a_output=(); a_output2=(); a_parlist=("kernel.randomize_va_space=2")
            l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"
    
            f_kernel_parameter_chk()
            {
                l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= '{print $2}' | xargs)" # Check running configuration
                if grep -Pq -- '\b'"$l_parameter_value"'\b' <<< "$l_running_parameter_value"; then
                    a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_running_parameter_value\" in the running configuration")
                else
                    a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_running_parameter_value\" in the running configuration and should have a value of: \"$l_value_out\"")
                fi
        
                unset A_out; declare -A A_out # Check durable setting (files)
                while read -r l_out; do
                    if [ -n "$l_out" ]; then
                        if [[ $l_out =~ ^\s*# ]]; then
                            l_file="${l_out//# /}"
                        else
                            l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                            [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_file")
                        fi
                    fi
                done < <("$l_systemdsysctl" --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')
        
                if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
                    l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)"
                    l_kpar="${l_kpar//\//.}"
                    [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf")
                fi
        
                if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
                    while IFS="=" read -r l_fkpname l_file_parameter_value; do
                        l_fkpname="${l_fkpname// /}"; l_file_parameter_value="${l_file_parameter_value// /}"
                        if grep -Pq -- '\b'"$l_parameter_value"'\b' <<< "$l_file_parameter_value"; then
                            a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\"")
                        else
                            a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_value_out\"")
                        fi
                    done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}")
                else
                    a_output2+=(" - \"$l_parameter_name\" is not set in an included file" \
                        " ** Note: \"$l_parameter_name\" May be set in a file that's ignored by load procedure **")
                fi
            }
    
            l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)"
            while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters
                l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}"
                l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }"
                l_value_out="$(tr -d '(){}' <<< "$l_value_out")"
                f_kernel_parameter_chk
            done < <(printf '%s\n' "${a_parlist[@]}")
    
            if [ "${#a_output2[@]}" -le 0 ]; then
                printf '%s\n' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" ""
                exit 0
            else
                printf '%s\n' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
                [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "" "- Correctly set:" "${a_output[@]}" ""
                exit 1
            fi
        }
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.5.1
remediate_1_5_1() {
    # 1.5.1 Ensure address space layout randomization is enabled (Automated)
    # Remediation: Set kernel.randomize_va_space = 2 in sysctl configuration
    # Description: ASLR is an exploit mitigation technique which randomly arranges 
    # the address space of key data areas of a process.

    echo "=== 1.5.1 ASLR Remediation ==="
    echo ""

    SYSCTL_CONF="/etc/sysctl.d/60-kernel_sysctl.conf"
    PARAM_NAME="kernel.randomize_va_space"
    PARAM_VALUE="2"

    echo "Setting $PARAM_NAME = $PARAM_VALUE"
    echo ""

    # Check current running value
    echo "1. Current running configuration:"
    CURRENT_VALUE=$(sysctl -n "$PARAM_NAME" 2>/dev/null)
    echo "   $PARAM_NAME = $CURRENT_VALUE"
    echo ""

    # Set the parameter in configuration file
    echo "2. Setting durable configuration in $SYSCTL_CONF..."

    # Create the file if it doesn't exist, or update if it does
    if [ -f "$SYSCTL_CONF" ]; then
        # Check if the parameter already exists in the file
        if grep -q "^$PARAM_NAME" "$SYSCTL_CONF"; then
            # Update existing parameter
            sed -i "s/^$PARAM_NAME.*/$PARAM_NAME = $PARAM_VALUE/" "$SYSCTL_CONF"
            echo "   [OK] Updated existing parameter in $SYSCTL_CONF"
        else
            # Append the parameter
            printf "%s\n" "$PARAM_NAME = $PARAM_VALUE" >> "$SYSCTL_CONF"
            echo "   [OK] Added parameter to $SYSCTL_CONF"
        fi
    else
        # Create new file with the parameter
        printf "%s\n" "$PARAM_NAME = $PARAM_VALUE" >> "$SYSCTL_CONF"
        echo "   [OK] Created $SYSCTL_CONF with parameter"
    fi

    # Apply the setting to the running kernel
    echo ""
    echo "3. Applying to running kernel..."
    sysctl -w "$PARAM_NAME=$PARAM_VALUE"
    if [ $? -eq 0 ]; then
        echo "   [OK] Applied successfully"
    else
        echo "   [ERROR] Failed to apply kernel parameter"
        return 1
    fi

    # Verify
    echo ""
    echo "4. Verification:"
    NEW_VALUE=$(sysctl -n "$PARAM_NAME" 2>/dev/null)
    echo "   $PARAM_NAME = $NEW_VALUE"

    if [ "$NEW_VALUE" = "$PARAM_VALUE" ]; then
        echo ""
        echo "[SUCCESS] ASLR is now enabled with value $PARAM_VALUE"
    else
        echo ""
        echo "[ERROR] Failed to set ASLR value"
        return 1
    fi
}


# Audit function for rule 1.5.2
audit_1_5_2() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.5.2 - Ensure ptrace_scope is restricted (Automated)
        # Profile: Level 1 - Server, Level 1 - Workstation
        #
        # NOTE: Ubuntu ships with /etc/sysctl.d/10-ptrace.conf which sets
        # kernel.yama.ptrace_scope = 1 by default (already CIS compliant)

        audit_ptrace_scope() {
            local l_output=""
            local l_output2=""
            local l_parameter_name="kernel.yama.ptrace_scope"
    
            # Check running configuration
            local l_running_value
            l_running_value="$(sysctl -n "$l_parameter_name" 2>/dev/null)"
    
            if [ -z "$l_running_value" ]; then
                l_output2="$l_output2\n - Unable to read $l_parameter_name from running configuration (Yama LSM may not be enabled)"
            elif [[ "$l_running_value" =~ ^[123]$ ]]; then
                l_output="$l_output\n - \"$l_parameter_name\" is correctly set to \"$l_running_value\" in the running configuration"
            else
                l_output2="$l_output2\n - \"$l_parameter_name\" is incorrectly set to \"$l_running_value\" in the running configuration (should be 1, 2, or 3)"
            fi
    
            # Check durable settings in configuration files
            local l_file_found=false
            local l_file_value=""
            local l_config_file=""
    
            # Check /etc/sysctl.conf and /etc/sysctl.d/*.conf
            # Only match lines that are NOT commented out (no leading #)
            for l_file in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
                if [ -f "$l_file" ]; then
                    # Extract only uncommented lines, get the last occurrence
                    local l_match
                    l_match="$(grep -E "^[^#]*$l_parameter_name\s*=" "$l_file" 2>/dev/null | tail -1)"
                    if [ -n "$l_match" ]; then
                        l_file_value="$(echo "$l_match" | awk -F= '{print $2}' | tr -d ' \t')"
                        if [ -n "$l_file_value" ]; then
                            l_file_found=true
                            l_config_file="$l_file"
                        fi
                    fi
                fi
            done
    
            # Check UFW sysctl file if exists
            if [ -f /etc/default/ufw ]; then
                local l_ufwscf
                l_ufwscf="$(awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw | tr -d '"')"
                if [ -n "$l_ufwscf" ] && [ -f "$l_ufwscf" ]; then
                    local l_match
                    l_match="$(grep -E "^[^#]*$l_parameter_name\s*=" "$l_ufwscf" 2>/dev/null | tail -1)"
                    if [ -n "$l_match" ]; then
                        local l_ufw_value
                        l_ufw_value="$(echo "$l_match" | awk -F= '{print $2}' | tr -d ' \t')"
                        if [ -n "$l_ufw_value" ]; then
                            l_file_found=true
                            l_file_value="$l_ufw_value"
                            l_config_file="$l_ufwscf"
                        fi
                    fi
                fi
            fi
    
            if [ "$l_file_found" = true ]; then
                if [[ "$l_file_value" =~ ^[123]$ ]]; then
                    l_output="$l_output\n - \"$l_parameter_name\" is correctly set to \"$l_file_value\" in \"$l_config_file\""
                else
                    l_output2="$l_output2\n - \"$l_parameter_name\" is incorrectly set to \"$l_file_value\" in \"$l_config_file\" (should be 1, 2, or 3)"
                fi
            else
                l_output2="$l_output2\n - \"$l_parameter_name\" is not set in any sysctl configuration file"
                l_output2="$l_output2\n   (Note: Check if the value is commented out or file is missing)"
            fi
    
            # Output results
            if [ -z "$l_output2" ]; then
                echo -e "\n- Audit Result: ** PASS **"
                echo -e "$l_output\n"
                return 0
            else
                echo -e "\n- Audit Result: ** FAIL **"
                echo -e " - Reason(s) for audit failure:"
                echo -e "$l_output2"
                if [ -n "$l_output" ]; then
                    echo -e "\n- Correctly set:"
                    echo -e "$l_output\n"
                fi
                return 1
            fi
        }

        audit_ptrace_scope
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.5.2
remediate_1_5_2() {
    # CIS Benchmark 1.5.2 - Ensure ptrace_scope is restricted (Automated)
    # Profile: Level 1 - Server, Level 1 - Workstation
    #
    # Remediation: Set kernel.yama.ptrace_scope to 1 (restricted ptrace)
    #
    # NOTE: Ubuntu ships with /etc/sysctl.d/10-ptrace.conf by default.
    # This script uses a dedicated file /etc/sysctl.d/60-ptrace_scope.conf
    # to ensure our setting takes precedence (higher number = loaded later)

    remediate_ptrace_scope() {
        local l_parameter_name="kernel.yama.ptrace_scope"
        local l_parameter_value="1"  # Using restricted mode (value 1) as default
        local l_sysctl_file="/etc/sysctl.d/60-ptrace_scope.conf"
    
        echo "Setting $l_parameter_name to $l_parameter_value..."
    
        # Create directory if it doesn't exist
        if [ ! -d "/etc/sysctl.d" ]; then
            mkdir -p /etc/sysctl.d
        fi
    
        # Comment out (not delete) any existing entries to preserve original config
        for l_file in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
            if [ -f "$l_file" ] && [ "$l_file" != "$l_sysctl_file" ]; then
                # Only modify if there's an uncommented entry
                if grep -Eq "^[^#]*$l_parameter_name\s*=" "$l_file" 2>/dev/null; then
                    echo " - Commenting out existing entry in $l_file"
                    sed -i "s/^\([^#]*$l_parameter_name\s*=\)/# \1/" "$l_file"
                fi
            fi
        done
    
        # Check and update UFW sysctl file if exists
        if [ -f /etc/default/ufw ]; then
            local l_ufwscf
            l_ufwscf="$(awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw | tr -d '"')"
            if [ -n "$l_ufwscf" ] && [ -f "$l_ufwscf" ]; then
                if grep -Eq "^[^#]*$l_parameter_name\s*=" "$l_ufwscf" 2>/dev/null; then
                    echo " - Commenting out existing entry in $l_ufwscf"
                    sed -i "s/^\([^#]*$l_parameter_name\s*=\)/# \1/" "$l_ufwscf"
                fi
            fi
        fi
    
        # Create or overwrite our dedicated configuration file
        echo " - Writing $l_parameter_name=$l_parameter_value to $l_sysctl_file"
        printf '%s\n' \
            "# CIS Benchmark 1.5.2 - Ensure ptrace_scope is restricted" \
            "# Generated by remediation script on $(date)" \
            "# Values: 1=restricted, 2=admin-only, 3=no attach (irreversible)" \
            "$l_parameter_name=$l_parameter_value" > "$l_sysctl_file"
    
        # Set the active kernel parameter
        echo " - Applying to running kernel..."
        if sysctl -w "$l_parameter_name=$l_parameter_value" > /dev/null 2>&1; then
            echo " - Successfully set $l_parameter_name to $l_parameter_value in running configuration"
        else
            echo " - WARNING: Failed to set $l_parameter_name in running configuration"
            echo "   Yama LSM may not be enabled in the kernel"
            return 1
        fi
    
        echo ""
        echo "Remediation complete."
        echo ""
        echo "Configuration saved to: $l_sysctl_file"
        echo ""
        echo "Value meanings:"
        echo "  1 = Restricted ptrace (only descendants can be traced)"
        echo "  2 = Admin-only attach (requires CAP_SYS_PTRACE)"
        echo "  3 = No attach (ptrace completely disabled, irreversible until reboot)"
        echo ""
        echo "If a value of 2 or 3 is required by local site policy,"
        echo "edit $l_sysctl_file and run: sysctl -p $l_sysctl_file"
    
        return 0
    }

    remediate_ptrace_scope
}


# Audit function for rule 1.5.3
audit_1_5_3() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.5.3 - Ensure core dumps are restricted
        # Audit Script

        audit_passed=true

        # Check 1: Verify hard core limit is set to 0
        echo "Checking hard core limit..."
        if grep -Pqs -- '^\h*\*\h+hard\h+core\h+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
            echo "PASS: Hard core limit is set to 0"
        else
            echo "FAIL: Hard core limit is not set to 0"
            audit_passed=false
        fi

        # Check 2: Verify fs.suid_dumpable is set to 0 in running configuration
        echo "Checking fs.suid_dumpable in running configuration..."
        running_value=$(sysctl -n fs.suid_dumpable 2>/dev/null)
        if [ "$running_value" = "0" ]; then
            echo "PASS: fs.suid_dumpable is correctly set to 0 in running configuration"
        else
            echo "FAIL: fs.suid_dumpable is set to '$running_value' in running configuration (should be 0)"
            audit_passed=false
        fi

        # Check 3: Verify fs.suid_dumpable is set in durable configuration
        echo "Checking fs.suid_dumpable in durable configuration..."
        durable_set=false
        for file in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
            if [ -f "$file" ]; then
                if grep -Pqs -- '^\h*fs\.suid_dumpable\h*=\h*0\b' "$file"; then
                    echo "PASS: fs.suid_dumpable=0 is set in $file"
                    durable_set=true
                    break
                fi
            fi
        done

        if [ "$durable_set" = false ]; then
            echo "FAIL: fs.suid_dumpable=0 is not set in any sysctl configuration file"
            audit_passed=false
        fi

        # Check 4: If systemd-coredump is installed, verify its configuration
        echo "Checking systemd-coredump configuration..."
        if systemctl list-unit-files 2>/dev/null | grep -q coredump; then
            echo "INFO: systemd-coredump is installed, checking configuration..."
    
            storage_ok=false
            processsize_ok=false
            storage_file=""
            processsize_file=""
    
            # Check /etc/systemd/coredump.conf and /etc/systemd/coredump.conf.d/*.conf
            config_files="/etc/systemd/coredump.conf"
            if [ -d "/etc/systemd/coredump.conf.d" ]; then
                config_files="$config_files $(find /etc/systemd/coredump.conf.d -name '*.conf' 2>/dev/null | tr '\n' ' ')"
            fi
    
            for conf_file in $config_files; do
                if [ -f "$conf_file" ]; then
                    if grep -Pqs -- '^\h*Storage\h*=\h*none\b' "$conf_file"; then
                        storage_ok=true
                        storage_file="$conf_file"
                    fi
            
                    if grep -Pqs -- '^\h*ProcessSizeMax\h*=\h*0\b' "$conf_file"; then
                        processsize_ok=true
                        processsize_file="$conf_file"
                    fi
                fi
            done
    
            if [ "$storage_ok" = true ] && [ "$processsize_ok" = true ]; then
                echo "PASS: systemd-coredump is correctly configured"
                echo "  - Storage=none found in $storage_file"
                echo "  - ProcessSizeMax=0 found in $processsize_file"
            else
                if [ "$storage_ok" = false ]; then
                    echo "FAIL: Storage=none is not set in any coredump configuration file"
                    audit_passed=false
                fi
                if [ "$processsize_ok" = false ]; then
                    echo "FAIL: ProcessSizeMax=0 is not set in any coredump configuration file"
                    audit_passed=false
                fi
            fi
        else
            echo "INFO: systemd-coredump is not installed (no additional configuration needed)"
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - Core dumps are properly restricted"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - Core dumps are not properly restricted"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.5.3
remediate_1_5_3() {
    # CIS Benchmark 1.5.3 - Ensure core dumps are restricted
    # Remediation Script

    echo "Applying remediation for CIS 1.5.3 - Ensure core dumps are restricted..."

    # Remediation 1: Set hard core limit to 0
    echo "Setting hard core limit to 0..."
    limits_file="/etc/security/limits.d/99-core-dumps.conf"

    # Check if already set in limits.conf or limits.d
    if ! grep -Pqs -- '^\h*\*\h+hard\h+core\h+0\b' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
        echo "* hard core 0" > "$limits_file"
        echo "Created $limits_file with hard core limit set to 0"
    else
        echo "Hard core limit is already set to 0"
    fi

    # Remediation 2: Set fs.suid_dumpable to 0 in durable configuration
    echo "Setting fs.suid_dumpable=0 in sysctl configuration..."
    sysctl_file="/etc/sysctl.d/60-fs_sysctl.conf"

    # Check if already set correctly
    if ! grep -Pqs -- '^\h*fs\.suid_dumpable\h*=\h*0\b' /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null; then
        # Create or append to sysctl file
        if [ -f "$sysctl_file" ]; then
            # Remove any existing fs.suid_dumpable entries to avoid conflicts
            sed -i '/^\s*fs\.suid_dumpable/d' "$sysctl_file"
        fi
        echo "fs.suid_dumpable = 0" >> "$sysctl_file"
        echo "Added fs.suid_dumpable=0 to $sysctl_file"
    else
        echo "fs.suid_dumpable=0 is already set in durable configuration"
    fi

    # Remediation 3: Apply kernel parameter immediately
    echo "Applying fs.suid_dumpable=0 to running configuration..."
    if sysctl -w fs.suid_dumpable=0 > /dev/null 2>&1; then
        echo "Successfully set fs.suid_dumpable=0 in running configuration"
    else
        echo "WARNING: Failed to set fs.suid_dumpable=0 in running configuration"
    fi

    # Remediation 4: Configure systemd-coredump if installed
    if systemctl list-unit-files 2>/dev/null | grep -q coredump; then
        echo "systemd-coredump is installed, applying additional configuration..."
    
        coredump_conf="/etc/systemd/coredump.conf"
        coredump_dir="/etc/systemd/coredump.conf.d"
    
        # Create coredump.conf.d directory if it doesn't exist
        if [ ! -d "$coredump_dir" ]; then
            mkdir -p "$coredump_dir"
        fi
    
        # Create override configuration
        override_file="$coredump_dir/99-disable-coredump.conf"
        printf '%s\n' \
            "[Coredump]" \
            "Storage=none" \
            "ProcessSizeMax=0" > "$override_file"
        echo "Created $override_file with Storage=none and ProcessSizeMax=0"
    
        # Reload systemd daemon
        if systemctl daemon-reload; then
            echo "Successfully reloaded systemd daemon"
        else
            echo "WARNING: Failed to reload systemd daemon"
        fi
    else
        echo "systemd-coredump is not installed, skipping additional configuration"
    fi

    echo ""
    echo "Remediation complete for CIS 1.5.3 - Ensure core dumps are restricted"
    echo "Note: A system reboot may be required for all changes to take full effect"
}


# Audit function for rule 1.5.4
audit_1_5_4() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.5.4 - Ensure prelink is not installed
        # Audit Script

        echo "Checking if prelink is installed..."

        if dpkg-query -s prelink &>/dev/null; then
            echo "FAIL: prelink is installed"
            echo ""
            echo "AUDIT RESULT: FAIL - prelink should not be installed"
            exit 1
        else
            echo "PASS: prelink is not installed"
            echo ""
            echo "AUDIT RESULT: PASS - prelink is not installed"
            exit 0
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.5.4
remediate_1_5_4() {
    # CIS Benchmark 1.5.4 - Ensure prelink is not installed
    # Remediation Script

    echo "Applying remediation for CIS 1.5.4 - Ensure prelink is not installed..."

    # Check if prelink is installed
    if dpkg-query -s prelink &>/dev/null; then
        echo "prelink is installed, removing..."
    
        # Restore binaries to normal before uninstalling
        echo "Restoring binaries to normal state..."
        if command -v prelink &>/dev/null; then
            if prelink -ua 2>/dev/null; then
                echo "Successfully restored binaries to normal"
            else
                echo "WARNING: Failed to restore binaries (prelink -ua)"
            fi
        fi
    
        # Uninstall prelink
        echo "Uninstalling prelink..."
        if apt purge -y prelink; then
            echo "Successfully removed prelink"
        else
            echo "ERROR: Failed to remove prelink"
            return 1
        fi
    else
        echo "prelink is not installed, no action needed"
    fi

    echo ""
    echo "Remediation complete for CIS 1.5.4 - Ensure prelink is not installed"
}


# Audit function for rule 1.5.5
audit_1_5_5() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.5.5 - Ensure Automatic Error Reporting is not enabled
        # Audit Script

        audit_passed=true

        echo "Checking Apport Error Reporting Service..."

        # Check 1: Verify apport is not installed or not enabled
        echo "Checking if apport is installed and enabled..."
        if dpkg-query -s apport &>/dev/null; then
            echo "INFO: apport package is installed"
    
            # Check if enabled in /etc/default/apport
            if [ -f /etc/default/apport ]; then
                if grep -Pqi -- '^\h*enabled\h*=\h*[^0]\b' /etc/default/apport; then
                    echo "FAIL: Apport is enabled in /etc/default/apport"
                    audit_passed=false
                else
                    echo "PASS: Apport is disabled in /etc/default/apport (enabled=0 or not set)"
                fi
            else
                echo "INFO: /etc/default/apport does not exist"
            fi
        else
            echo "PASS: apport package is not installed"
        fi

        # Check 2: Verify apport service is not active
        echo "Checking if apport service is active..."
        if systemctl is-active apport.service 2>/dev/null | grep -q '^active'; then
            echo "FAIL: apport.service is active"
            audit_passed=false
        else
            echo "PASS: apport.service is not active"
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - Automatic Error Reporting is not enabled"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - Automatic Error Reporting is enabled"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.5.5
remediate_1_5_5() {
    # CIS Benchmark 1.5.5 - Ensure Automatic Error Reporting is not enabled
    # Remediation Script

    echo "Applying remediation for CIS 1.5.5 - Ensure Automatic Error Reporting is not enabled..."

    # Check if apport is installed
    if dpkg-query -s apport &>/dev/null; then
        echo "apport is installed, disabling..."
    
        # Disable apport in /etc/default/apport
        apport_default="/etc/default/apport"
        if [ -f "$apport_default" ]; then
            echo "Configuring $apport_default..."
            if grep -Pq '^\h*enabled\h*=' "$apport_default"; then
                # Replace existing enabled line
                sed -i 's/^\s*enabled\s*=.*/enabled=0/' "$apport_default"
                echo "Updated enabled=0 in $apport_default"
            else
                # Add enabled=0 if not present
                echo "enabled=0" >> "$apport_default"
                echo "Added enabled=0 to $apport_default"
            fi
        else
            # Create the file with enabled=0
            echo "enabled=0" > "$apport_default"
            echo "Created $apport_default with enabled=0"
        fi
    
        # Stop and mask the apport service
        echo "Stopping apport service..."
        if systemctl stop apport.service 2>/dev/null; then
            echo "Successfully stopped apport.service"
        else
            echo "INFO: apport.service was not running or could not be stopped"
        fi
    
        echo "Masking apport service..."
        if systemctl mask apport.service 2>/dev/null; then
            echo "Successfully masked apport.service"
        else
            echo "WARNING: Failed to mask apport.service"
        fi
    else
        echo "apport is not installed, no action needed"
    fi

    echo ""
    echo "Remediation complete for CIS 1.5.5 - Ensure Automatic Error Reporting is not enabled"
}


# Audit function for rule 1.6.1
audit_1_6_1() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.6.1 - Ensure message of the day is configured properly
        # Audit Script

        audit_passed=true

        echo "Checking /etc/motd configuration..."

        # Check if /etc/motd exists
        if [ -f /etc/motd ]; then
            echo "INFO: /etc/motd exists"
            echo ""
            echo "Current /etc/motd contents:"
            echo "----------------------------"
            cat /etc/motd
            echo "----------------------------"
            echo ""
    
            # Get OS ID for checking
            os_id=$(grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')
    
            # Check for prohibited content (OS info disclosure)
            echo "Checking for prohibited content..."
    
            # Build the pattern
            pattern="(\\\\v|\\\\r|\\\\m|\\\\s"
            if [ -n "$os_id" ]; then
                pattern="${pattern}|${os_id}"
            fi
            pattern="${pattern})"
    
            if grep -E -i "$pattern" /etc/motd &>/dev/null; then
                echo "FAIL: /etc/motd contains OS information that should be removed"
                echo "Found matches:"
                grep -E -i "$pattern" /etc/motd
                audit_passed=false
            else
                echo "PASS: /etc/motd does not contain prohibited OS information"
            fi
        else
            echo "INFO: /etc/motd does not exist (this is acceptable)"
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - Message of the day is configured properly"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - Message of the day contains prohibited content"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.6.1
remediate_1_6_1() {
    # CIS Benchmark 1.6.1 - Ensure message of the day is configured properly
    # Remediation Script

    echo "Applying remediation for CIS 1.6.1 - Ensure message of the day is configured properly..."

    motd_file="/etc/motd"

    # Check if /etc/motd exists
    if [ -f "$motd_file" ]; then
        echo "Checking $motd_file for prohibited content..."
    
        # Get OS ID
        os_id=$(grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')
    
        # Remove escape sequences that display OS information
        echo "Removing OS information escape sequences..."
    
        # Create a temporary file with cleaned content
        sed -i 's/\\m//g; s/\\r//g; s/\\s//g; s/\\v//g' "$motd_file"
    
        # Remove OS name references (case insensitive)
        if [ -n "$os_id" ]; then
            sed -i "s/$os_id//gi" "$motd_file"
        fi
    
        echo "Cleaned $motd_file of prohibited content"
    
        # Check if file is now empty or contains only whitespace
        if [ ! -s "$motd_file" ] || ! grep -q '[^[:space:]]' "$motd_file"; then
            echo "INFO: $motd_file is empty after cleanup"
            echo "Consider adding an appropriate message of the day or removing the file"
        fi
    else
        echo "INFO: $motd_file does not exist, no action needed"
    fi

    echo ""
    echo "Remediation complete for CIS 1.6.1 - Ensure message of the day is configured properly"
    echo ""
    echo "NOTE: Please review /etc/motd and add appropriate content according to your site policy"
    echo "The file should contain a legal warning banner without OS-specific information"
}


# Audit function for rule 1.6.2
audit_1_6_2() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.6.2 - Ensure local login warning banner is configured properly
        # Audit Script

        audit_passed=true

        echo "Checking /etc/issue configuration..."

        # Check if /etc/issue exists
        if [ -f /etc/issue ]; then
            echo "INFO: /etc/issue exists"
            echo ""
            echo "Current /etc/issue contents:"
            echo "----------------------------"
            cat /etc/issue
            echo "----------------------------"
            echo ""
    
            # Get OS ID for checking
            os_id=$(grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')
    
            # Check for prohibited content (OS info disclosure)
            echo "Checking for prohibited content..."
    
            # Build the pattern
            pattern="(\\\\v|\\\\r|\\\\m|\\\\s"
            if [ -n "$os_id" ]; then
                pattern="${pattern}|${os_id}"
            fi
            pattern="${pattern})"
    
            if grep -E -i "$pattern" /etc/issue &>/dev/null; then
                echo "FAIL: /etc/issue contains OS information that should be removed"
                echo "Found matches:"
                grep -E -i "$pattern" /etc/issue
                audit_passed=false
            else
                echo "PASS: /etc/issue does not contain prohibited OS information"
            fi
        else
            echo "FAIL: /etc/issue does not exist - a warning banner should be configured"
            audit_passed=false
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - Local login warning banner is configured properly"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - Local login warning banner is not configured properly"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.6.2
remediate_1_6_2() {
    # CIS Benchmark 1.6.2 - Ensure local login warning banner is configured properly
    # Remediation Script

    echo "Applying remediation for CIS 1.6.2 - Ensure local login warning banner is configured properly..."

    issue_file="/etc/issue"

    # Default warning banner message
    default_banner="Authorized users only. All activity may be monitored and reported."

    # Check if /etc/issue exists
    if [ -f "$issue_file" ]; then
        echo "Checking $issue_file for prohibited content..."
    
        # Get OS ID
        os_id=$(grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')
    
        # Remove escape sequences that display OS information
        echo "Removing OS information escape sequences..."
    
        # Create cleaned content
        sed -i 's/\\m//g; s/\\r//g; s/\\s//g; s/\\v//g' "$issue_file"
    
        # Remove OS name references (case insensitive)
        if [ -n "$os_id" ]; then
            sed -i "s/$os_id//gi" "$issue_file"
        fi
    
        echo "Cleaned $issue_file of prohibited content"
    
        # Check if file is now empty or contains only whitespace
        if [ ! -s "$issue_file" ] || ! grep -q '[^[:space:]]' "$issue_file"; then
            echo "INFO: $issue_file is empty after cleanup, setting default banner"
            echo "$default_banner" > "$issue_file"
        fi
    else
        echo "INFO: $issue_file does not exist, creating with default banner"
        echo "$default_banner" > "$issue_file"
    fi

    echo ""
    echo "Current $issue_file contents:"
    echo "----------------------------"
    cat "$issue_file"
    echo "----------------------------"
    echo ""
    echo "Remediation complete for CIS 1.6.2 - Ensure local login warning banner is configured properly"
    echo ""
    echo "NOTE: Please review /etc/issue and customize according to your site policy"
}


# Audit function for rule 1.6.3
audit_1_6_3() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.6.3 - Ensure remote login warning banner is configured properly
        # Audit Script

        audit_passed=true

        echo "Checking /etc/issue.net configuration..."

        # Check if /etc/issue.net exists
        if [ -f /etc/issue.net ]; then
            echo "INFO: /etc/issue.net exists"
            echo ""
            echo "Current /etc/issue.net contents:"
            echo "----------------------------"
            cat /etc/issue.net
            echo "----------------------------"
            echo ""
    
            # Get OS ID for checking
            os_id=$(grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')
    
            # Check for prohibited content (OS info disclosure)
            echo "Checking for prohibited content..."
    
            # Build the pattern
            pattern="(\\\\v|\\\\r|\\\\m|\\\\s"
            if [ -n "$os_id" ]; then
                pattern="${pattern}|${os_id}"
            fi
            pattern="${pattern})"
    
            if grep -E -i "$pattern" /etc/issue.net &>/dev/null; then
                echo "FAIL: /etc/issue.net contains OS information that should be removed"
                echo "Found matches:"
                grep -E -i "$pattern" /etc/issue.net
                audit_passed=false
            else
                echo "PASS: /etc/issue.net does not contain prohibited OS information"
            fi
        else
            echo "FAIL: /etc/issue.net does not exist - a warning banner should be configured"
            audit_passed=false
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - Remote login warning banner is configured properly"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - Remote login warning banner is not configured properly"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.6.3
remediate_1_6_3() {
    # CIS Benchmark 1.6.3 - Ensure remote login warning banner is configured properly
    # Remediation Script

    echo "Applying remediation for CIS 1.6.3 - Ensure remote login warning banner is configured properly..."

    issue_net_file="/etc/issue.net"

    # Default warning banner message
    default_banner="Authorized users only. All activity may be monitored and reported."

    # Check if /etc/issue.net exists
    if [ -f "$issue_net_file" ]; then
        echo "Checking $issue_net_file for prohibited content..."
    
        # Get OS ID
        os_id=$(grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | sed -e 's/"//g')
    
        # Remove escape sequences that display OS information
        echo "Removing OS information escape sequences..."
    
        # Create cleaned content
        sed -i 's/\\m//g; s/\\r//g; s/\\s//g; s/\\v//g' "$issue_net_file"
    
        # Remove OS name references (case insensitive)
        if [ -n "$os_id" ]; then
            sed -i "s/$os_id//gi" "$issue_net_file"
        fi
    
        echo "Cleaned $issue_net_file of prohibited content"
    
        # Check if file is now empty or contains only whitespace
        if [ ! -s "$issue_net_file" ] || ! grep -q '[^[:space:]]' "$issue_net_file"; then
            echo "INFO: $issue_net_file is empty after cleanup, setting default banner"
            echo "$default_banner" > "$issue_net_file"
        fi
    else
        echo "INFO: $issue_net_file does not exist, creating with default banner"
        echo "$default_banner" > "$issue_net_file"
    fi

    echo ""
    echo "Current $issue_net_file contents:"
    echo "----------------------------"
    cat "$issue_net_file"
    echo "----------------------------"
    echo ""
    echo "Remediation complete for CIS 1.6.3 - Ensure remote login warning banner is configured properly"
    echo ""
    echo "NOTE: Please review /etc/issue.net and customize according to your site policy"
}


# Audit function for rule 1.6.4
audit_1_6_4() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.6.4 - Ensure access to /etc/motd is configured
        # Audit Script

        audit_passed=true

        echo "Checking /etc/motd access configuration..."

        motd_file="/etc/motd"

        # Check if /etc/motd exists
        if [ -e "$motd_file" ]; then
            echo "INFO: $motd_file exists"
    
            # Resolve symlinks
            real_file=$(readlink -e "$motd_file")
    
            # Get file permissions, owner, and group
            file_perms=$(stat -Lc '%a' "$real_file")
            file_uid=$(stat -Lc '%u' "$real_file")
            file_gid=$(stat -Lc '%g' "$real_file")
    
            echo "Current status:"
            stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' "$real_file"
            echo ""
    
            # Check ownership (should be root:root, uid=0, gid=0)
            if [ "$file_uid" -eq 0 ] && [ "$file_gid" -eq 0 ]; then
                echo "PASS: Owner and group are root (0:0)"
            else
                echo "FAIL: Owner ($file_uid) and/or group ($file_gid) are not root (0)"
                audit_passed=false
            fi
    
            # Check permissions (should be 644 or more restrictive)
            # 644 means: owner=rw (6), group=r (4), others=r (4)
            # More restrictive means:
            # - Owner: 0, 2, 4, or 6 (no execute bit, max rw)
            # - Group: 0 or 4 only (no write, no execute)
            # - Others: 0 or 4 only (no write, no execute)
    
            # Pad permissions to 3 digits
            padded_perms=$(printf "%03d" "$file_perms")
    
            # Extract individual permission digits
            owner_perm=${padded_perms:0:1}
            group_perm=${padded_perms:1:1}
            other_perm=${padded_perms:2:1}
    
            perm_ok=true
            perm_errors=""
    
            # Check owner permissions (should be 0, 2, 4, or 6 - no execute, max rw)
            case "$owner_perm" in
                0|2|4|6) ;;
                *) perm_ok=false; perm_errors="$perm_errors Owner has invalid permission ($owner_perm)." ;;
            esac
    
            # Check group permissions (should be 0 or 4 only - read or none)
            case "$group_perm" in
                0|4) ;;
                *) perm_ok=false; perm_errors="$perm_errors Group has invalid permission ($group_perm)." ;;
            esac
    
            # Check other permissions (should be 0 or 4 only - read or none)
            case "$other_perm" in
                0|4) ;;
                *) perm_ok=false; perm_errors="$perm_errors Others has invalid permission ($other_perm)." ;;
            esac
    
            if [ "$perm_ok" = true ]; then
                echo "PASS: Permissions ($file_perms) are 644 or more restrictive"
            else
                echo "FAIL: Permissions ($file_perms) are not compliant"
                echo "      Errors:$perm_errors"
                echo "      Expected: 644 or more restrictive (e.g., 644, 640, 600, 400, 444, 440, 404, 000)"
                audit_passed=false
            fi
        else
            echo "INFO: $motd_file does not exist (this is acceptable)"
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - Access to /etc/motd is configured properly"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - Access to /etc/motd is not configured properly"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.6.4
remediate_1_6_4() {
    # CIS Benchmark 1.6.4 - Ensure access to /etc/motd is configured
    # Remediation Script

    echo "Applying remediation for CIS 1.6.4 - Ensure access to /etc/motd is configured..."

    motd_file="/etc/motd"

    # Check if /etc/motd exists
    if [ -e "$motd_file" ]; then
        # Resolve symlinks to get the real file
        real_file=$(readlink -e "$motd_file")
    
        if [ -n "$real_file" ]; then
            echo "Configuring access for $real_file..."
        
            # Set ownership to root:root
            echo "Setting ownership to root:root..."
            if chown root:root "$real_file"; then
                echo "Successfully set ownership to root:root"
            else
                echo "ERROR: Failed to set ownership"
                return 1
            fi
        
            # Set permissions to 644
            echo "Setting permissions to 644..."
            if chmod 644 "$real_file"; then
                echo "Successfully set permissions to 644"
            else
                echo "ERROR: Failed to set permissions"
                return 1
            fi
        
            # Display new status
            echo ""
            echo "New status:"
            stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' "$real_file"
        else
            echo "ERROR: Could not resolve $motd_file"
            return 1
        fi
    else
        echo "INFO: $motd_file does not exist, no action needed"
    fi

    echo ""
    echo "Remediation complete for CIS 1.6.4 - Ensure access to /etc/motd is configured"
}


# Audit function for rule 1.6.5
audit_1_6_5() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.6.5 - Ensure access to /etc/issue is configured
        # Audit Script

        audit_passed=true

        echo "Checking /etc/issue access configuration..."

        issue_file="/etc/issue"

        # Check if /etc/issue exists
        if [ -e "$issue_file" ]; then
            echo "INFO: $issue_file exists"
    
            # Resolve symlinks
            real_file=$(readlink -e "$issue_file")
    
            # Get file permissions, owner, and group
            file_perms=$(stat -Lc '%a' "$real_file")
            file_uid=$(stat -Lc '%u' "$real_file")
            file_gid=$(stat -Lc '%g' "$real_file")
    
            echo "Current status:"
            stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' "$real_file"
            echo ""
    
            # Check ownership (should be root:root, uid=0, gid=0)
            if [ "$file_uid" -eq 0 ] && [ "$file_gid" -eq 0 ]; then
                echo "PASS: Owner and group are root (0:0)"
            else
                echo "FAIL: Owner ($file_uid) and/or group ($file_gid) are not root (0)"
                audit_passed=false
            fi
    
            # Check permissions (should be 644 or more restrictive)
            # 644 means: owner=rw (6), group=r (4), others=r (4)
            # More restrictive means:
            # - Owner: 0, 2, 4, or 6 (no execute bit, max rw)
            # - Group: 0 or 4 only (no write, no execute)
            # - Others: 0 or 4 only (no write, no execute)
    
            # Pad permissions to 3 digits
            padded_perms=$(printf "%03d" "$file_perms")
    
            # Extract individual permission digits
            owner_perm=${padded_perms:0:1}
            group_perm=${padded_perms:1:1}
            other_perm=${padded_perms:2:1}
    
            perm_ok=true
            perm_errors=""
    
            # Check owner permissions (should be 0, 2, 4, or 6 - no execute, max rw)
            case "$owner_perm" in
                0|2|4|6) ;;
                *) perm_ok=false; perm_errors="$perm_errors Owner has invalid permission ($owner_perm)." ;;
            esac
    
            # Check group permissions (should be 0 or 4 only - read or none)
            case "$group_perm" in
                0|4) ;;
                *) perm_ok=false; perm_errors="$perm_errors Group has invalid permission ($group_perm)." ;;
            esac
    
            # Check other permissions (should be 0 or 4 only - read or none)
            case "$other_perm" in
                0|4) ;;
                *) perm_ok=false; perm_errors="$perm_errors Others has invalid permission ($other_perm)." ;;
            esac
    
            if [ "$perm_ok" = true ]; then
                echo "PASS: Permissions ($file_perms) are 644 or more restrictive"
            else
                echo "FAIL: Permissions ($file_perms) are not compliant"
                echo "      Errors:$perm_errors"
                echo "      Expected: 644 or more restrictive (e.g., 644, 640, 600, 400, 444, 440, 404, 000)"
                audit_passed=false
            fi
        else
            echo "FAIL: $issue_file does not exist"
            audit_passed=false
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - Access to /etc/issue is configured properly"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - Access to /etc/issue is not configured properly"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.6.5
remediate_1_6_5() {
    # CIS Benchmark 1.6.5 - Ensure access to /etc/issue is configured
    # Remediation Script

    echo "Applying remediation for CIS 1.6.5 - Ensure access to /etc/issue is configured..."

    issue_file="/etc/issue"

    # Check if /etc/issue exists
    if [ -e "$issue_file" ]; then
        # Resolve symlinks to get the real file
        real_file=$(readlink -e "$issue_file")
    
        if [ -n "$real_file" ]; then
            echo "Configuring access for $real_file..."
        
            # Set ownership to root:root
            echo "Setting ownership to root:root..."
            if chown root:root "$real_file"; then
                echo "Successfully set ownership to root:root"
            else
                echo "ERROR: Failed to set ownership"
                return 1
            fi
        
            # Set permissions to 644
            echo "Setting permissions to 644..."
            if chmod 644 "$real_file"; then
                echo "Successfully set permissions to 644"
            else
                echo "ERROR: Failed to set permissions"
                return 1
            fi
        
            # Display new status
            echo ""
            echo "New status:"
            stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' "$real_file"
        else
            echo "ERROR: Could not resolve $issue_file"
            return 1
        fi
    else
        echo "WARNING: $issue_file does not exist"
        echo "Consider creating it with an appropriate warning banner"
    fi

    echo ""
    echo "Remediation complete for CIS 1.6.5 - Ensure access to /etc/issue is configured"
}


# Audit function for rule 1.6.6
audit_1_6_6() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.6.6 - Ensure access to /etc/issue.net is configured
        # Audit Script

        audit_passed=true

        echo "Checking /etc/issue.net access configuration..."

        issue_net_file="/etc/issue.net"

        # Check if /etc/issue.net exists
        if [ -e "$issue_net_file" ]; then
            echo "INFO: $issue_net_file exists"
    
            # Resolve symlinks
            real_file=$(readlink -e "$issue_net_file")
    
            # Get file permissions, owner, and group
            file_perms=$(stat -Lc '%a' "$real_file")
            file_uid=$(stat -Lc '%u' "$real_file")
            file_gid=$(stat -Lc '%g' "$real_file")
    
            echo "Current status:"
            stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' "$real_file"
            echo ""
    
            # Check ownership (should be root:root, uid=0, gid=0)
            if [ "$file_uid" -eq 0 ] && [ "$file_gid" -eq 0 ]; then
                echo "PASS: Owner and group are root (0:0)"
            else
                echo "FAIL: Owner ($file_uid) and/or group ($file_gid) are not root (0)"
                audit_passed=false
            fi
    
            # Check permissions (should be 644 or more restrictive)
            # 644 means: owner=rw (6), group=r (4), others=r (4)
            # More restrictive means:
            # - Owner: 0, 2, 4, or 6 (no execute bit, max rw)
            # - Group: 0 or 4 only (no write, no execute)
            # - Others: 0 or 4 only (no write, no execute)
    
            # Pad permissions to 3 digits
            padded_perms=$(printf "%03d" "$file_perms")
    
            # Extract individual permission digits
            owner_perm=${padded_perms:0:1}
            group_perm=${padded_perms:1:1}
            other_perm=${padded_perms:2:1}
    
            perm_ok=true
            perm_errors=""
    
            # Check owner permissions (should be 0, 2, 4, or 6 - no execute, max rw)
            case "$owner_perm" in
                0|2|4|6) ;;
                *) perm_ok=false; perm_errors="$perm_errors Owner has invalid permission ($owner_perm)." ;;
            esac
    
            # Check group permissions (should be 0 or 4 only - read or none)
            case "$group_perm" in
                0|4) ;;
                *) perm_ok=false; perm_errors="$perm_errors Group has invalid permission ($group_perm)." ;;
            esac
    
            # Check other permissions (should be 0 or 4 only - read or none)
            case "$other_perm" in
                0|4) ;;
                *) perm_ok=false; perm_errors="$perm_errors Others has invalid permission ($other_perm)." ;;
            esac
    
            if [ "$perm_ok" = true ]; then
                echo "PASS: Permissions ($file_perms) are 644 or more restrictive"
            else
                echo "FAIL: Permissions ($file_perms) are not compliant"
                echo "      Errors:$perm_errors"
                echo "      Expected: 644 or more restrictive (e.g., 644, 640, 600, 400, 444, 440, 404, 000)"
                audit_passed=false
            fi
        else
            echo "FAIL: $issue_net_file does not exist"
            audit_passed=false
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - Access to /etc/issue.net is configured properly"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - Access to /etc/issue.net is not configured properly"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.6.6
remediate_1_6_6() {
    # CIS Benchmark 1.6.6 - Ensure access to /etc/issue.net is configured
    # Remediation Script

    echo "Applying remediation for CIS 1.6.6 - Ensure access to /etc/issue.net is configured..."

    issue_net_file="/etc/issue.net"

    # Check if /etc/issue.net exists
    if [ -e "$issue_net_file" ]; then
        # Resolve symlinks to get the real file
        real_file=$(readlink -e "$issue_net_file")
    
        if [ -n "$real_file" ]; then
            echo "Configuring access for $real_file..."
        
            # Set ownership to root:root
            echo "Setting ownership to root:root..."
            if chown root:root "$real_file"; then
                echo "Successfully set ownership to root:root"
            else
                echo "ERROR: Failed to set ownership"
                return 1
            fi
        
            # Set permissions to 644
            echo "Setting permissions to 644..."
            if chmod 644 "$real_file"; then
                echo "Successfully set permissions to 644"
            else
                echo "ERROR: Failed to set permissions"
                return 1
            fi
        
            # Display new status
            echo ""
            echo "New status:"
            stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' "$real_file"
        else
            echo "ERROR: Could not resolve $issue_net_file"
            return 1
        fi
    else
        echo "WARNING: $issue_net_file does not exist"
        echo "Consider creating it with an appropriate warning banner"
    fi

    echo ""
    echo "Remediation complete for CIS 1.6.6 - Ensure access to /etc/issue.net is configured"
}


# Audit function for rule 1.7.1
audit_1_7_1() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.7.1 - Ensure GDM is removed
        # Audit Script

        echo "Checking if GDM (gdm3) is installed..."

        # Check if gdm3 is installed
        gdm_status=$(dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null)

        if [ "$gdm_status" = "installed" ]; then
            echo "FAIL: gdm3 is installed"
            echo ""
            echo "Package status:"
            dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' gdm3
            echo ""
            echo "AUDIT RESULT: FAIL - GDM (gdm3) is installed and should be removed"
            exit 1
        else
            echo "PASS: gdm3 is not installed"
            echo ""
            echo "AUDIT RESULT: PASS - GDM (gdm3) is not installed"
            exit 0
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.7.1
remediate_1_7_1() {
    # CIS Benchmark 1.7.1 - Ensure GDM is removed
    # Remediation Script

    echo "Applying remediation for CIS 1.7.1 - Ensure GDM is removed..."

    # Check if gdm3 is installed
    gdm_status=$(dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null)

    if [ "$gdm_status" = "installed" ]; then
        echo "gdm3 is installed, removing..."
    
        echo ""
        echo "WARNING: This will remove the GNOME Display Manager and the graphical login interface."
        echo "         The system will no longer have a GUI login screen after this operation."
        echo ""
    
        # Purge gdm3 package
        echo "Purging gdm3 package..."
        if apt purge -y gdm3; then
            echo "Successfully purged gdm3"
        else
            echo "ERROR: Failed to purge gdm3"
            return 1
        fi
    
        # Remove unused dependencies
        echo "Removing unused dependencies..."
        apt autoremove -y || echo "WARNING: Failed to autoremove dependencies"
    else
        echo "gdm3 is not installed, no action needed"
    fi

    echo ""
    echo "Remediation complete for CIS 1.7.1 - Ensure GDM is removed"
}


# Audit function for rule 1.7.2
audit_1_7_2() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.7.2 - Ensure GDM login banner is configured
        # Audit Script

        audit_passed=true

        echo "Checking GDM login banner configuration..."

        # First check if GDM is installed
        if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
            echo "INFO: GDM (gdm3) is not installed"
            echo "      This check is not applicable if GDM is not installed"
            echo ""
            echo "AUDIT RESULT: PASS - GDM is not installed (not applicable)"
            exit 0
        fi

        echo "GDM is installed, checking banner configuration..."

        # Check dconf database configuration (machine-wide settings)
        dconf_profile="/etc/dconf/profile/gdm"
        banner_config="/etc/dconf/db/gdm.d/01-banner-message"

        echo ""
        echo "Checking dconf configuration..."

        # Check if dconf profile exists
        if [ -f "$dconf_profile" ]; then
            echo "PASS: dconf profile exists at $dconf_profile"
        else
            echo "FAIL: dconf profile does not exist at $dconf_profile"
            audit_passed=false
        fi

        # Check if banner configuration file exists
        if [ -f "$banner_config" ]; then
            echo "PASS: Banner configuration file exists at $banner_config"
    
            # Check banner-message-enable
            if grep -Pq '^\s*banner-message-enable\s*=\s*true' "$banner_config"; then
                echo "PASS: banner-message-enable is set to true"
            else
                echo "FAIL: banner-message-enable is not set to true"
                audit_passed=false
            fi
    
            # Check banner-message-text
            if grep -Pq '^\s*banner-message-text\s*=' "$banner_config"; then
                banner_text=$(grep -P '^\s*banner-message-text\s*=' "$banner_config")
                echo "PASS: banner-message-text is configured"
                echo "      Current value: $banner_text"
            else
                echo "FAIL: banner-message-text is not configured"
                audit_passed=false
            fi
        else
            echo "FAIL: Banner configuration file does not exist at $banner_config"
            audit_passed=false
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - GDM login banner is configured properly"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - GDM login banner is not configured properly"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.7.2
remediate_1_7_2() {
    # CIS Benchmark 1.7.2 - Ensure GDM login banner is configured
    # Remediation Script

    echo "Applying remediation for CIS 1.7.2 - Ensure GDM login banner is configured..."

    # Default banner message
    BANNER_MESSAGE="Authorized uses only. All activity may be monitored and reported."

    # First check if GDM is installed
    if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
        echo "INFO: GDM (gdm3) is not installed"
        echo "      No action needed - this rule is not applicable"
        exit 0
    fi

    echo "GDM is installed, configuring login banner..."

    # Create dconf profile for gdm
    dconf_profile="/etc/dconf/profile/gdm"
    echo "Creating/updating dconf profile at $dconf_profile..."

    mkdir -p /etc/dconf/profile
    printf '%s\n' \
        "user-db:user" \
        "system-db:gdm" \
        "file-db:/usr/share/gdm/greeter-dconf-defaults" > "$dconf_profile"

    echo "Created dconf profile"

    # Create banner message configuration
    banner_config_dir="/etc/dconf/db/gdm.d"
    banner_config="$banner_config_dir/01-banner-message"

    echo "Creating banner configuration at $banner_config..."

    mkdir -p "$banner_config_dir"
    printf '%s\n' \
        "[org/gnome/login-screen]" \
        "banner-message-enable=true" \
        "banner-message-text='$BANNER_MESSAGE'" > "$banner_config"

    echo "Created banner configuration"

    # Update dconf database
    echo "Updating dconf database..."
    if command -v dconf &>/dev/null; then
        dconf update
        echo "Successfully updated dconf database"
    else
        echo "WARNING: dconf command not found, database not updated"
        echo "         Run 'dconf update' manually after installing dconf"
    fi

    echo ""
    echo "Current configuration:"
    echo "----------------------"
    echo "dconf profile ($dconf_profile):"
    cat "$dconf_profile"
    echo ""
    echo "Banner config ($banner_config):"
    cat "$banner_config"
    echo "----------------------"
    echo ""
    echo "Remediation complete for CIS 1.7.2 - Ensure GDM login banner is configured"
    echo ""
    echo "NOTE: Users must log out and back in again for the settings to take effect"
    echo "      A system restart may be required for CIS-CAT Assessor to appropriately assess"
}


# Audit function for rule 1.7.3
audit_1_7_3() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.7.3 - Ensure GDM disable-user-list option is enabled
        # Audit Script

        audit_passed=true

        echo "Checking GDM disable-user-list configuration..."

        # First check if GDM is installed
        if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
            echo "INFO: GDM (gdm3) is not installed"
            echo "      This check is not applicable if GDM is not installed"
            echo ""
            echo "AUDIT RESULT: PASS - GDM is not installed (not applicable)"
            exit 0
        fi

        echo "GDM is installed, checking disable-user-list configuration..."

        # Check dconf database configuration (machine-wide settings)
        dconf_profile="/etc/dconf/profile/gdm"
        login_screen_config="/etc/dconf/db/gdm.d/00-login-screen"

        echo ""
        echo "Checking dconf configuration..."

        # Check if dconf profile exists
        if [ -f "$dconf_profile" ]; then
            echo "PASS: dconf profile exists at $dconf_profile"
        else
            echo "FAIL: dconf profile does not exist at $dconf_profile"
            audit_passed=false
        fi

        # Check if login-screen configuration file exists
        if [ -f "$login_screen_config" ]; then
            echo "PASS: Login screen configuration file exists at $login_screen_config"
    
            # Check disable-user-list setting
            if grep -Pq '^\s*disable-user-list\s*=\s*true' "$login_screen_config"; then
                echo "PASS: disable-user-list is set to true"
            else
                echo "FAIL: disable-user-list is not set to true"
                audit_passed=false
            fi
        else
            echo "FAIL: Login screen configuration file does not exist at $login_screen_config"
            audit_passed=false
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - GDM disable-user-list option is enabled"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - GDM disable-user-list option is not enabled"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.7.3
remediate_1_7_3() {
    # CIS Benchmark 1.7.3 - Ensure GDM disable-user-list option is enabled
    # Remediation Script

    echo "Applying remediation for CIS 1.7.3 - Ensure GDM disable-user-list option is enabled..."

    # First check if GDM is installed
    if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
        echo "INFO: GDM (gdm3) is not installed"
        echo "      No action needed - this rule is not applicable"
        exit 0
    fi

    echo "GDM is installed, configuring disable-user-list..."

    # Create dconf profile for gdm
    dconf_profile="/etc/dconf/profile/gdm"
    echo "Creating/updating dconf profile at $dconf_profile..."

    mkdir -p /etc/dconf/profile
    printf '%s\n' \
        "user-db:user" \
        "system-db:gdm" \
        "file-db:/usr/share/gdm/greeter-dconf-defaults" > "$dconf_profile"

    echo "Created dconf profile"

    # Create login-screen configuration
    login_screen_config_dir="/etc/dconf/db/gdm.d"
    login_screen_config="$login_screen_config_dir/00-login-screen"

    echo "Creating login-screen configuration at $login_screen_config..."

    mkdir -p "$login_screen_config_dir"
    printf '%s\n' \
        "[org/gnome/login-screen]" \
        "# Do not show the user list" \
        "disable-user-list=true" > "$login_screen_config"

    echo "Created login-screen configuration"

    # Update dconf database
    echo "Updating dconf database..."
    if command -v dconf &>/dev/null; then
        dconf update
        echo "Successfully updated dconf database"
    else
        echo "WARNING: dconf command not found, database not updated"
        echo "         Run 'dconf update' manually after installing dconf"
    fi

    echo ""
    echo "Current configuration:"
    echo "----------------------"
    echo "dconf profile ($dconf_profile):"
    cat "$dconf_profile"
    echo ""
    echo "Login screen config ($login_screen_config):"
    cat "$login_screen_config"
    echo "----------------------"
    echo ""
    echo "Remediation complete for CIS 1.7.3 - Ensure GDM disable-user-list option is enabled"
    echo ""
    echo "NOTE: Users must log out and back in again for the settings to take effect"
}


# Audit function for rule 1.7.4
audit_1_7_4() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.7.4 - Ensure GDM screen locks when the user is idle
        # Audit Script

        # Configuration thresholds
        MAX_LOCK_DELAY=5      # Maximum lock-delay in seconds (5 or less)
        MAX_IDLE_DELAY=900    # Maximum idle-delay in seconds (900 or less, not 0)

        audit_passed=true

        echo "Checking GDM screen lock configuration..."

        # First check if GDM is installed
        if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
            echo "INFO: GDM (gdm3) is not installed"
            echo "      This check is not applicable if GDM is not installed"
            echo ""
            echo "AUDIT RESULT: PASS - GDM is not installed (not applicable)"
            exit 0
        fi

        echo "GDM is installed, checking screen lock configuration..."

        # Check dconf database configuration (machine-wide settings)
        dconf_profile="/etc/dconf/profile/user"
        screensaver_config="/etc/dconf/db/local.d/00-screensaver"

        echo ""
        echo "Checking dconf configuration..."

        # Check if dconf profile exists
        if [ -f "$dconf_profile" ]; then
            echo "PASS: dconf profile exists at $dconf_profile"
        else
            echo "FAIL: dconf profile does not exist at $dconf_profile"
            audit_passed=false
        fi

        # Check if screensaver configuration file exists
        if [ -f "$screensaver_config" ]; then
            echo "PASS: Screensaver configuration file exists at $screensaver_config"
    
            # Check idle-delay setting
            idle_delay=$(grep -Po '^\s*idle-delay\s*=\s*uint32\s+\K\d+' "$screensaver_config" 2>/dev/null)
            if [ -n "$idle_delay" ]; then
                if [ "$idle_delay" -eq 0 ]; then
                    echo "FAIL: idle-delay is set to 0 (disabled)"
                    audit_passed=false
                elif [ "$idle_delay" -le "$MAX_IDLE_DELAY" ]; then
                    echo "PASS: idle-delay is set to $idle_delay seconds (within $MAX_IDLE_DELAY limit)"
                else
                    echo "FAIL: idle-delay is set to $idle_delay seconds (exceeds $MAX_IDLE_DELAY limit)"
                    audit_passed=false
                fi
            else
                echo "FAIL: idle-delay is not configured"
                audit_passed=false
            fi
    
            # Check lock-delay setting
            lock_delay=$(grep -Po '^\s*lock-delay\s*=\s*uint32\s+\K\d+' "$screensaver_config" 2>/dev/null)
            if [ -n "$lock_delay" ]; then
                if [ "$lock_delay" -le "$MAX_LOCK_DELAY" ]; then
                    echo "PASS: lock-delay is set to $lock_delay seconds (within $MAX_LOCK_DELAY limit)"
                else
                    echo "FAIL: lock-delay is set to $lock_delay seconds (exceeds $MAX_LOCK_DELAY limit)"
                    audit_passed=false
                fi
            else
                echo "FAIL: lock-delay is not configured"
                audit_passed=false
            fi
        else
            echo "FAIL: Screensaver configuration file does not exist at $screensaver_config"
            audit_passed=false
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - GDM screen locks when the user is idle"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - GDM screen lock is not properly configured"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.7.4
remediate_1_7_4() {
    # CIS Benchmark 1.7.4 - Ensure GDM screen locks when the user is idle
    # Remediation Script

    # Configuration values (can be adjusted according to site policy)
    IDLE_DELAY=900    # 15 minutes (900 seconds)
    LOCK_DELAY=5      # 5 seconds after screen blanks

    echo "Applying remediation for CIS 1.7.4 - Ensure GDM screen locks when the user is idle..."

    # First check if GDM is installed
    if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
        echo "INFO: GDM (gdm3) is not installed"
        echo "      No action needed - this rule is not applicable"
        exit 0
    fi

    echo "GDM is installed, configuring screen lock settings..."

    # Create dconf profile for user
    dconf_profile="/etc/dconf/profile/user"
    echo "Creating/updating dconf profile at $dconf_profile..."

    mkdir -p /etc/dconf/profile
    printf '%s\n' \
        "user-db:user" \
        "system-db:local" > "$dconf_profile"

    echo "Created dconf profile"

    # Create screensaver configuration
    screensaver_config_dir="/etc/dconf/db/local.d"
    screensaver_config="$screensaver_config_dir/00-screensaver"

    echo "Creating screensaver configuration at $screensaver_config..."

    mkdir -p "$screensaver_config_dir"
    printf '%s\n' \
        "[org/gnome/desktop/session]" \
        "# Number of seconds of inactivity before the screen goes blank" \
        "# Set to 0 seconds if you want to deactivate the screensaver." \
        "idle-delay=uint32 $IDLE_DELAY" \
        "" \
        "[org/gnome/desktop/screensaver]" \
        "# Number of seconds after the screen is blank before locking the screen" \
        "lock-delay=uint32 $LOCK_DELAY" > "$screensaver_config"

    echo "Created screensaver configuration"

    # Update dconf database
    echo "Updating dconf database..."
    if command -v dconf &>/dev/null; then
        dconf update
        echo "Successfully updated dconf database"
    else
        echo "WARNING: dconf command not found, database not updated"
        echo "         Run 'dconf update' manually after installing dconf"
    fi

    echo ""
    echo "Current configuration:"
    echo "----------------------"
    echo "dconf profile ($dconf_profile):"
    cat "$dconf_profile"
    echo ""
    echo "Screensaver config ($screensaver_config):"
    cat "$screensaver_config"
    echo "----------------------"
    echo ""
    echo "Remediation complete for CIS 1.7.4 - Ensure GDM screen locks when the user is idle"
    echo ""
    echo "Settings applied:"
    echo "  - idle-delay: $IDLE_DELAY seconds ($(($IDLE_DELAY / 60)) minutes)"
    echo "  - lock-delay: $LOCK_DELAY seconds"
    echo ""
    echo "NOTE: Users must log out and back in again for the settings to take effect"
}


# Audit function for rule 1.7.5
audit_1_7_5() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.7.5 - Ensure GDM screen locks cannot be overridden
        # Audit Script

        audit_passed=true

        echo "Checking GDM screen lock override configuration..."

        # First check if GDM is installed
        if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
            echo "INFO: GDM (gdm3) is not installed"
            echo "      This check is not applicable if GDM is not installed"
            echo ""
            echo "AUDIT RESULT: PASS - GDM is not installed (not applicable)"
            exit 0
        fi

        echo "GDM is installed, checking screen lock override settings..."

        # Check dconf locks directory
        locks_dir="/etc/dconf/db/local.d/locks"
        locks_file="$locks_dir/00-screensaver"

        echo ""
        echo "Checking dconf locks configuration..."

        # Settings to verify are locked
        declare -A settings=(
            ["idle-delay"]="/org/gnome/desktop/session/idle-delay"
            ["lock-delay"]="/org/gnome/desktop/screensaver/lock-delay"
        )

        # Check if locks directory exists
        if [ -d "$locks_dir" ]; then
            echo "PASS: Locks directory exists at $locks_dir"
    
            # Check each setting
            for setting in "${!settings[@]}"; do
                lock_path="${settings[$setting]}"
        
                if grep -Psrilq -- "^\h*$lock_path\b" "$locks_dir"/* 2>/dev/null; then
                    echo "PASS: \"$setting\" ($lock_path) is locked"
                else
                    echo "FAIL: \"$setting\" ($lock_path) is not locked"
                    audit_passed=false
                fi
            done
        else
            echo "FAIL: Locks directory does not exist at $locks_dir"
            audit_passed=false
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - GDM screen locks cannot be overridden"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - GDM screen lock settings can be overridden by users"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.7.5
remediate_1_7_5() {
    # CIS Benchmark 1.7.5 - Ensure GDM screen locks cannot be overridden
    # Remediation Script

    echo "Applying remediation for CIS 1.7.5 - Ensure GDM screen locks cannot be overridden..."

    # First check if GDM is installed
    if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
        echo "INFO: GDM (gdm3) is not installed"
        echo "      No action needed - this rule is not applicable"
        exit 0
    fi

    echo "GDM is installed, configuring screen lock override prevention..."

    # Create locks directory
    locks_dir="/etc/dconf/db/local.d/locks"
    locks_file="$locks_dir/00-screensaver"

    echo "Creating locks directory at $locks_dir..."
    mkdir -p "$locks_dir"

    echo "Creating locks configuration at $locks_file..."
    printf '%s\n' \
        "# Lock desktop screensaver settings" \
        "/org/gnome/desktop/session/idle-delay" \
        "/org/gnome/desktop/screensaver/lock-delay" > "$locks_file"

    echo "Created locks configuration"

    # Ensure user profile exists (required for locks to work)
    dconf_profile="/etc/dconf/profile/user"
    if [ ! -f "$dconf_profile" ]; then
        echo "Creating dconf profile at $dconf_profile..."
        mkdir -p /etc/dconf/profile
        printf '%s\n' \
            "user-db:user" \
            "system-db:local" > "$dconf_profile"
        echo "Created dconf profile"
    else
        echo "dconf profile already exists at $dconf_profile"
    fi

    # Update dconf database
    echo "Updating dconf database..."
    if command -v dconf &>/dev/null; then
        dconf update
        echo "Successfully updated dconf database"
    else
        echo "WARNING: dconf command not found, database not updated"
        echo "         Run 'dconf update' manually after installing dconf"
    fi

    echo ""
    echo "Current configuration:"
    echo "----------------------"
    echo "Locks file ($locks_file):"
    cat "$locks_file"
    echo "----------------------"
    echo ""
    echo "Remediation complete for CIS 1.7.5 - Ensure GDM screen locks cannot be overridden"
    echo ""
    echo "NOTE: Users must log out and back in again for the settings to take effect"
}


# Audit function for rule 1.7.6
audit_1_7_6() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.7.6 - Ensure GDM automatic mounting of removable media is disabled
        # Audit Script

        audit_passed=true

        echo "Checking GDM automatic mounting configuration..."

        # First check if GDM is installed
        if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
            echo "INFO: GDM (gdm3) is not installed"
            echo "      This check is not applicable if GDM is not installed"
            echo ""
            echo "AUDIT RESULT: PASS - GDM is not installed (not applicable)"
            exit 0
        fi

        echo "GDM is installed, checking automatic mounting configuration..."

        # Check dconf database configuration (machine-wide settings)
        automount_config="/etc/dconf/db/local.d/00-media-automount"

        echo ""
        echo "Checking dconf configuration..."

        # Check if automount configuration file exists
        if [ -f "$automount_config" ]; then
            echo "PASS: Automount configuration file exists at $automount_config"
    
            # Check automount setting
            if grep -Pq '^\s*automount\s*=\s*false' "$automount_config"; then
                echo "PASS: automount is set to false"
            else
                echo "FAIL: automount is not set to false"
                audit_passed=false
            fi
    
            # Check automount-open setting
            if grep -Pq '^\s*automount-open\s*=\s*false' "$automount_config"; then
                echo "PASS: automount-open is set to false"
            else
                echo "FAIL: automount-open is not set to false"
                audit_passed=false
            fi
        else
            echo "FAIL: Automount configuration file does not exist at $automount_config"
            audit_passed=false
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - GDM automatic mounting of removable media is disabled"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - GDM automatic mounting is not properly disabled"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.7.6
remediate_1_7_6() {
    # CIS Benchmark 1.7.6 - Ensure GDM automatic mounting of removable media is disabled
    # Remediation Script

    echo "Applying remediation for CIS 1.7.6 - Ensure GDM automatic mounting of removable media is disabled..."

    # First check if GDM is installed
    if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
        echo "INFO: GDM (gdm3) is not installed"
        echo "      No action needed - this rule is not applicable"
        exit 0
    fi

    echo "GDM is installed, configuring automatic mounting settings..."

    # Ensure user profile exists
    dconf_profile="/etc/dconf/profile/user"
    if [ ! -f "$dconf_profile" ]; then
        echo "Creating dconf profile at $dconf_profile..."
        mkdir -p /etc/dconf/profile
        printf '%s\n' \
            "user-db:user" \
            "system-db:local" > "$dconf_profile"
        echo "Created dconf profile"
    else
        echo "dconf profile already exists at $dconf_profile"
    fi

    # Create automount configuration
    automount_config_dir="/etc/dconf/db/local.d"
    automount_config="$automount_config_dir/00-media-automount"

    echo "Creating automount configuration at $automount_config..."

    mkdir -p "$automount_config_dir"
    printf '%s\n' \
        "[org/gnome/desktop/media-handling]" \
        "automount=false" \
        "automount-open=false" > "$automount_config"

    echo "Created automount configuration"

    # Update dconf database
    echo "Updating dconf database..."
    if command -v dconf &>/dev/null; then
        dconf update
        echo "Successfully updated dconf database"
    else
        echo "WARNING: dconf command not found, database not updated"
        echo "         Run 'dconf update' manually after installing dconf"
    fi

    echo ""
    echo "Current configuration:"
    echo "----------------------"
    echo "Automount config ($automount_config):"
    cat "$automount_config"
    echo "----------------------"
    echo ""
    echo "Remediation complete for CIS 1.7.6 - Ensure GDM automatic mounting of removable media is disabled"
    echo ""
    echo "NOTE: Users must log out and back in again for the settings to take effect"
}


# Audit function for rule 1.7.7
audit_1_7_7() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.7.7 - Ensure GDM disabling automatic mounting of removable media is not overridden
        # Audit Script

        audit_passed=true

        echo "Checking GDM automatic mounting override configuration..."

        # First check if GDM is installed
        if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
            echo "INFO: GDM (gdm3) is not installed"
            echo "      This check is not applicable if GDM is not installed"
            echo ""
            echo "AUDIT RESULT: PASS - GDM is not installed (not applicable)"
            exit 0
        fi

        echo "GDM is installed, checking automatic mounting override settings..."

        # Check dconf locks directory
        locks_dir="/etc/dconf/db/local.d/locks"

        echo ""
        echo "Checking dconf locks configuration..."

        # Settings to verify are locked
        declare -A settings=(
            ["automount"]="/org/gnome/desktop/media-handling/automount"
            ["automount-open"]="/org/gnome/desktop/media-handling/automount-open"
        )

        # Check if locks directory exists
        if [ -d "$locks_dir" ]; then
            echo "PASS: Locks directory exists at $locks_dir"
    
            # Check each setting
            for setting in "${!settings[@]}"; do
                lock_path="${settings[$setting]}"
        
                if grep -Psrilq -- "^\h*$lock_path\b" "$locks_dir"/* 2>/dev/null; then
                    echo "PASS: \"$setting\" ($lock_path) is locked"
                else
                    echo "FAIL: \"$setting\" ($lock_path) is not locked"
                    audit_passed=false
                fi
            done
        else
            echo "FAIL: Locks directory does not exist at $locks_dir"
            audit_passed=false
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - GDM automatic mounting settings cannot be overridden"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - GDM automatic mounting settings can be overridden by users"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.7.7
remediate_1_7_7() {
    # CIS Benchmark 1.7.7 - Ensure GDM disabling automatic mounting of removable media is not overridden
    # Remediation Script

    echo "Applying remediation for CIS 1.7.7 - Ensure GDM disabling automatic mounting of removable media is not overridden..."

    # First check if GDM is installed
    if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
        echo "INFO: GDM (gdm3) is not installed"
        echo "      No action needed - this rule is not applicable"
        exit 0
    fi

    echo "GDM is installed, configuring automatic mounting override prevention..."

    # Create locks directory
    locks_dir="/etc/dconf/db/local.d/locks"
    locks_file="$locks_dir/00-media-automount"

    echo "Creating locks directory at $locks_dir..."
    mkdir -p "$locks_dir"

    echo "Creating locks configuration at $locks_file..."
    printf '%s\n' \
        "# Lock automatic mounting settings" \
        "/org/gnome/desktop/media-handling/automount" \
        "/org/gnome/desktop/media-handling/automount-open" > "$locks_file"

    echo "Created locks configuration"

    # Ensure user profile exists (required for locks to work)
    dconf_profile="/etc/dconf/profile/user"
    if [ ! -f "$dconf_profile" ]; then
        echo "Creating dconf profile at $dconf_profile..."
        mkdir -p /etc/dconf/profile
        printf '%s\n' \
            "user-db:user" \
            "system-db:local" > "$dconf_profile"
        echo "Created dconf profile"
    else
        echo "dconf profile already exists at $dconf_profile"
    fi

    # Update dconf database
    echo "Updating dconf database..."
    if command -v dconf &>/dev/null; then
        dconf update
        echo "Successfully updated dconf database"
    else
        echo "WARNING: dconf command not found, database not updated"
        echo "         Run 'dconf update' manually after installing dconf"
    fi

    echo ""
    echo "Current configuration:"
    echo "----------------------"
    echo "Locks file ($locks_file):"
    cat "$locks_file"
    echo "----------------------"
    echo ""
    echo "Remediation complete for CIS 1.7.7 - Ensure GDM disabling automatic mounting of removable media is not overridden"
    echo ""
    echo "NOTE: Users must log out and back in again for the settings to take effect"
}


# Audit function for rule 1.7.8
audit_1_7_8() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.7.8 - Ensure GDM autorun-never is enabled
        # Audit Script

        audit_passed=true

        echo "Checking GDM autorun-never configuration..."

        # First check if GDM is installed
        if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
            echo "INFO: GDM (gdm3) is not installed"
            echo "      This check is not applicable if GDM is not installed"
            echo ""
            echo "AUDIT RESULT: PASS - GDM is not installed (not applicable)"
            exit 0
        fi

        echo "GDM is installed, checking autorun-never configuration..."

        # Check dconf database configuration (machine-wide settings)
        autorun_config="/etc/dconf/db/local.d/00-media-autorun"

        echo ""
        echo "Checking dconf configuration..."

        # Check if autorun configuration file exists
        if [ -f "$autorun_config" ]; then
            echo "PASS: Autorun configuration file exists at $autorun_config"
    
            # Check autorun-never setting
            if grep -Pq '^\s*autorun-never\s*=\s*true' "$autorun_config"; then
                echo "PASS: autorun-never is set to true"
            else
                echo "FAIL: autorun-never is not set to true"
                audit_passed=false
            fi
        else
            echo "FAIL: Autorun configuration file does not exist at $autorun_config"
            audit_passed=false
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - GDM autorun-never is enabled"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - GDM autorun-never is not enabled"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.7.8
remediate_1_7_8() {
    # CIS Benchmark 1.7.8 - Ensure GDM autorun-never is enabled
    # Remediation Script

    echo "Applying remediation for CIS 1.7.8 - Ensure GDM autorun-never is enabled..."

    # First check if GDM is installed
    if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
        echo "INFO: GDM (gdm3) is not installed"
        echo "      No action needed - this rule is not applicable"
        exit 0
    fi

    echo "GDM is installed, configuring autorun-never setting..."

    # Ensure user profile exists
    dconf_profile="/etc/dconf/profile/user"
    if [ ! -f "$dconf_profile" ]; then
        echo "Creating dconf profile at $dconf_profile..."
        mkdir -p /etc/dconf/profile
        printf '%s\n' \
            "user-db:user" \
            "system-db:local" > "$dconf_profile"
        echo "Created dconf profile"
    else
        echo "dconf profile already exists at $dconf_profile"
    fi

    # Create autorun configuration
    autorun_config_dir="/etc/dconf/db/local.d"
    autorun_config="$autorun_config_dir/00-media-autorun"

    echo "Creating autorun configuration at $autorun_config..."

    mkdir -p "$autorun_config_dir"
    printf '%s\n' \
        "[org/gnome/desktop/media-handling]" \
        "autorun-never=true" > "$autorun_config"

    echo "Created autorun configuration"

    # Update dconf database
    echo "Updating dconf database..."
    if command -v dconf &>/dev/null; then
        dconf update
        echo "Successfully updated dconf database"
    else
        echo "WARNING: dconf command not found, database not updated"
        echo "         Run 'dconf update' manually after installing dconf"
    fi

    echo ""
    echo "Current configuration:"
    echo "----------------------"
    echo "Autorun config ($autorun_config):"
    cat "$autorun_config"
    echo "----------------------"
    echo ""
    echo "Remediation complete for CIS 1.7.8 - Ensure GDM autorun-never is enabled"
    echo ""
    echo "NOTE: Users must log out and back in again for the settings to take effect"
}


# Audit function for rule 1.7.9
audit_1_7_9() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.7.9 - Ensure GDM autorun-never is not overridden
        # Audit Script

        audit_passed=true

        echo "Checking GDM autorun-never override configuration..."

        # First check if GDM is installed
        if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
            echo "INFO: GDM (gdm3) is not installed"
            echo "      This check is not applicable if GDM is not installed"
            echo ""
            echo "AUDIT RESULT: PASS - GDM is not installed (not applicable)"
            exit 0
        fi

        echo "GDM is installed, checking autorun-never override settings..."

        # Check dconf locks directory
        locks_dir="/etc/dconf/db/local.d/locks"

        echo ""
        echo "Checking dconf locks configuration..."

        # Setting to verify is locked
        lock_path="/org/gnome/desktop/media-handling/autorun-never"

        # Check if locks directory exists
        if [ -d "$locks_dir" ]; then
            echo "PASS: Locks directory exists at $locks_dir"
    
            # Check if autorun-never is locked
            if grep -Psrilq -- "^\h*$lock_path\b" "$locks_dir"/* 2>/dev/null; then
                echo "PASS: autorun-never ($lock_path) is locked"
            else
                echo "FAIL: autorun-never ($lock_path) is not locked"
                audit_passed=false
            fi
        else
            echo "FAIL: Locks directory does not exist at $locks_dir"
            audit_passed=false
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - GDM autorun-never setting cannot be overridden"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - GDM autorun-never setting can be overridden by users"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.7.9
remediate_1_7_9() {
    # CIS Benchmark 1.7.9 - Ensure GDM autorun-never is not overridden
    # Remediation Script

    echo "Applying remediation for CIS 1.7.9 - Ensure GDM autorun-never is not overridden..."

    # First check if GDM is installed
    if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
        echo "INFO: GDM (gdm3) is not installed"
        echo "      No action needed - this rule is not applicable"
        exit 0
    fi

    echo "GDM is installed, configuring autorun-never override prevention..."

    # Create locks directory
    locks_dir="/etc/dconf/db/local.d/locks"
    locks_file="$locks_dir/00-media-autorun"

    echo "Creating locks directory at $locks_dir..."
    mkdir -p "$locks_dir"

    echo "Creating locks configuration at $locks_file..."
    printf '%s\n' \
        "# Lock autorun-never setting" \
        "/org/gnome/desktop/media-handling/autorun-never" > "$locks_file"

    echo "Created locks configuration"

    # Ensure user profile exists (required for locks to work)
    dconf_profile="/etc/dconf/profile/user"
    if [ ! -f "$dconf_profile" ]; then
        echo "Creating dconf profile at $dconf_profile..."
        mkdir -p /etc/dconf/profile
        printf '%s\n' \
            "user-db:user" \
            "system-db:local" > "$dconf_profile"
        echo "Created dconf profile"
    else
        echo "dconf profile already exists at $dconf_profile"
    fi

    # Update dconf database
    echo "Updating dconf database..."
    if command -v dconf &>/dev/null; then
        dconf update
        echo "Successfully updated dconf database"
    else
        echo "WARNING: dconf command not found, database not updated"
        echo "         Run 'dconf update' manually after installing dconf"
    fi

    echo ""
    echo "Current configuration:"
    echo "----------------------"
    echo "Locks file ($locks_file):"
    cat "$locks_file"
    echo "----------------------"
    echo ""
    echo "Remediation complete for CIS 1.7.9 - Ensure GDM autorun-never is not overridden"
    echo ""
    echo "NOTE: Users must log out and back in again for the settings to take effect"
}


# Audit function for rule 1.7.10
audit_1_7_10() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 1.7.10 - Ensure XDMCP is not enabled
        # Audit Script

        audit_passed=true

        echo "Checking XDMCP configuration..."

        # First check if GDM is installed
        if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
            echo "INFO: GDM (gdm3) is not installed"
            echo "      This check is not applicable if GDM is not installed"
            echo ""
            echo "AUDIT RESULT: PASS - GDM is not installed (not applicable)"
            exit 0
        fi

        echo "GDM is installed, checking XDMCP configuration..."
        echo ""

        # Check for XDMCP enabled in GDM configuration files
        xdmcp_enabled=false

        for config_file in /etc/gdm3/custom.conf /etc/gdm3/daemon.conf /etc/gdm/custom.conf /etc/gdm/daemon.conf; do
            if [ -f "$config_file" ]; then
                # Check if [xdmcp] block exists and Enable=true is set
                result=$(awk '/\[xdmcp\]/{ f = 1;next } /\[/{ f = 0 } f {if (/^\s*Enable\s*=\s*true/) print $0}' "$config_file" 2>/dev/null)
        
                if [ -n "$result" ]; then
                    echo "FAIL: XDMCP is enabled in $config_file"
                    echo "      Found: $result"
                    xdmcp_enabled=true
                    audit_passed=false
                fi
            fi
        done

        if [ "$xdmcp_enabled" = false ]; then
            echo "PASS: XDMCP is not enabled in any GDM configuration file"
        fi

        # Final result
        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - XDMCP is not enabled"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - XDMCP is enabled and should be disabled"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 1.7.10
remediate_1_7_10() {
    # CIS Benchmark 1.7.10 - Ensure XDMCP is not enabled
    # Remediation Script

    echo "Applying remediation for CIS 1.7.10 - Ensure XDMCP is not enabled..."

    # First check if GDM is installed
    if ! dpkg-query -W -f='${db:Status-Status}' gdm3 2>/dev/null | grep -q "installed"; then
        echo "INFO: GDM (gdm3) is not installed"
        echo "      No action needed - this rule is not applicable"
        return 0
    fi

    echo "GDM is installed, checking and disabling XDMCP..."

    # Check and fix each configuration file
    files_modified=0

    for config_file in /etc/gdm3/custom.conf /etc/gdm3/daemon.conf /etc/gdm/custom.conf /etc/gdm/daemon.conf; do
        if [ -f "$config_file" ]; then
            # Check if [xdmcp] block with Enable=true exists
            if grep -Pziq '\[xdmcp\][^\[]*Enable\s*=\s*true' "$config_file" 2>/dev/null; then
                echo "Found XDMCP enabled in $config_file, disabling..."
            
                # Comment out Enable=true in [xdmcp] block
                # Use awk to process the file
                awk '
                    /\[xdmcp\]/ { in_xdmcp = 1 }
                    /^\[/ && !/\[xdmcp\]/ { in_xdmcp = 0 }
                    in_xdmcp && /^\s*Enable\s*=\s*true/ { 
                        print "# " $0 " # Disabled by CIS remediation"
                        next
                    }
                    { print }
                ' "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"
            
                echo "Disabled XDMCP in $config_file"
                ((files_modified++))
            else
                echo "INFO: XDMCP is not enabled in $config_file"
            fi
        fi
    done

    if [ "$files_modified" -eq 0 ]; then
        echo "No changes needed - XDMCP was not enabled in any configuration file"
    else
        echo ""
        echo "$files_modified file(s) were modified"
        echo ""
        echo "NOTE: You may need to restart GDM for changes to take effect:"
        echo "      systemctl restart gdm3"
    fi

    echo ""
    echo "Remediation complete for CIS 1.7.10 - Ensure XDMCP is not enabled"
}


# Audit function for rule 2.1.1
audit_2_1_1() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.1 - Ensure autofs services are not in use
        # Audit Script

        audit_passed=true

        echo "Checking autofs services..."

        # Check if autofs is installed
        if dpkg-query -W -f='${db:Status-Status}' autofs 2>/dev/null | grep -q "installed"; then
            echo "FAIL: autofs package is installed"
            audit_passed=false
        else
            echo "PASS: autofs package is not installed"
        fi

        # Check if autofs.service is enabled
        if systemctl is-enabled autofs.service 2>/dev/null | grep -q "enabled"; then
            echo "FAIL: autofs.service is enabled"
            audit_passed=false
        else
            echo "PASS: autofs.service is not enabled"
        fi

        # Check if autofs.service is active
        if systemctl is-active autofs.service 2>/dev/null | grep -q "^active"; then
            echo "FAIL: autofs.service is active"
            audit_passed=false
        else
            echo "PASS: autofs.service is not active"
        fi

        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - autofs services are not in use"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - autofs services are in use"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.1
remediate_2_1_1() {
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


# Audit function for rule 2.1.2
audit_2_1_2() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.2 - Ensure avahi daemon services are not in use
        # Audit Script

        audit_passed=true
        echo "Checking avahi-daemon services..."

        if dpkg-query -W -f='${db:Status-Status}' avahi-daemon 2>/dev/null | grep -q "installed"; then
            echo "FAIL: avahi-daemon package is installed"
            audit_passed=false
        else
            echo "PASS: avahi-daemon package is not installed"
        fi

        if systemctl is-enabled avahi-daemon.service 2>/dev/null | grep -q "enabled"; then
            echo "FAIL: avahi-daemon.service is enabled"
            audit_passed=false
        else
            echo "PASS: avahi-daemon.service is not enabled"
        fi

        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - avahi daemon services are not in use"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - avahi daemon services are in use"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.2
remediate_2_1_2() {
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


# Audit function for rule 2.1.3
audit_2_1_3() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.3 - Ensure dhcp server services are not in use
        # Audit Script

        audit_passed=true
        echo "Checking DHCP server services..."

        if dpkg-query -W -f='${db:Status-Status}' isc-dhcp-server 2>/dev/null | grep -q "installed"; then
            echo "FAIL: isc-dhcp-server package is installed"
            audit_passed=false
        else
            echo "PASS: isc-dhcp-server package is not installed"
        fi

        for svc in isc-dhcp-server.service isc-dhcp-server6.service; do
            if systemctl is-enabled "$svc" 2>/dev/null | grep -q "enabled"; then
                echo "FAIL: $svc is enabled"
                audit_passed=false
            fi
        done

        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - DHCP server services are not in use"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - DHCP server services are in use"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.3
remediate_2_1_3() {
    # CIS Benchmark 2.1.3 - Ensure dhcp server services are not in use
    # Remediation Script

    echo "Applying remediation for CIS 2.1.3..."

    systemctl stop isc-dhcp-server.service isc-dhcp-server6.service 2>/dev/null
    systemctl mask isc-dhcp-server.service isc-dhcp-server6.service 2>/dev/null

    if dpkg-query -W -f='${db:Status-Status}' isc-dhcp-server 2>/dev/null | grep -q "installed"; then
        apt purge -y isc-dhcp-server
    fi

    echo "Remediation complete for CIS 2.1.3"
}


# Audit function for rule 2.1.4
audit_2_1_4() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.4 - Ensure dns server services are not in use
        # Audit Script

        audit_passed=true
        echo "Checking DNS server services..."

        if dpkg-query -W -f='${db:Status-Status}' bind9 2>/dev/null | grep -q "installed"; then
            echo "FAIL: bind9 package is installed"
            audit_passed=false
        else
            echo "PASS: bind9 package is not installed"
        fi

        if systemctl is-enabled named.service 2>/dev/null | grep -q "enabled"; then
            echo "FAIL: named.service is enabled"
            audit_passed=false
        else
            echo "PASS: named.service is not enabled"
        fi

        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - DNS server services are not in use"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - DNS server services are in use"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.4
remediate_2_1_4() {
    # CIS Benchmark 2.1.4 - Ensure dns server services are not in use
    # Remediation Script

    echo "Applying remediation for CIS 2.1.4..."

    systemctl stop named.service 2>/dev/null
    systemctl mask named.service 2>/dev/null

    if dpkg-query -W -f='${db:Status-Status}' bind9 2>/dev/null | grep -q "installed"; then
        apt purge -y bind9
    fi

    echo "Remediation complete for CIS 2.1.4"
}


# Audit function for rule 2.1.5
audit_2_1_5() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.5 - Ensure dnsmasq services are not in use
        # Audit Script

        audit_passed=true
        echo "Checking dnsmasq services..."

        if dpkg-query -W -f='${db:Status-Status}' dnsmasq 2>/dev/null | grep -q "installed"; then
            echo "FAIL: dnsmasq package is installed"
            audit_passed=false
        else
            echo "PASS: dnsmasq package is not installed"
        fi

        if systemctl is-enabled dnsmasq.service 2>/dev/null | grep -q "enabled"; then
            echo "FAIL: dnsmasq.service is enabled"
            audit_passed=false
        else
            echo "PASS: dnsmasq.service is not enabled"
        fi

        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - dnsmasq services are not in use"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - dnsmasq services are in use"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.5
remediate_2_1_5() {
    # CIS Benchmark 2.1.5 - Ensure dnsmasq services are not in use
    # Remediation Script

    echo "Applying remediation for CIS 2.1.5..."

    systemctl stop dnsmasq.service 2>/dev/null
    systemctl mask dnsmasq.service 2>/dev/null

    if dpkg-query -W -f='${db:Status-Status}' dnsmasq 2>/dev/null | grep -q "installed"; then
        apt purge -y dnsmasq
    fi

    echo "Remediation complete for CIS 2.1.5"
}


# Audit function for rule 2.1.6
audit_2_1_6() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.6 - Ensure ftp server services are not in use
        # Audit Script

        audit_passed=true
        echo "Checking FTP server services..."

        if dpkg-query -W -f='${db:Status-Status}' vsftpd 2>/dev/null | grep -q "installed"; then
            echo "FAIL: vsftpd package is installed"
            audit_passed=false
        else
            echo "PASS: vsftpd package is not installed"
        fi

        if systemctl is-enabled vsftpd.service 2>/dev/null | grep -q "enabled"; then
            echo "FAIL: vsftpd.service is enabled"
            audit_passed=false
        else
            echo "PASS: vsftpd.service is not enabled"
        fi

        echo ""
        if [ "$audit_passed" = true ]; then
            echo "AUDIT RESULT: PASS - FTP server services are not in use"
            exit 0
        else
            echo "AUDIT RESULT: FAIL - FTP server services are in use"
            exit 1
        fi
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.6
remediate_2_1_6() {
    # CIS Benchmark 2.1.6 - Ensure ftp server services are not in use
    # Remediation Script

    echo "Applying remediation for CIS 2.1.6..."

    systemctl stop vsftpd.service 2>/dev/null
    systemctl mask vsftpd.service 2>/dev/null

    if dpkg-query -W -f='${db:Status-Status}' vsftpd 2>/dev/null | grep -q "installed"; then
        apt purge -y vsftpd
    fi

    echo "Remediation complete for CIS 2.1.6"
}


# Audit function for rule 2.1.7
audit_2_1_7() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.7 - Ensure ldap server services are not in use
        audit_passed=true
        echo "Checking LDAP server services..."

        if dpkg-query -W -f='${db:Status-Status}' slapd 2>/dev/null | grep -q "installed"; then
            echo "FAIL: slapd package is installed"; audit_passed=false
        else
            echo "PASS: slapd package is not installed"
        fi

        if systemctl is-enabled slapd.service 2>/dev/null | grep -q "enabled"; then
            echo "FAIL: slapd.service is enabled"; audit_passed=false
        else
            echo "PASS: slapd.service is not enabled"
        fi

        echo ""
        [ "$audit_passed" = true ] && echo "AUDIT RESULT: PASS" && exit 0 || echo "AUDIT RESULT: FAIL" && exit 1
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.7
remediate_2_1_7() {
    # CIS Benchmark 2.1.7 - Ensure ldap server services are not in use
    echo "Applying remediation for CIS 2.1.7..."
    systemctl stop slapd.service 2>/dev/null
    systemctl mask slapd.service 2>/dev/null
    dpkg-query -W -f='${db:Status-Status}' slapd 2>/dev/null | grep -q "installed" && apt purge -y slapd
    echo "Remediation complete for CIS 2.1.7"
}


# Audit function for rule 2.1.8
audit_2_1_8() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.8 - Ensure message access agent services are not in use
        audit_passed=true
        echo "Checking message access agent services..."

        for pkg in dovecot-imapd dovecot-pop3d; do
            if dpkg-query -W -f='${db:Status-Status}' "$pkg" 2>/dev/null | grep -q "installed"; then
                echo "FAIL: $pkg package is installed"; audit_passed=false
            else
                echo "PASS: $pkg package is not installed"
            fi
        done

        if systemctl is-enabled dovecot.service 2>/dev/null | grep -q "enabled"; then
            echo "FAIL: dovecot.service is enabled"; audit_passed=false
        else
            echo "PASS: dovecot.service is not enabled"
        fi

        echo ""
        [ "$audit_passed" = true ] && echo "AUDIT RESULT: PASS" && exit 0 || echo "AUDIT RESULT: FAIL" && exit 1
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.8
remediate_2_1_8() {
    # CIS Benchmark 2.1.8 - Ensure message access agent services are not in use
    echo "Applying remediation for CIS 2.1.8..."
    systemctl stop dovecot.service 2>/dev/null
    systemctl mask dovecot.service 2>/dev/null
    apt purge -y dovecot-imapd dovecot-pop3d 2>/dev/null
    echo "Remediation complete for CIS 2.1.8"
}


# Audit function for rule 2.1.9
audit_2_1_9() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.9 - Ensure network file system services are not in use
        audit_passed=true
        echo "Checking NFS server services..."

        if dpkg-query -W -f='${db:Status-Status}' nfs-kernel-server 2>/dev/null | grep -q "installed"; then
            echo "FAIL: nfs-kernel-server package is installed"; audit_passed=false
        else
            echo "PASS: nfs-kernel-server package is not installed"
        fi

        if systemctl is-enabled nfs-server.service 2>/dev/null | grep -q "enabled"; then
            echo "FAIL: nfs-server.service is enabled"; audit_passed=false
        else
            echo "PASS: nfs-server.service is not enabled"
        fi

        echo ""
        [ "$audit_passed" = true ] && echo "AUDIT RESULT: PASS" && exit 0 || echo "AUDIT RESULT: FAIL" && exit 1
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.9
remediate_2_1_9() {
    # CIS Benchmark 2.1.9 - Ensure network file system services are not in use
    echo "Applying remediation for CIS 2.1.9..."
    systemctl stop nfs-server.service 2>/dev/null
    systemctl mask nfs-server.service 2>/dev/null
    dpkg-query -W -f='${db:Status-Status}' nfs-kernel-server 2>/dev/null | grep -q "installed" && apt purge -y nfs-kernel-server
    echo "Remediation complete for CIS 2.1.9"
}


# Audit function for rule 2.1.10
audit_2_1_10() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.10 - Ensure nis server services are not in use
        audit_passed=true
        echo "Checking NIS server services..."

        if dpkg-query -W -f='${db:Status-Status}' nis 2>/dev/null | grep -q "installed"; then
            echo "FAIL: nis package is installed"; audit_passed=false
        else
            echo "PASS: nis package is not installed"
        fi

        if systemctl is-enabled ypserv.service 2>/dev/null | grep -q "enabled"; then
            echo "FAIL: ypserv.service is enabled"; audit_passed=false
        else
            echo "PASS: ypserv.service is not enabled"
        fi

        echo ""
        [ "$audit_passed" = true ] && echo "AUDIT RESULT: PASS" && exit 0 || echo "AUDIT RESULT: FAIL" && exit 1
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.10
remediate_2_1_10() {
    # CIS Benchmark 2.1.10 - Ensure nis server services are not in use
    echo "Applying remediation for CIS 2.1.10..."
    systemctl stop ypserv.service 2>/dev/null
    systemctl mask ypserv.service 2>/dev/null
    dpkg-query -W -f='${db:Status-Status}' nis 2>/dev/null | grep -q "installed" && apt purge -y nis
    echo "Remediation complete for CIS 2.1.10"
}


# Audit function for rule 2.1.11
audit_2_1_11() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.11 - Ensure print server services are not in use
        audit_passed=true
        echo "Checking print server services..."

        if dpkg-query -W -f='${db:Status-Status}' cups 2>/dev/null | grep -q "installed"; then
            echo "FAIL: cups package is installed"; audit_passed=false
        else
            echo "PASS: cups package is not installed"
        fi

        if systemctl is-enabled cups.service 2>/dev/null | grep -q "enabled"; then
            echo "FAIL: cups.service is enabled"; audit_passed=false
        else
            echo "PASS: cups.service is not enabled"
        fi

        echo ""
        [ "$audit_passed" = true ] && echo "AUDIT RESULT: PASS" && exit 0 || echo "AUDIT RESULT: FAIL" && exit 1
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.11
remediate_2_1_11() {
    # CIS Benchmark 2.1.11 - Ensure print server services are not in use
    echo "Applying remediation for CIS 2.1.11..."
    systemctl stop cups.service cups.socket 2>/dev/null
    systemctl mask cups.service cups.socket 2>/dev/null
    dpkg-query -W -f='${db:Status-Status}' cups 2>/dev/null | grep -q "installed" && apt purge -y cups
    echo "Remediation complete for CIS 2.1.11"
}


# Audit function for rule 2.1.12
audit_2_1_12() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.12 - Ensure rpcbind services are not in use
        audit_passed=true
        echo "Checking rpcbind services..."

        if dpkg-query -W -f='${db:Status-Status}' rpcbind 2>/dev/null | grep -q "installed"; then
            echo "FAIL: rpcbind package is installed"; audit_passed=false
        else
            echo "PASS: rpcbind package is not installed"
        fi

        for svc in rpcbind.service rpcbind.socket; do
            if systemctl is-enabled "$svc" 2>/dev/null | grep -q "enabled"; then
                echo "FAIL: $svc is enabled"; audit_passed=false
            fi
        done

        echo ""
        [ "$audit_passed" = true ] && echo "AUDIT RESULT: PASS" && exit 0 || echo "AUDIT RESULT: FAIL" && exit 1
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.12
remediate_2_1_12() {
    # CIS Benchmark 2.1.12 - Ensure rpcbind services are not in use
    echo "Applying remediation for CIS 2.1.12..."
    systemctl stop rpcbind.service rpcbind.socket 2>/dev/null
    systemctl mask rpcbind.service rpcbind.socket 2>/dev/null
    dpkg-query -W -f='${db:Status-Status}' rpcbind 2>/dev/null | grep -q "installed" && apt purge -y rpcbind
    echo "Remediation complete for CIS 2.1.12"
}


# Audit function for rule 2.1.13
audit_2_1_13() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.13 - Ensure rsync services are not in use
        audit_passed=true
        echo "Checking rsync services..."

        if dpkg-query -W -f='${db:Status-Status}' rsync 2>/dev/null | grep -q "installed"; then
            echo "FAIL: rsync package is installed"; audit_passed=false
        else
            echo "PASS: rsync package is not installed"
        fi

        if systemctl is-enabled rsync.service 2>/dev/null | grep -q "enabled"; then
            echo "FAIL: rsync.service is enabled"; audit_passed=false
        else
            echo "PASS: rsync.service is not enabled"
        fi

        echo ""
        [ "$audit_passed" = true ] && echo "AUDIT RESULT: PASS" && exit 0 || echo "AUDIT RESULT: FAIL" && exit 1
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.13
remediate_2_1_13() {
    # CIS Benchmark 2.1.13 - Ensure rsync services are not in use
    echo "Applying remediation for CIS 2.1.13..."
    systemctl stop rsync.service 2>/dev/null
    systemctl mask rsync.service 2>/dev/null
    dpkg-query -W -f='${db:Status-Status}' rsync 2>/dev/null | grep -q "installed" && apt purge -y rsync
    echo "Remediation complete for CIS 2.1.13"
}


# Audit function for rule 2.1.14
audit_2_1_14() {
    local output
    local exit_code
    
    output=$(
        # CIS Benchmark 2.1.14 - Ensure samba file server services are not in use
        audit_passed=true
        echo "Checking samba services..."

        if dpkg-query -W -f='${db:Status-Status}' samba 2>/dev/null | grep -q "installed"; then
            echo "FAIL: samba package is installed"; audit_passed=false
        else
            echo "PASS: samba package is not installed"
        fi

        if systemctl is-enabled smbd.service 2>/dev/null | grep -q "enabled"; then
            echo "FAIL: smbd.service is enabled"; audit_passed=false
        else
            echo "PASS: smbd.service is not enabled"
        fi

        echo ""
        [ "$audit_passed" = true ] && echo "AUDIT RESULT: PASS" && exit 0 || echo "AUDIT RESULT: FAIL" && exit 1
    ) 2>&1
    exit_code=$?
    
    echo "$output"
    return $exit_code
}


# Remediation function for rule 2.1.14
remediate_2_1_14() {
    # CIS Benchmark 2.1.14 - Ensure samba file server services are not in use
    echo "Applying remediation for CIS 2.1.14..."
    systemctl stop smbd.service nmbd.service 2>/dev/null
    systemctl mask smbd.service nmbd.service 2>/dev/null
    dpkg-query -W -f='${db:Status-Status}' samba 2>/dev/null | grep -q "installed" && apt purge -y samba
    echo "Remediation complete for CIS 2.1.14"
}


# --- Before Audit: 1.1.1.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [1/50]: 1.1.1.1"
RULE_START_TIME["1.1.1.1"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[1/50] Auditing 1.1.1.1... "
BEFORE_OUTPUT["1.1.1.1"]=$(audit_1_1_1_1 2>&1)
BEFORE_RESULTS["1.1.1.1"]=$?

RULE_END_TIME["1.1.1.1"]=$(date +%s)
RULE_DURATION["1.1.1.1"]=$((RULE_END_TIME["1.1.1.1"] - RULE_START_TIME["1.1.1.1"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.1.1.1"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.1.1.1"]}"

if [ "${BEFORE_RESULTS["1.1.1.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.1.1.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.1.1.1"]}"
log_detailed ""


# --- Before Audit: 1.1.1.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [2/50]: 1.1.1.2"
RULE_START_TIME["1.1.1.2"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[2/50] Auditing 1.1.1.2... "
BEFORE_OUTPUT["1.1.1.2"]=$(audit_1_1_1_2 2>&1)
BEFORE_RESULTS["1.1.1.2"]=$?

RULE_END_TIME["1.1.1.2"]=$(date +%s)
RULE_DURATION["1.1.1.2"]=$((RULE_END_TIME["1.1.1.2"] - RULE_START_TIME["1.1.1.2"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.1.1.2"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.1.1.2"]}"

if [ "${BEFORE_RESULTS["1.1.1.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.1.1.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.1.1.2"]}"
log_detailed ""


# --- Before Audit: 1.1.1.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [3/50]: 1.1.1.3"
RULE_START_TIME["1.1.1.3"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[3/50] Auditing 1.1.1.3... "
BEFORE_OUTPUT["1.1.1.3"]=$(audit_1_1_1_3 2>&1)
BEFORE_RESULTS["1.1.1.3"]=$?

RULE_END_TIME["1.1.1.3"]=$(date +%s)
RULE_DURATION["1.1.1.3"]=$((RULE_END_TIME["1.1.1.3"] - RULE_START_TIME["1.1.1.3"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.1.1.3"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.1.1.3"]}"

if [ "${BEFORE_RESULTS["1.1.1.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.1.1.3"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.1.1.3"]}"
log_detailed ""


# --- Before Audit: 1.1.1.4 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [4/50]: 1.1.1.4"
RULE_START_TIME["1.1.1.4"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[4/50] Auditing 1.1.1.4... "
BEFORE_OUTPUT["1.1.1.4"]=$(audit_1_1_1_4 2>&1)
BEFORE_RESULTS["1.1.1.4"]=$?

RULE_END_TIME["1.1.1.4"]=$(date +%s)
RULE_DURATION["1.1.1.4"]=$((RULE_END_TIME["1.1.1.4"] - RULE_START_TIME["1.1.1.4"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.1.1.4"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.1.1.4"]}"

if [ "${BEFORE_RESULTS["1.1.1.4"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.1.1.4"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.1.1.4"]}"
log_detailed ""


# --- Before Audit: 1.1.1.5 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [5/50]: 1.1.1.5"
RULE_START_TIME["1.1.1.5"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[5/50] Auditing 1.1.1.5... "
BEFORE_OUTPUT["1.1.1.5"]=$(audit_1_1_1_5 2>&1)
BEFORE_RESULTS["1.1.1.5"]=$?

RULE_END_TIME["1.1.1.5"]=$(date +%s)
RULE_DURATION["1.1.1.5"]=$((RULE_END_TIME["1.1.1.5"] - RULE_START_TIME["1.1.1.5"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.1.1.5"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.1.1.5"]}"

if [ "${BEFORE_RESULTS["1.1.1.5"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.1.1.5"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.1.1.5"]}"
log_detailed ""


# --- Before Audit: 1.1.1.6 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [6/50]: 1.1.1.6"
RULE_START_TIME["1.1.1.6"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[6/50] Auditing 1.1.1.6... "
BEFORE_OUTPUT["1.1.1.6"]=$(audit_1_1_1_6 2>&1)
BEFORE_RESULTS["1.1.1.6"]=$?

RULE_END_TIME["1.1.1.6"]=$(date +%s)
RULE_DURATION["1.1.1.6"]=$((RULE_END_TIME["1.1.1.6"] - RULE_START_TIME["1.1.1.6"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.1.1.6"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.1.1.6"]}"

if [ "${BEFORE_RESULTS["1.1.1.6"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.1.1.6"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.1.1.6"]}"
log_detailed ""


# --- Before Audit: 1.1.1.7 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [7/50]: 1.1.1.7"
RULE_START_TIME["1.1.1.7"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[7/50] Auditing 1.1.1.7... "
BEFORE_OUTPUT["1.1.1.7"]=$(audit_1_1_1_7 2>&1)
BEFORE_RESULTS["1.1.1.7"]=$?

RULE_END_TIME["1.1.1.7"]=$(date +%s)
RULE_DURATION["1.1.1.7"]=$((RULE_END_TIME["1.1.1.7"] - RULE_START_TIME["1.1.1.7"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.1.1.7"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.1.1.7"]}"

if [ "${BEFORE_RESULTS["1.1.1.7"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.1.1.7"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.1.1.7"]}"
log_detailed ""


# --- Before Audit: 1.1.1.8 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [8/50]: 1.1.1.8"
RULE_START_TIME["1.1.1.8"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[8/50] Auditing 1.1.1.8... "
BEFORE_OUTPUT["1.1.1.8"]=$(audit_1_1_1_8 2>&1)
BEFORE_RESULTS["1.1.1.8"]=$?

RULE_END_TIME["1.1.1.8"]=$(date +%s)
RULE_DURATION["1.1.1.8"]=$((RULE_END_TIME["1.1.1.8"] - RULE_START_TIME["1.1.1.8"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.1.1.8"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.1.1.8"]}"

if [ "${BEFORE_RESULTS["1.1.1.8"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.1.1.8"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.1.1.8"]}"
log_detailed ""


# --- Before Audit: 1.1.1.9 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [9/50]: 1.1.1.9"
RULE_START_TIME["1.1.1.9"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[9/50] Auditing 1.1.1.9... "
BEFORE_OUTPUT["1.1.1.9"]=$(audit_1_1_1_9 2>&1)
BEFORE_RESULTS["1.1.1.9"]=$?

RULE_END_TIME["1.1.1.9"]=$(date +%s)
RULE_DURATION["1.1.1.9"]=$((RULE_END_TIME["1.1.1.9"] - RULE_START_TIME["1.1.1.9"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.1.1.9"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.1.1.9"]}"

if [ "${BEFORE_RESULTS["1.1.1.9"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.1.1.9"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.1.1.9"]}"
log_detailed ""


# --- Before Audit: 1.3.1.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [10/50]: 1.3.1.1"
RULE_START_TIME["1.3.1.1"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[10/50] Auditing 1.3.1.1... "
BEFORE_OUTPUT["1.3.1.1"]=$(audit_1_3_1_1 2>&1)
BEFORE_RESULTS["1.3.1.1"]=$?

RULE_END_TIME["1.3.1.1"]=$(date +%s)
RULE_DURATION["1.3.1.1"]=$((RULE_END_TIME["1.3.1.1"] - RULE_START_TIME["1.3.1.1"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.3.1.1"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.3.1.1"]}"

if [ "${BEFORE_RESULTS["1.3.1.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.3.1.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.3.1.1"]}"
log_detailed ""


# --- Before Audit: 1.3.1.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [11/50]: 1.3.1.2"
RULE_START_TIME["1.3.1.2"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[11/50] Auditing 1.3.1.2... "
BEFORE_OUTPUT["1.3.1.2"]=$(audit_1_3_1_2 2>&1)
BEFORE_RESULTS["1.3.1.2"]=$?

RULE_END_TIME["1.3.1.2"]=$(date +%s)
RULE_DURATION["1.3.1.2"]=$((RULE_END_TIME["1.3.1.2"] - RULE_START_TIME["1.3.1.2"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.3.1.2"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.3.1.2"]}"

if [ "${BEFORE_RESULTS["1.3.1.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.3.1.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.3.1.2"]}"
log_detailed ""


# --- Before Audit: 1.3.1.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [12/50]: 1.3.1.3"
RULE_START_TIME["1.3.1.3"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[12/50] Auditing 1.3.1.3... "
BEFORE_OUTPUT["1.3.1.3"]=$(audit_1_3_1_3 2>&1)
BEFORE_RESULTS["1.3.1.3"]=$?

RULE_END_TIME["1.3.1.3"]=$(date +%s)
RULE_DURATION["1.3.1.3"]=$((RULE_END_TIME["1.3.1.3"] - RULE_START_TIME["1.3.1.3"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.3.1.3"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.3.1.3"]}"

if [ "${BEFORE_RESULTS["1.3.1.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.3.1.3"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.3.1.3"]}"
log_detailed ""


# --- Before Audit: 1.3.1.4 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [13/50]: 1.3.1.4"
RULE_START_TIME["1.3.1.4"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[13/50] Auditing 1.3.1.4... "
BEFORE_OUTPUT["1.3.1.4"]=$(audit_1_3_1_4 2>&1)
BEFORE_RESULTS["1.3.1.4"]=$?

RULE_END_TIME["1.3.1.4"]=$(date +%s)
RULE_DURATION["1.3.1.4"]=$((RULE_END_TIME["1.3.1.4"] - RULE_START_TIME["1.3.1.4"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.3.1.4"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.3.1.4"]}"

if [ "${BEFORE_RESULTS["1.3.1.4"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.3.1.4"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.3.1.4"]}"
log_detailed ""


# --- Before Audit: 1.4.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [14/50]: 1.4.1"
RULE_START_TIME["1.4.1"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[14/50] Auditing 1.4.1... "
BEFORE_OUTPUT["1.4.1"]=$(audit_1_4_1 2>&1)
BEFORE_RESULTS["1.4.1"]=$?

RULE_END_TIME["1.4.1"]=$(date +%s)
RULE_DURATION["1.4.1"]=$((RULE_END_TIME["1.4.1"] - RULE_START_TIME["1.4.1"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.4.1"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.4.1"]}"

if [ "${BEFORE_RESULTS["1.4.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.4.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.4.1"]}"
log_detailed ""


# --- Before Audit: 1.4.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [15/50]: 1.4.2"
RULE_START_TIME["1.4.2"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[15/50] Auditing 1.4.2... "
BEFORE_OUTPUT["1.4.2"]=$(audit_1_4_2 2>&1)
BEFORE_RESULTS["1.4.2"]=$?

RULE_END_TIME["1.4.2"]=$(date +%s)
RULE_DURATION["1.4.2"]=$((RULE_END_TIME["1.4.2"] - RULE_START_TIME["1.4.2"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.4.2"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.4.2"]}"

if [ "${BEFORE_RESULTS["1.4.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.4.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.4.2"]}"
log_detailed ""


# --- Before Audit: 1.5.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [16/50]: 1.5.1"
RULE_START_TIME["1.5.1"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[16/50] Auditing 1.5.1... "
BEFORE_OUTPUT["1.5.1"]=$(audit_1_5_1 2>&1)
BEFORE_RESULTS["1.5.1"]=$?

RULE_END_TIME["1.5.1"]=$(date +%s)
RULE_DURATION["1.5.1"]=$((RULE_END_TIME["1.5.1"] - RULE_START_TIME["1.5.1"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.5.1"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.5.1"]}"

if [ "${BEFORE_RESULTS["1.5.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.5.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.5.1"]}"
log_detailed ""


# --- Before Audit: 1.5.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [17/50]: 1.5.2"
RULE_START_TIME["1.5.2"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[17/50] Auditing 1.5.2... "
BEFORE_OUTPUT["1.5.2"]=$(audit_1_5_2 2>&1)
BEFORE_RESULTS["1.5.2"]=$?

RULE_END_TIME["1.5.2"]=$(date +%s)
RULE_DURATION["1.5.2"]=$((RULE_END_TIME["1.5.2"] - RULE_START_TIME["1.5.2"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.5.2"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.5.2"]}"

if [ "${BEFORE_RESULTS["1.5.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.5.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.5.2"]}"
log_detailed ""


# --- Before Audit: 1.5.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [18/50]: 1.5.3"
RULE_START_TIME["1.5.3"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[18/50] Auditing 1.5.3... "
BEFORE_OUTPUT["1.5.3"]=$(audit_1_5_3 2>&1)
BEFORE_RESULTS["1.5.3"]=$?

RULE_END_TIME["1.5.3"]=$(date +%s)
RULE_DURATION["1.5.3"]=$((RULE_END_TIME["1.5.3"] - RULE_START_TIME["1.5.3"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.5.3"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.5.3"]}"

if [ "${BEFORE_RESULTS["1.5.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.5.3"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.5.3"]}"
log_detailed ""


# --- Before Audit: 1.5.4 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [19/50]: 1.5.4"
RULE_START_TIME["1.5.4"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[19/50] Auditing 1.5.4... "
BEFORE_OUTPUT["1.5.4"]=$(audit_1_5_4 2>&1)
BEFORE_RESULTS["1.5.4"]=$?

RULE_END_TIME["1.5.4"]=$(date +%s)
RULE_DURATION["1.5.4"]=$((RULE_END_TIME["1.5.4"] - RULE_START_TIME["1.5.4"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.5.4"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.5.4"]}"

if [ "${BEFORE_RESULTS["1.5.4"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.5.4"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.5.4"]}"
log_detailed ""


# --- Before Audit: 1.5.5 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [20/50]: 1.5.5"
RULE_START_TIME["1.5.5"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[20/50] Auditing 1.5.5... "
BEFORE_OUTPUT["1.5.5"]=$(audit_1_5_5 2>&1)
BEFORE_RESULTS["1.5.5"]=$?

RULE_END_TIME["1.5.5"]=$(date +%s)
RULE_DURATION["1.5.5"]=$((RULE_END_TIME["1.5.5"] - RULE_START_TIME["1.5.5"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.5.5"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.5.5"]}"

if [ "${BEFORE_RESULTS["1.5.5"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.5.5"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.5.5"]}"
log_detailed ""


# --- Before Audit: 1.6.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [21/50]: 1.6.1"
RULE_START_TIME["1.6.1"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[21/50] Auditing 1.6.1... "
BEFORE_OUTPUT["1.6.1"]=$(audit_1_6_1 2>&1)
BEFORE_RESULTS["1.6.1"]=$?

RULE_END_TIME["1.6.1"]=$(date +%s)
RULE_DURATION["1.6.1"]=$((RULE_END_TIME["1.6.1"] - RULE_START_TIME["1.6.1"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.6.1"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.6.1"]}"

if [ "${BEFORE_RESULTS["1.6.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.6.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.6.1"]}"
log_detailed ""


# --- Before Audit: 1.6.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [22/50]: 1.6.2"
RULE_START_TIME["1.6.2"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[22/50] Auditing 1.6.2... "
BEFORE_OUTPUT["1.6.2"]=$(audit_1_6_2 2>&1)
BEFORE_RESULTS["1.6.2"]=$?

RULE_END_TIME["1.6.2"]=$(date +%s)
RULE_DURATION["1.6.2"]=$((RULE_END_TIME["1.6.2"] - RULE_START_TIME["1.6.2"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.6.2"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.6.2"]}"

if [ "${BEFORE_RESULTS["1.6.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.6.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.6.2"]}"
log_detailed ""


# --- Before Audit: 1.6.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [23/50]: 1.6.3"
RULE_START_TIME["1.6.3"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[23/50] Auditing 1.6.3... "
BEFORE_OUTPUT["1.6.3"]=$(audit_1_6_3 2>&1)
BEFORE_RESULTS["1.6.3"]=$?

RULE_END_TIME["1.6.3"]=$(date +%s)
RULE_DURATION["1.6.3"]=$((RULE_END_TIME["1.6.3"] - RULE_START_TIME["1.6.3"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.6.3"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.6.3"]}"

if [ "${BEFORE_RESULTS["1.6.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.6.3"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.6.3"]}"
log_detailed ""


# --- Before Audit: 1.6.4 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [24/50]: 1.6.4"
RULE_START_TIME["1.6.4"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[24/50] Auditing 1.6.4... "
BEFORE_OUTPUT["1.6.4"]=$(audit_1_6_4 2>&1)
BEFORE_RESULTS["1.6.4"]=$?

RULE_END_TIME["1.6.4"]=$(date +%s)
RULE_DURATION["1.6.4"]=$((RULE_END_TIME["1.6.4"] - RULE_START_TIME["1.6.4"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.6.4"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.6.4"]}"

if [ "${BEFORE_RESULTS["1.6.4"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.6.4"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.6.4"]}"
log_detailed ""


# --- Before Audit: 1.6.5 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [25/50]: 1.6.5"
RULE_START_TIME["1.6.5"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[25/50] Auditing 1.6.5... "
BEFORE_OUTPUT["1.6.5"]=$(audit_1_6_5 2>&1)
BEFORE_RESULTS["1.6.5"]=$?

RULE_END_TIME["1.6.5"]=$(date +%s)
RULE_DURATION["1.6.5"]=$((RULE_END_TIME["1.6.5"] - RULE_START_TIME["1.6.5"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.6.5"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.6.5"]}"

if [ "${BEFORE_RESULTS["1.6.5"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.6.5"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.6.5"]}"
log_detailed ""


# --- Before Audit: 1.6.6 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [26/50]: 1.6.6"
RULE_START_TIME["1.6.6"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[26/50] Auditing 1.6.6... "
BEFORE_OUTPUT["1.6.6"]=$(audit_1_6_6 2>&1)
BEFORE_RESULTS["1.6.6"]=$?

RULE_END_TIME["1.6.6"]=$(date +%s)
RULE_DURATION["1.6.6"]=$((RULE_END_TIME["1.6.6"] - RULE_START_TIME["1.6.6"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.6.6"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.6.6"]}"

if [ "${BEFORE_RESULTS["1.6.6"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.6.6"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.6.6"]}"
log_detailed ""


# --- Before Audit: 1.7.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [27/50]: 1.7.1"
RULE_START_TIME["1.7.1"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[27/50] Auditing 1.7.1... "
BEFORE_OUTPUT["1.7.1"]=$(audit_1_7_1 2>&1)
BEFORE_RESULTS["1.7.1"]=$?

RULE_END_TIME["1.7.1"]=$(date +%s)
RULE_DURATION["1.7.1"]=$((RULE_END_TIME["1.7.1"] - RULE_START_TIME["1.7.1"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.7.1"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.7.1"]}"

if [ "${BEFORE_RESULTS["1.7.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.7.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.7.1"]}"
log_detailed ""


# --- Before Audit: 1.7.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [28/50]: 1.7.2"
RULE_START_TIME["1.7.2"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[28/50] Auditing 1.7.2... "
BEFORE_OUTPUT["1.7.2"]=$(audit_1_7_2 2>&1)
BEFORE_RESULTS["1.7.2"]=$?

RULE_END_TIME["1.7.2"]=$(date +%s)
RULE_DURATION["1.7.2"]=$((RULE_END_TIME["1.7.2"] - RULE_START_TIME["1.7.2"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.7.2"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.7.2"]}"

if [ "${BEFORE_RESULTS["1.7.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.7.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.7.2"]}"
log_detailed ""


# --- Before Audit: 1.7.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [29/50]: 1.7.3"
RULE_START_TIME["1.7.3"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[29/50] Auditing 1.7.3... "
BEFORE_OUTPUT["1.7.3"]=$(audit_1_7_3 2>&1)
BEFORE_RESULTS["1.7.3"]=$?

RULE_END_TIME["1.7.3"]=$(date +%s)
RULE_DURATION["1.7.3"]=$((RULE_END_TIME["1.7.3"] - RULE_START_TIME["1.7.3"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.7.3"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.7.3"]}"

if [ "${BEFORE_RESULTS["1.7.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.7.3"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.7.3"]}"
log_detailed ""


# --- Before Audit: 1.7.4 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [30/50]: 1.7.4"
RULE_START_TIME["1.7.4"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[30/50] Auditing 1.7.4... "
BEFORE_OUTPUT["1.7.4"]=$(audit_1_7_4 2>&1)
BEFORE_RESULTS["1.7.4"]=$?

RULE_END_TIME["1.7.4"]=$(date +%s)
RULE_DURATION["1.7.4"]=$((RULE_END_TIME["1.7.4"] - RULE_START_TIME["1.7.4"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.7.4"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.7.4"]}"

if [ "${BEFORE_RESULTS["1.7.4"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.7.4"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.7.4"]}"
log_detailed ""


# --- Before Audit: 1.7.5 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [31/50]: 1.7.5"
RULE_START_TIME["1.7.5"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[31/50] Auditing 1.7.5... "
BEFORE_OUTPUT["1.7.5"]=$(audit_1_7_5 2>&1)
BEFORE_RESULTS["1.7.5"]=$?

RULE_END_TIME["1.7.5"]=$(date +%s)
RULE_DURATION["1.7.5"]=$((RULE_END_TIME["1.7.5"] - RULE_START_TIME["1.7.5"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.7.5"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.7.5"]}"

if [ "${BEFORE_RESULTS["1.7.5"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.7.5"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.7.5"]}"
log_detailed ""


# --- Before Audit: 1.7.6 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [32/50]: 1.7.6"
RULE_START_TIME["1.7.6"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[32/50] Auditing 1.7.6... "
BEFORE_OUTPUT["1.7.6"]=$(audit_1_7_6 2>&1)
BEFORE_RESULTS["1.7.6"]=$?

RULE_END_TIME["1.7.6"]=$(date +%s)
RULE_DURATION["1.7.6"]=$((RULE_END_TIME["1.7.6"] - RULE_START_TIME["1.7.6"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.7.6"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.7.6"]}"

if [ "${BEFORE_RESULTS["1.7.6"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.7.6"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.7.6"]}"
log_detailed ""


# --- Before Audit: 1.7.7 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [33/50]: 1.7.7"
RULE_START_TIME["1.7.7"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[33/50] Auditing 1.7.7... "
BEFORE_OUTPUT["1.7.7"]=$(audit_1_7_7 2>&1)
BEFORE_RESULTS["1.7.7"]=$?

RULE_END_TIME["1.7.7"]=$(date +%s)
RULE_DURATION["1.7.7"]=$((RULE_END_TIME["1.7.7"] - RULE_START_TIME["1.7.7"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.7.7"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.7.7"]}"

if [ "${BEFORE_RESULTS["1.7.7"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.7.7"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.7.7"]}"
log_detailed ""


# --- Before Audit: 1.7.8 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [34/50]: 1.7.8"
RULE_START_TIME["1.7.8"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[34/50] Auditing 1.7.8... "
BEFORE_OUTPUT["1.7.8"]=$(audit_1_7_8 2>&1)
BEFORE_RESULTS["1.7.8"]=$?

RULE_END_TIME["1.7.8"]=$(date +%s)
RULE_DURATION["1.7.8"]=$((RULE_END_TIME["1.7.8"] - RULE_START_TIME["1.7.8"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.7.8"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.7.8"]}"

if [ "${BEFORE_RESULTS["1.7.8"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.7.8"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.7.8"]}"
log_detailed ""


# --- Before Audit: 1.7.9 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [35/50]: 1.7.9"
RULE_START_TIME["1.7.9"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[35/50] Auditing 1.7.9... "
BEFORE_OUTPUT["1.7.9"]=$(audit_1_7_9 2>&1)
BEFORE_RESULTS["1.7.9"]=$?

RULE_END_TIME["1.7.9"]=$(date +%s)
RULE_DURATION["1.7.9"]=$((RULE_END_TIME["1.7.9"] - RULE_START_TIME["1.7.9"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.7.9"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.7.9"]}"

if [ "${BEFORE_RESULTS["1.7.9"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.7.9"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.7.9"]}"
log_detailed ""


# --- Before Audit: 1.7.10 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [36/50]: 1.7.10"
RULE_START_TIME["1.7.10"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[36/50] Auditing 1.7.10... "
BEFORE_OUTPUT["1.7.10"]=$(audit_1_7_10 2>&1)
BEFORE_RESULTS["1.7.10"]=$?

RULE_END_TIME["1.7.10"]=$(date +%s)
RULE_DURATION["1.7.10"]=$((RULE_END_TIME["1.7.10"] - RULE_START_TIME["1.7.10"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["1.7.10"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["1.7.10"]}"

if [ "${BEFORE_RESULTS["1.7.10"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["1.7.10"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["1.7.10"]}"
log_detailed ""


# --- Before Audit: 2.1.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [37/50]: 2.1.1"
RULE_START_TIME["2.1.1"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[37/50] Auditing 2.1.1... "
BEFORE_OUTPUT["2.1.1"]=$(audit_2_1_1 2>&1)
BEFORE_RESULTS["2.1.1"]=$?

RULE_END_TIME["2.1.1"]=$(date +%s)
RULE_DURATION["2.1.1"]=$((RULE_END_TIME["2.1.1"] - RULE_START_TIME["2.1.1"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.1"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.1"]}"

if [ "${BEFORE_RESULTS["2.1.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.1"]}"
log_detailed ""


# --- Before Audit: 2.1.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [38/50]: 2.1.2"
RULE_START_TIME["2.1.2"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[38/50] Auditing 2.1.2... "
BEFORE_OUTPUT["2.1.2"]=$(audit_2_1_2 2>&1)
BEFORE_RESULTS["2.1.2"]=$?

RULE_END_TIME["2.1.2"]=$(date +%s)
RULE_DURATION["2.1.2"]=$((RULE_END_TIME["2.1.2"] - RULE_START_TIME["2.1.2"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.2"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.2"]}"

if [ "${BEFORE_RESULTS["2.1.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.2"]}"
log_detailed ""


# --- Before Audit: 2.1.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [39/50]: 2.1.3"
RULE_START_TIME["2.1.3"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[39/50] Auditing 2.1.3... "
BEFORE_OUTPUT["2.1.3"]=$(audit_2_1_3 2>&1)
BEFORE_RESULTS["2.1.3"]=$?

RULE_END_TIME["2.1.3"]=$(date +%s)
RULE_DURATION["2.1.3"]=$((RULE_END_TIME["2.1.3"] - RULE_START_TIME["2.1.3"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.3"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.3"]}"

if [ "${BEFORE_RESULTS["2.1.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.3"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.3"]}"
log_detailed ""


# --- Before Audit: 2.1.4 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [40/50]: 2.1.4"
RULE_START_TIME["2.1.4"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[40/50] Auditing 2.1.4... "
BEFORE_OUTPUT["2.1.4"]=$(audit_2_1_4 2>&1)
BEFORE_RESULTS["2.1.4"]=$?

RULE_END_TIME["2.1.4"]=$(date +%s)
RULE_DURATION["2.1.4"]=$((RULE_END_TIME["2.1.4"] - RULE_START_TIME["2.1.4"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.4"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.4"]}"

if [ "${BEFORE_RESULTS["2.1.4"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.4"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.4"]}"
log_detailed ""


# --- Before Audit: 2.1.5 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [41/50]: 2.1.5"
RULE_START_TIME["2.1.5"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[41/50] Auditing 2.1.5... "
BEFORE_OUTPUT["2.1.5"]=$(audit_2_1_5 2>&1)
BEFORE_RESULTS["2.1.5"]=$?

RULE_END_TIME["2.1.5"]=$(date +%s)
RULE_DURATION["2.1.5"]=$((RULE_END_TIME["2.1.5"] - RULE_START_TIME["2.1.5"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.5"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.5"]}"

if [ "${BEFORE_RESULTS["2.1.5"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.5"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.5"]}"
log_detailed ""


# --- Before Audit: 2.1.6 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [42/50]: 2.1.6"
RULE_START_TIME["2.1.6"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[42/50] Auditing 2.1.6... "
BEFORE_OUTPUT["2.1.6"]=$(audit_2_1_6 2>&1)
BEFORE_RESULTS["2.1.6"]=$?

RULE_END_TIME["2.1.6"]=$(date +%s)
RULE_DURATION["2.1.6"]=$((RULE_END_TIME["2.1.6"] - RULE_START_TIME["2.1.6"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.6"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.6"]}"

if [ "${BEFORE_RESULTS["2.1.6"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.6"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.6"]}"
log_detailed ""


# --- Before Audit: 2.1.7 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [43/50]: 2.1.7"
RULE_START_TIME["2.1.7"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[43/50] Auditing 2.1.7... "
BEFORE_OUTPUT["2.1.7"]=$(audit_2_1_7 2>&1)
BEFORE_RESULTS["2.1.7"]=$?

RULE_END_TIME["2.1.7"]=$(date +%s)
RULE_DURATION["2.1.7"]=$((RULE_END_TIME["2.1.7"] - RULE_START_TIME["2.1.7"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.7"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.7"]}"

if [ "${BEFORE_RESULTS["2.1.7"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.7"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.7"]}"
log_detailed ""


# --- Before Audit: 2.1.8 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [44/50]: 2.1.8"
RULE_START_TIME["2.1.8"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[44/50] Auditing 2.1.8... "
BEFORE_OUTPUT["2.1.8"]=$(audit_2_1_8 2>&1)
BEFORE_RESULTS["2.1.8"]=$?

RULE_END_TIME["2.1.8"]=$(date +%s)
RULE_DURATION["2.1.8"]=$((RULE_END_TIME["2.1.8"] - RULE_START_TIME["2.1.8"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.8"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.8"]}"

if [ "${BEFORE_RESULTS["2.1.8"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.8"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.8"]}"
log_detailed ""


# --- Before Audit: 2.1.9 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [45/50]: 2.1.9"
RULE_START_TIME["2.1.9"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[45/50] Auditing 2.1.9... "
BEFORE_OUTPUT["2.1.9"]=$(audit_2_1_9 2>&1)
BEFORE_RESULTS["2.1.9"]=$?

RULE_END_TIME["2.1.9"]=$(date +%s)
RULE_DURATION["2.1.9"]=$((RULE_END_TIME["2.1.9"] - RULE_START_TIME["2.1.9"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.9"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.9"]}"

if [ "${BEFORE_RESULTS["2.1.9"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.9"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.9"]}"
log_detailed ""


# --- Before Audit: 2.1.10 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [46/50]: 2.1.10"
RULE_START_TIME["2.1.10"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[46/50] Auditing 2.1.10... "
BEFORE_OUTPUT["2.1.10"]=$(audit_2_1_10 2>&1)
BEFORE_RESULTS["2.1.10"]=$?

RULE_END_TIME["2.1.10"]=$(date +%s)
RULE_DURATION["2.1.10"]=$((RULE_END_TIME["2.1.10"] - RULE_START_TIME["2.1.10"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.10"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.10"]}"

if [ "${BEFORE_RESULTS["2.1.10"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.10"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.10"]}"
log_detailed ""


# --- Before Audit: 2.1.11 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [47/50]: 2.1.11"
RULE_START_TIME["2.1.11"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[47/50] Auditing 2.1.11... "
BEFORE_OUTPUT["2.1.11"]=$(audit_2_1_11 2>&1)
BEFORE_RESULTS["2.1.11"]=$?

RULE_END_TIME["2.1.11"]=$(date +%s)
RULE_DURATION["2.1.11"]=$((RULE_END_TIME["2.1.11"] - RULE_START_TIME["2.1.11"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.11"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.11"]}"

if [ "${BEFORE_RESULTS["2.1.11"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.11"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.11"]}"
log_detailed ""


# --- Before Audit: 2.1.12 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [48/50]: 2.1.12"
RULE_START_TIME["2.1.12"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[48/50] Auditing 2.1.12... "
BEFORE_OUTPUT["2.1.12"]=$(audit_2_1_12 2>&1)
BEFORE_RESULTS["2.1.12"]=$?

RULE_END_TIME["2.1.12"]=$(date +%s)
RULE_DURATION["2.1.12"]=$((RULE_END_TIME["2.1.12"] - RULE_START_TIME["2.1.12"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.12"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.12"]}"

if [ "${BEFORE_RESULTS["2.1.12"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.12"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.12"]}"
log_detailed ""


# --- Before Audit: 2.1.13 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [49/50]: 2.1.13"
RULE_START_TIME["2.1.13"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[49/50] Auditing 2.1.13... "
BEFORE_OUTPUT["2.1.13"]=$(audit_2_1_13 2>&1)
BEFORE_RESULTS["2.1.13"]=$?

RULE_END_TIME["2.1.13"]=$(date +%s)
RULE_DURATION["2.1.13"]=$((RULE_END_TIME["2.1.13"] - RULE_START_TIME["2.1.13"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.13"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.13"]}"

if [ "${BEFORE_RESULTS["2.1.13"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.13"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.13"]}"
log_detailed ""


# --- Before Audit: 2.1.14 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [50/50]: 2.1.14"
RULE_START_TIME["2.1.14"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[50/50] Auditing 2.1.14... "
BEFORE_OUTPUT["2.1.14"]=$(audit_2_1_14 2>&1)
BEFORE_RESULTS["2.1.14"]=$?

RULE_END_TIME["2.1.14"]=$(date +%s)
RULE_DURATION["2.1.14"]=$((RULE_END_TIME["2.1.14"] - RULE_START_TIME["2.1.14"]))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${RULE_DURATION["2.1.14"]} seconds"
log_detailed "Exit Code: ${BEFORE_RESULTS["2.1.14"]}"

if [ "${BEFORE_RESULTS["2.1.14"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${BEFORE_RESULTS["2.1.14"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${BEFORE_OUTPUT["2.1.14"]}"
log_detailed ""


###############################################################################
# PHASE 2: REMEDIATION
###############################################################################
echo ""
echo -e "${YELLOW}=== PHASE 2: Remediation ===${NC}"
echo ""

log_detailed "================================================================================"
log_detailed "PHASE 2: REMEDIATION"
log_detailed "================================================================================"
log_detailed ""

REMEDIATED_COUNT=0
SKIPPED_NA_COUNT=0
for rule_id in "${RULES_LIST[@]}"; do
    # Skip if NOT_APPLICABLE (exit code 2)
    if [ "${BEFORE_RESULTS[$rule_id]}" -eq 2 ]; then
        echo -e "${YELLOW}Skipping $rule_id (NOT_APPLICABLE)${NC}"
        log_detailed "Skipping Rule: $rule_id (NOT_APPLICABLE - exit code 2)"
        ((SKIPPED_NA_COUNT++)) || true
        continue
    fi
    
    # Only remediate if FAIL (exit code 1)
    if [ "${BEFORE_RESULTS[$rule_id]}" -eq 1 ]; then
        echo -e "${BLUE}Remediating $rule_id...${NC}"
        log_detailed "--------------------------------------------------------------------------------"
        log_detailed "Remediating Rule: $rule_id"
        log_detailed "Reason: Failed in initial audit (exit code: ${BEFORE_RESULTS[$rule_id]})"
        log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

        REMEDIATION_START=$(date +%s)
        REMEDIATION_OUTPUT=""

        case "$rule_id" in

            "1.1.1.1")
                REMEDIATION_OUTPUT=$(remediate_1_1_1_1 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.1.1.2")
                REMEDIATION_OUTPUT=$(remediate_1_1_1_2 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.1.1.3")
                REMEDIATION_OUTPUT=$(remediate_1_1_1_3 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.1.1.4")
                REMEDIATION_OUTPUT=$(remediate_1_1_1_4 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.1.1.5")
                REMEDIATION_OUTPUT=$(remediate_1_1_1_5 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.1.1.6")
                REMEDIATION_OUTPUT=$(remediate_1_1_1_6 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.1.1.7")
                REMEDIATION_OUTPUT=$(remediate_1_1_1_7 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.1.1.8")
                REMEDIATION_OUTPUT=$(remediate_1_1_1_8 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.1.1.9")
                REMEDIATION_OUTPUT=$(remediate_1_1_1_9 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.3.1.1")
                REMEDIATION_OUTPUT=$(remediate_1_3_1_1 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.3.1.2")
                REMEDIATION_OUTPUT=$(remediate_1_3_1_2 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.3.1.3")
                REMEDIATION_OUTPUT=$(remediate_1_3_1_3 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.3.1.4")
                REMEDIATION_OUTPUT=$(remediate_1_3_1_4 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.4.1")
                REMEDIATION_OUTPUT=$(remediate_1_4_1 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.4.2")
                REMEDIATION_OUTPUT=$(remediate_1_4_2 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.5.1")
                REMEDIATION_OUTPUT=$(remediate_1_5_1 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.5.2")
                REMEDIATION_OUTPUT=$(remediate_1_5_2 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.5.3")
                REMEDIATION_OUTPUT=$(remediate_1_5_3 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.5.4")
                REMEDIATION_OUTPUT=$(remediate_1_5_4 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.5.5")
                REMEDIATION_OUTPUT=$(remediate_1_5_5 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.6.1")
                REMEDIATION_OUTPUT=$(remediate_1_6_1 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.6.2")
                REMEDIATION_OUTPUT=$(remediate_1_6_2 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.6.3")
                REMEDIATION_OUTPUT=$(remediate_1_6_3 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.6.4")
                REMEDIATION_OUTPUT=$(remediate_1_6_4 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.6.5")
                REMEDIATION_OUTPUT=$(remediate_1_6_5 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.6.6")
                REMEDIATION_OUTPUT=$(remediate_1_6_6 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.7.1")
                REMEDIATION_OUTPUT=$(remediate_1_7_1 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.7.2")
                REMEDIATION_OUTPUT=$(remediate_1_7_2 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.7.3")
                REMEDIATION_OUTPUT=$(remediate_1_7_3 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.7.4")
                REMEDIATION_OUTPUT=$(remediate_1_7_4 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.7.5")
                REMEDIATION_OUTPUT=$(remediate_1_7_5 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.7.6")
                REMEDIATION_OUTPUT=$(remediate_1_7_6 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.7.7")
                REMEDIATION_OUTPUT=$(remediate_1_7_7 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.7.8")
                REMEDIATION_OUTPUT=$(remediate_1_7_8 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.7.9")
                REMEDIATION_OUTPUT=$(remediate_1_7_9 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.7.10")
                REMEDIATION_OUTPUT=$(remediate_1_7_10 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.1")
                REMEDIATION_OUTPUT=$(remediate_2_1_1 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.2")
                REMEDIATION_OUTPUT=$(remediate_2_1_2 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.3")
                REMEDIATION_OUTPUT=$(remediate_2_1_3 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.4")
                REMEDIATION_OUTPUT=$(remediate_2_1_4 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.5")
                REMEDIATION_OUTPUT=$(remediate_2_1_5 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.6")
                REMEDIATION_OUTPUT=$(remediate_2_1_6 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.7")
                REMEDIATION_OUTPUT=$(remediate_2_1_7 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.8")
                REMEDIATION_OUTPUT=$(remediate_2_1_8 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.9")
                REMEDIATION_OUTPUT=$(remediate_2_1_9 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.10")
                REMEDIATION_OUTPUT=$(remediate_2_1_10 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.11")
                REMEDIATION_OUTPUT=$(remediate_2_1_11 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.12")
                REMEDIATION_OUTPUT=$(remediate_2_1_12 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.13")
                REMEDIATION_OUTPUT=$(remediate_2_1_13 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "2.1.14")
                REMEDIATION_OUTPUT=$(remediate_2_1_14 2>&1)
                REMEDIATION_EXIT=$?
                ;;

        esac

        REMEDIATION_END=$(date +%s)
        REMEDIATION_DURATION=$((REMEDIATION_END - REMEDIATION_START))

        log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
        log_detailed "Duration: ${REMEDIATION_DURATION} seconds"
        log_detailed "Exit Code: ${REMEDIATION_EXIT:-0}"
        log_detailed ""
        log_detailed "REMEDIATION OUTPUT:"
        log_detailed "${REMEDIATION_OUTPUT:-No output captured}"
        log_detailed ""

        ((REMEDIATED_COUNT++))
    fi
done

if [ "$REMEDIATED_COUNT" -eq 0 ] && [ "$SKIPPED_NA_COUNT" -eq 0 ]; then
    echo "No remediation needed - all rules passed!"
    log_detailed "No remediation needed - all rules passed initial audit"
elif [ "$REMEDIATED_COUNT" -eq 0 ]; then
    echo "No remediation needed - rules either passed or not applicable"
    log_detailed "No remediation needed. Skipped (N/A): $SKIPPED_NA_COUNT"
else
    echo ""
    echo "Remediated $REMEDIATED_COUNT rule(s), skipped $SKIPPED_NA_COUNT (N/A)"
    log_detailed "Total rules remediated: $REMEDIATED_COUNT"
    log_detailed "Total rules skipped (N/A): $SKIPPED_NA_COUNT"
fi

log_detailed ""


###############################################################################
# PHASE 3: FINAL AUDIT (AFTER)
###############################################################################
echo ""
echo -e "${YELLOW}=== PHASE 3: Final Audit (AFTER) ===${NC}"
echo ""

log_detailed "================================================================================"
log_detailed "PHASE 3: FINAL AUDIT (AFTER)"
log_detailed "================================================================================"
log_detailed ""



# --- After Audit: 1.1.1.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [1/50]: 1.1.1.1"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[1/50] Re-auditing 1.1.1.1... "
AFTER_OUTPUT["1.1.1.1"]=$(audit_1_1_1_1 2>&1)
AFTER_RESULTS["1.1.1.1"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.1.1.1"]}"

if [ "${AFTER_RESULTS["1.1.1.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.1.1.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.1.1.1"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.1.1.1"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.1.1.1"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.1.1.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.1"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.1.1.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.1"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.1.1.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.1"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.1.1.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.1"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.1.1.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [2/50]: 1.1.1.2"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[2/50] Re-auditing 1.1.1.2... "
AFTER_OUTPUT["1.1.1.2"]=$(audit_1_1_1_2 2>&1)
AFTER_RESULTS["1.1.1.2"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.1.1.2"]}"

if [ "${AFTER_RESULTS["1.1.1.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.1.1.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.1.1.2"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.1.1.2"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.1.1.2"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.1.1.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.2"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.1.1.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.2"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.1.1.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.2"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.1.1.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.2"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.1.1.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [3/50]: 1.1.1.3"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[3/50] Re-auditing 1.1.1.3... "
AFTER_OUTPUT["1.1.1.3"]=$(audit_1_1_1_3 2>&1)
AFTER_RESULTS["1.1.1.3"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.1.1.3"]}"

if [ "${AFTER_RESULTS["1.1.1.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.1.1.3"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.1.1.3"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.1.1.3"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.1.1.3"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.1.1.3"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.3"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.1.1.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.3"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.1.1.3"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.3"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.1.1.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.3"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.1.1.4 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [4/50]: 1.1.1.4"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[4/50] Re-auditing 1.1.1.4... "
AFTER_OUTPUT["1.1.1.4"]=$(audit_1_1_1_4 2>&1)
AFTER_RESULTS["1.1.1.4"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.1.1.4"]}"

if [ "${AFTER_RESULTS["1.1.1.4"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.1.1.4"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.1.1.4"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.1.1.4"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.1.1.4"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.1.1.4"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.4"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.1.1.4"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.4"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.1.1.4"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.4"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.1.1.4"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.4"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.1.1.5 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [5/50]: 1.1.1.5"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[5/50] Re-auditing 1.1.1.5... "
AFTER_OUTPUT["1.1.1.5"]=$(audit_1_1_1_5 2>&1)
AFTER_RESULTS["1.1.1.5"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.1.1.5"]}"

if [ "${AFTER_RESULTS["1.1.1.5"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.1.1.5"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.1.1.5"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.1.1.5"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.1.1.5"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.1.1.5"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.5"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.1.1.5"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.5"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.1.1.5"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.5"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.1.1.5"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.5"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.1.1.6 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [6/50]: 1.1.1.6"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[6/50] Re-auditing 1.1.1.6... "
AFTER_OUTPUT["1.1.1.6"]=$(audit_1_1_1_6 2>&1)
AFTER_RESULTS["1.1.1.6"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.1.1.6"]}"

if [ "${AFTER_RESULTS["1.1.1.6"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.1.1.6"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.1.1.6"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.1.1.6"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.1.1.6"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.1.1.6"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.6"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.1.1.6"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.6"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.1.1.6"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.6"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.1.1.6"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.6"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.1.1.7 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [7/50]: 1.1.1.7"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[7/50] Re-auditing 1.1.1.7... "
AFTER_OUTPUT["1.1.1.7"]=$(audit_1_1_1_7 2>&1)
AFTER_RESULTS["1.1.1.7"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.1.1.7"]}"

if [ "${AFTER_RESULTS["1.1.1.7"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.1.1.7"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.1.1.7"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.1.1.7"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.1.1.7"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.1.1.7"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.7"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.1.1.7"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.7"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.1.1.7"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.7"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.1.1.7"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.7"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.1.1.8 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [8/50]: 1.1.1.8"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[8/50] Re-auditing 1.1.1.8... "
AFTER_OUTPUT["1.1.1.8"]=$(audit_1_1_1_8 2>&1)
AFTER_RESULTS["1.1.1.8"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.1.1.8"]}"

if [ "${AFTER_RESULTS["1.1.1.8"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.1.1.8"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.1.1.8"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.1.1.8"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.1.1.8"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.1.1.8"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.8"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.1.1.8"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.8"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.1.1.8"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.8"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.1.1.8"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.8"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.1.1.9 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [9/50]: 1.1.1.9"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[9/50] Re-auditing 1.1.1.9... "
AFTER_OUTPUT["1.1.1.9"]=$(audit_1_1_1_9 2>&1)
AFTER_RESULTS["1.1.1.9"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.1.1.9"]}"

if [ "${AFTER_RESULTS["1.1.1.9"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.1.1.9"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.1.1.9"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.1.1.9"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.1.1.9"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.1.1.9"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.9"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.1.1.9"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.9"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.1.1.9"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.1.1.9"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.1.1.9"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.9"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.3.1.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [10/50]: 1.3.1.1"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[10/50] Re-auditing 1.3.1.1... "
AFTER_OUTPUT["1.3.1.1"]=$(audit_1_3_1_1 2>&1)
AFTER_RESULTS["1.3.1.1"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.3.1.1"]}"

if [ "${AFTER_RESULTS["1.3.1.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.3.1.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.3.1.1"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.3.1.1"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.3.1.1"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.3.1.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.3.1.1"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.3.1.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.3.1.1"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.3.1.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.3.1.1"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.3.1.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.3.1.1"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.3.1.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [11/50]: 1.3.1.2"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[11/50] Re-auditing 1.3.1.2... "
AFTER_OUTPUT["1.3.1.2"]=$(audit_1_3_1_2 2>&1)
AFTER_RESULTS["1.3.1.2"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.3.1.2"]}"

if [ "${AFTER_RESULTS["1.3.1.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.3.1.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.3.1.2"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.3.1.2"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.3.1.2"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.3.1.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.3.1.2"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.3.1.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.3.1.2"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.3.1.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.3.1.2"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.3.1.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.3.1.2"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.3.1.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [12/50]: 1.3.1.3"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[12/50] Re-auditing 1.3.1.3... "
AFTER_OUTPUT["1.3.1.3"]=$(audit_1_3_1_3 2>&1)
AFTER_RESULTS["1.3.1.3"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.3.1.3"]}"

if [ "${AFTER_RESULTS["1.3.1.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.3.1.3"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.3.1.3"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.3.1.3"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.3.1.3"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.3.1.3"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.3.1.3"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.3.1.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.3.1.3"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.3.1.3"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.3.1.3"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.3.1.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.3.1.3"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.3.1.4 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [13/50]: 1.3.1.4"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[13/50] Re-auditing 1.3.1.4... "
AFTER_OUTPUT["1.3.1.4"]=$(audit_1_3_1_4 2>&1)
AFTER_RESULTS["1.3.1.4"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.3.1.4"]}"

if [ "${AFTER_RESULTS["1.3.1.4"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.3.1.4"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.3.1.4"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.3.1.4"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.3.1.4"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.3.1.4"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.3.1.4"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.3.1.4"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.3.1.4"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.3.1.4"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.3.1.4"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.3.1.4"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.3.1.4"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.4.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [14/50]: 1.4.1"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[14/50] Re-auditing 1.4.1... "
AFTER_OUTPUT["1.4.1"]=$(audit_1_4_1 2>&1)
AFTER_RESULTS["1.4.1"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.4.1"]}"

if [ "${AFTER_RESULTS["1.4.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.4.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.4.1"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.4.1"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.4.1"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.4.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.4.1"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.4.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.4.1"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.4.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.4.1"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.4.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.4.1"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.4.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [15/50]: 1.4.2"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[15/50] Re-auditing 1.4.2... "
AFTER_OUTPUT["1.4.2"]=$(audit_1_4_2 2>&1)
AFTER_RESULTS["1.4.2"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.4.2"]}"

if [ "${AFTER_RESULTS["1.4.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.4.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.4.2"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.4.2"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.4.2"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.4.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.4.2"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.4.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.4.2"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.4.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.4.2"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.4.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.4.2"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.5.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [16/50]: 1.5.1"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[16/50] Re-auditing 1.5.1... "
AFTER_OUTPUT["1.5.1"]=$(audit_1_5_1 2>&1)
AFTER_RESULTS["1.5.1"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.5.1"]}"

if [ "${AFTER_RESULTS["1.5.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.5.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.5.1"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.5.1"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.5.1"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.5.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.5.1"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.5.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.5.1"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.5.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.5.1"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.5.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.5.1"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.5.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [17/50]: 1.5.2"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[17/50] Re-auditing 1.5.2... "
AFTER_OUTPUT["1.5.2"]=$(audit_1_5_2 2>&1)
AFTER_RESULTS["1.5.2"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.5.2"]}"

if [ "${AFTER_RESULTS["1.5.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.5.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.5.2"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.5.2"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.5.2"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.5.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.5.2"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.5.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.5.2"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.5.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.5.2"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.5.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.5.2"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.5.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [18/50]: 1.5.3"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[18/50] Re-auditing 1.5.3... "
AFTER_OUTPUT["1.5.3"]=$(audit_1_5_3 2>&1)
AFTER_RESULTS["1.5.3"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.5.3"]}"

if [ "${AFTER_RESULTS["1.5.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.5.3"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.5.3"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.5.3"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.5.3"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.5.3"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.5.3"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.5.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.5.3"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.5.3"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.5.3"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.5.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.5.3"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.5.4 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [19/50]: 1.5.4"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[19/50] Re-auditing 1.5.4... "
AFTER_OUTPUT["1.5.4"]=$(audit_1_5_4 2>&1)
AFTER_RESULTS["1.5.4"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.5.4"]}"

if [ "${AFTER_RESULTS["1.5.4"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.5.4"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.5.4"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.5.4"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.5.4"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.5.4"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.5.4"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.5.4"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.5.4"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.5.4"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.5.4"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.5.4"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.5.4"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.5.5 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [20/50]: 1.5.5"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[20/50] Re-auditing 1.5.5... "
AFTER_OUTPUT["1.5.5"]=$(audit_1_5_5 2>&1)
AFTER_RESULTS["1.5.5"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.5.5"]}"

if [ "${AFTER_RESULTS["1.5.5"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.5.5"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.5.5"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.5.5"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.5.5"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.5.5"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.5.5"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.5.5"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.5.5"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.5.5"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.5.5"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.5.5"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.5.5"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.6.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [21/50]: 1.6.1"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[21/50] Re-auditing 1.6.1... "
AFTER_OUTPUT["1.6.1"]=$(audit_1_6_1 2>&1)
AFTER_RESULTS["1.6.1"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.6.1"]}"

if [ "${AFTER_RESULTS["1.6.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.6.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.6.1"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.6.1"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.6.1"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.6.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.6.1"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.6.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.6.1"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.6.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.6.1"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.6.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.6.1"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.6.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [22/50]: 1.6.2"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[22/50] Re-auditing 1.6.2... "
AFTER_OUTPUT["1.6.2"]=$(audit_1_6_2 2>&1)
AFTER_RESULTS["1.6.2"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.6.2"]}"

if [ "${AFTER_RESULTS["1.6.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.6.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.6.2"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.6.2"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.6.2"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.6.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.6.2"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.6.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.6.2"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.6.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.6.2"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.6.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.6.2"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.6.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [23/50]: 1.6.3"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[23/50] Re-auditing 1.6.3... "
AFTER_OUTPUT["1.6.3"]=$(audit_1_6_3 2>&1)
AFTER_RESULTS["1.6.3"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.6.3"]}"

if [ "${AFTER_RESULTS["1.6.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.6.3"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.6.3"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.6.3"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.6.3"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.6.3"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.6.3"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.6.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.6.3"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.6.3"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.6.3"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.6.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.6.3"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.6.4 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [24/50]: 1.6.4"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[24/50] Re-auditing 1.6.4... "
AFTER_OUTPUT["1.6.4"]=$(audit_1_6_4 2>&1)
AFTER_RESULTS["1.6.4"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.6.4"]}"

if [ "${AFTER_RESULTS["1.6.4"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.6.4"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.6.4"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.6.4"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.6.4"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.6.4"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.6.4"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.6.4"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.6.4"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.6.4"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.6.4"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.6.4"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.6.4"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.6.5 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [25/50]: 1.6.5"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[25/50] Re-auditing 1.6.5... "
AFTER_OUTPUT["1.6.5"]=$(audit_1_6_5 2>&1)
AFTER_RESULTS["1.6.5"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.6.5"]}"

if [ "${AFTER_RESULTS["1.6.5"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.6.5"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.6.5"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.6.5"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.6.5"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.6.5"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.6.5"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.6.5"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.6.5"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.6.5"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.6.5"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.6.5"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.6.5"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.6.6 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [26/50]: 1.6.6"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[26/50] Re-auditing 1.6.6... "
AFTER_OUTPUT["1.6.6"]=$(audit_1_6_6 2>&1)
AFTER_RESULTS["1.6.6"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.6.6"]}"

if [ "${AFTER_RESULTS["1.6.6"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.6.6"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.6.6"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.6.6"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.6.6"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.6.6"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.6.6"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.6.6"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.6.6"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.6.6"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.6.6"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.6.6"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.6.6"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.7.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [27/50]: 1.7.1"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[27/50] Re-auditing 1.7.1... "
AFTER_OUTPUT["1.7.1"]=$(audit_1_7_1 2>&1)
AFTER_RESULTS["1.7.1"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.7.1"]}"

if [ "${AFTER_RESULTS["1.7.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.7.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.7.1"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.7.1"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.7.1"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.7.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.1"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.7.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.1"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.7.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.1"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.7.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.1"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.7.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [28/50]: 1.7.2"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[28/50] Re-auditing 1.7.2... "
AFTER_OUTPUT["1.7.2"]=$(audit_1_7_2 2>&1)
AFTER_RESULTS["1.7.2"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.7.2"]}"

if [ "${AFTER_RESULTS["1.7.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.7.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.7.2"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.7.2"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.7.2"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.7.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.2"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.7.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.2"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.7.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.2"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.7.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.2"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.7.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [29/50]: 1.7.3"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[29/50] Re-auditing 1.7.3... "
AFTER_OUTPUT["1.7.3"]=$(audit_1_7_3 2>&1)
AFTER_RESULTS["1.7.3"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.7.3"]}"

if [ "${AFTER_RESULTS["1.7.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.7.3"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.7.3"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.7.3"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.7.3"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.7.3"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.3"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.7.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.3"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.7.3"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.3"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.7.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.3"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.7.4 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [30/50]: 1.7.4"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[30/50] Re-auditing 1.7.4... "
AFTER_OUTPUT["1.7.4"]=$(audit_1_7_4 2>&1)
AFTER_RESULTS["1.7.4"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.7.4"]}"

if [ "${AFTER_RESULTS["1.7.4"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.7.4"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.7.4"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.7.4"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.7.4"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.7.4"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.4"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.7.4"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.4"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.7.4"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.4"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.7.4"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.4"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.7.5 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [31/50]: 1.7.5"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[31/50] Re-auditing 1.7.5... "
AFTER_OUTPUT["1.7.5"]=$(audit_1_7_5 2>&1)
AFTER_RESULTS["1.7.5"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.7.5"]}"

if [ "${AFTER_RESULTS["1.7.5"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.7.5"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.7.5"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.7.5"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.7.5"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.7.5"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.5"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.7.5"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.5"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.7.5"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.5"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.7.5"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.5"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.7.6 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [32/50]: 1.7.6"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[32/50] Re-auditing 1.7.6... "
AFTER_OUTPUT["1.7.6"]=$(audit_1_7_6 2>&1)
AFTER_RESULTS["1.7.6"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.7.6"]}"

if [ "${AFTER_RESULTS["1.7.6"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.7.6"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.7.6"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.7.6"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.7.6"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.7.6"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.6"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.7.6"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.6"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.7.6"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.6"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.7.6"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.6"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.7.7 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [33/50]: 1.7.7"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[33/50] Re-auditing 1.7.7... "
AFTER_OUTPUT["1.7.7"]=$(audit_1_7_7 2>&1)
AFTER_RESULTS["1.7.7"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.7.7"]}"

if [ "${AFTER_RESULTS["1.7.7"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.7.7"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.7.7"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.7.7"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.7.7"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.7.7"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.7"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.7.7"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.7"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.7.7"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.7"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.7.7"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.7"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.7.8 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [34/50]: 1.7.8"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[34/50] Re-auditing 1.7.8... "
AFTER_OUTPUT["1.7.8"]=$(audit_1_7_8 2>&1)
AFTER_RESULTS["1.7.8"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.7.8"]}"

if [ "${AFTER_RESULTS["1.7.8"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.7.8"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.7.8"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.7.8"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.7.8"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.7.8"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.8"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.7.8"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.8"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.7.8"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.8"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.7.8"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.8"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.7.9 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [35/50]: 1.7.9"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[35/50] Re-auditing 1.7.9... "
AFTER_OUTPUT["1.7.9"]=$(audit_1_7_9 2>&1)
AFTER_RESULTS["1.7.9"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.7.9"]}"

if [ "${AFTER_RESULTS["1.7.9"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.7.9"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.7.9"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.7.9"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.7.9"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.7.9"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.9"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.7.9"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.9"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.7.9"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.9"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.7.9"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.9"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.7.10 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [36/50]: 1.7.10"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[36/50] Re-auditing 1.7.10... "
AFTER_OUTPUT["1.7.10"]=$(audit_1_7_10 2>&1)
AFTER_RESULTS["1.7.10"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["1.7.10"]}"

if [ "${AFTER_RESULTS["1.7.10"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["1.7.10"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.7.10"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["1.7.10"]}" -eq 2 ] || [ "${AFTER_RESULTS["1.7.10"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["1.7.10"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.10"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.7.10"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.10"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.7.10"]}" -eq 1 ] && [ "${AFTER_RESULTS["1.7.10"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["1.7.10"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.7.10"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [37/50]: 2.1.1"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[37/50] Re-auditing 2.1.1... "
AFTER_OUTPUT["2.1.1"]=$(audit_2_1_1 2>&1)
AFTER_RESULTS["2.1.1"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.1"]}"

if [ "${AFTER_RESULTS["2.1.1"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.1"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.1"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.1"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.1"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.1"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.1"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.1"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.1"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.1"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [38/50]: 2.1.2"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[38/50] Re-auditing 2.1.2... "
AFTER_OUTPUT["2.1.2"]=$(audit_2_1_2 2>&1)
AFTER_RESULTS["2.1.2"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.2"]}"

if [ "${AFTER_RESULTS["2.1.2"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.2"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.2"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.2"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.2"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.2"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.2"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.2"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.2"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.2"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [39/50]: 2.1.3"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[39/50] Re-auditing 2.1.3... "
AFTER_OUTPUT["2.1.3"]=$(audit_2_1_3 2>&1)
AFTER_RESULTS["2.1.3"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.3"]}"

if [ "${AFTER_RESULTS["2.1.3"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.3"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.3"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.3"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.3"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.3"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.3"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.3"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.3"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.3"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.3"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.4 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [40/50]: 2.1.4"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[40/50] Re-auditing 2.1.4... "
AFTER_OUTPUT["2.1.4"]=$(audit_2_1_4 2>&1)
AFTER_RESULTS["2.1.4"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.4"]}"

if [ "${AFTER_RESULTS["2.1.4"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.4"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.4"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.4"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.4"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.4"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.4"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.4"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.4"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.4"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.4"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.4"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.4"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.5 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [41/50]: 2.1.5"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[41/50] Re-auditing 2.1.5... "
AFTER_OUTPUT["2.1.5"]=$(audit_2_1_5 2>&1)
AFTER_RESULTS["2.1.5"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.5"]}"

if [ "${AFTER_RESULTS["2.1.5"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.5"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.5"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.5"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.5"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.5"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.5"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.5"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.5"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.5"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.5"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.5"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.5"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.6 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [42/50]: 2.1.6"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[42/50] Re-auditing 2.1.6... "
AFTER_OUTPUT["2.1.6"]=$(audit_2_1_6 2>&1)
AFTER_RESULTS["2.1.6"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.6"]}"

if [ "${AFTER_RESULTS["2.1.6"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.6"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.6"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.6"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.6"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.6"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.6"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.6"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.6"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.6"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.6"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.6"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.6"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.7 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [43/50]: 2.1.7"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[43/50] Re-auditing 2.1.7... "
AFTER_OUTPUT["2.1.7"]=$(audit_2_1_7 2>&1)
AFTER_RESULTS["2.1.7"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.7"]}"

if [ "${AFTER_RESULTS["2.1.7"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.7"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.7"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.7"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.7"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.7"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.7"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.7"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.7"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.7"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.7"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.7"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.7"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.8 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [44/50]: 2.1.8"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[44/50] Re-auditing 2.1.8... "
AFTER_OUTPUT["2.1.8"]=$(audit_2_1_8 2>&1)
AFTER_RESULTS["2.1.8"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.8"]}"

if [ "${AFTER_RESULTS["2.1.8"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.8"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.8"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.8"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.8"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.8"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.8"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.8"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.8"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.8"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.8"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.8"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.8"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.9 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [45/50]: 2.1.9"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[45/50] Re-auditing 2.1.9... "
AFTER_OUTPUT["2.1.9"]=$(audit_2_1_9 2>&1)
AFTER_RESULTS["2.1.9"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.9"]}"

if [ "${AFTER_RESULTS["2.1.9"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.9"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.9"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.9"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.9"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.9"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.9"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.9"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.9"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.9"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.9"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.9"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.9"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.10 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [46/50]: 2.1.10"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[46/50] Re-auditing 2.1.10... "
AFTER_OUTPUT["2.1.10"]=$(audit_2_1_10 2>&1)
AFTER_RESULTS["2.1.10"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.10"]}"

if [ "${AFTER_RESULTS["2.1.10"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.10"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.10"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.10"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.10"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.10"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.10"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.10"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.10"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.10"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.10"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.10"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.10"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.11 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [47/50]: 2.1.11"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[47/50] Re-auditing 2.1.11... "
AFTER_OUTPUT["2.1.11"]=$(audit_2_1_11 2>&1)
AFTER_RESULTS["2.1.11"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.11"]}"

if [ "${AFTER_RESULTS["2.1.11"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.11"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.11"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.11"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.11"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.11"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.11"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.11"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.11"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.11"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.11"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.11"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.11"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.12 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [48/50]: 2.1.12"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[48/50] Re-auditing 2.1.12... "
AFTER_OUTPUT["2.1.12"]=$(audit_2_1_12 2>&1)
AFTER_RESULTS["2.1.12"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.12"]}"

if [ "${AFTER_RESULTS["2.1.12"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.12"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.12"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.12"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.12"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.12"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.12"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.12"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.12"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.12"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.12"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.12"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.12"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.13 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [49/50]: 2.1.13"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[49/50] Re-auditing 2.1.13... "
AFTER_OUTPUT["2.1.13"]=$(audit_2_1_13 2>&1)
AFTER_RESULTS["2.1.13"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.13"]}"

if [ "${AFTER_RESULTS["2.1.13"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.13"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.13"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.13"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.13"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.13"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.13"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.13"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.13"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.13"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.13"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.13"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.13"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 2.1.14 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [50/50]: 2.1.14"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[50/50] Re-auditing 2.1.14... "
AFTER_OUTPUT["2.1.14"]=$(audit_2_1_14 2>&1)
AFTER_RESULTS["2.1.14"]=$?

AFTER_END=$(date +%s)
AFTER_DURATION=$((AFTER_END - AFTER_START))

log_detailed "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
log_detailed "Duration: ${AFTER_DURATION} seconds"
log_detailed "Exit Code: ${AFTER_RESULTS["2.1.14"]}"

if [ "${AFTER_RESULTS["2.1.14"]}" -eq 0 ]; then
    echo -e "${GREEN}PASS${NC}"
    log_detailed "Status: PASS"
elif [ "${AFTER_RESULTS["2.1.14"]}" -eq 2 ]; then
    echo -e "${YELLOW}N/A${NC}"
    log_detailed "Status: NOT_APPLICABLE"
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["2.1.14"]}"
log_detailed ""

# Log comparison (handle N/A cases)
if [ "${BEFORE_RESULTS["2.1.14"]}" -eq 2 ] || [ "${AFTER_RESULTS["2.1.14"]}" -eq 2 ]; then
    log_detailed "RESULT: NOT_APPLICABLE - Rule is not applicable to this system"
elif [ "${BEFORE_RESULTS["2.1.14"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.14"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["2.1.14"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.14"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["2.1.14"]}" -eq 1 ] && [ "${AFTER_RESULTS["2.1.14"]}" -eq 1 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
elif [ "${BEFORE_RESULTS["2.1.14"]}" -eq 0 ] && [ "${AFTER_RESULTS["2.1.14"]}" -eq 1 ]; then
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


###############################################################################
# PHASE 4: GENERATE REPORTS
###############################################################################
echo ""
echo -e "${YELLOW}=== PHASE 4: Generating Reports ===${NC}"
echo ""

log_detailed "================================================================================"
log_detailed "PHASE 4: GENERATING REPORTS"
log_detailed "================================================================================"
log_detailed ""

REPORT_FILE="$REPORT_DIR/cis_report.html"
HOSTNAME=$(hostname)
REPORT_DATE=$(date '+%Y-%m-%d %H:%M:%S')
EXECUTION_END=$(date '+%Y-%m-%d %H:%M:%S')

# Count results
BEFORE_PASS=0
BEFORE_FAIL=0
BEFORE_NA=0
AFTER_PASS=0
AFTER_FAIL=0
AFTER_NA=0
FIXED_COUNT=0

for rule_id in "${RULES_LIST[@]}"; do
    # Before counts
    if [ "${BEFORE_RESULTS[$rule_id]}" -eq 0 ]; then
        ((BEFORE_PASS++)) || true
    elif [ "${BEFORE_RESULTS[$rule_id]}" -eq 2 ]; then
        ((BEFORE_NA++)) || true
    else
        ((BEFORE_FAIL++)) || true
    fi
    # After counts
    if [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
        ((AFTER_PASS++)) || true
    elif [ "${AFTER_RESULTS[$rule_id]}" -eq 2 ]; then
        ((AFTER_NA++)) || true
    else
        ((AFTER_FAIL++)) || true
    fi
    # Fixed count (only if before was FAIL and after is PASS)
    if [ "${BEFORE_RESULTS[$rule_id]}" -eq 1 ] && [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
        ((FIXED_COUNT++)) || true
    fi
done

cat > "$REPORT_FILE" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Benchmark Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; padding: 20px; color: #eee; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { text-align: center; margin-bottom: 30px; color: #00d4ff; text-shadow: 0 0 20px rgba(0,212,255,0.5); }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); border-radius: 15px; padding: 20px; text-align: center; border: 1px solid rgba(255,255,255,0.2); }
        .card h3 { font-size: 0.9em; color: #aaa; margin-bottom: 10px; text-transform: uppercase; }
        .card .value { font-size: 2.5em; font-weight: bold; }
        .card.pass .value { color: #00ff88; }
        .card.fail .value { color: #ff4757; }
        .card.fixed .value { color: #ffd700; }
        .card.info .value { color: #00d4ff; }
        table { width: 100%; border-collapse: collapse; background: rgba(255,255,255,0.05); border-radius: 10px; overflow: hidden; }
        th { background: rgba(0,212,255,0.2); padding: 15px; text-align: left; font-weight: 600; }
        td { padding: 12px 15px; border-bottom: 1px solid rgba(255,255,255,0.1); }
        tr:hover { background: rgba(255,255,255,0.05); }
        .status { padding: 5px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }
        .status.pass { background: rgba(0,255,136,0.2); color: #00ff88; }
        .status.fail { background: rgba(255,71,87,0.2); color: #ff4757; }
        .status.fixed { background: rgba(255,215,0,0.2); color: #ffd700; }
        .status.na { background: rgba(128,128,128,0.2); color: #888; }
        .toggle-btn { background: rgba(0,212,255,0.2); border: none; color: #00d4ff; padding: 5px 10px; border-radius: 5px; cursor: pointer; font-size: 0.8em; }
        .toggle-btn:hover { background: rgba(0,212,255,0.4); }
        .output { display: none; background: #0a0a15; padding: 10px; border-radius: 5px; margin-top: 10px; font-family: monospace; font-size: 0.85em; white-space: pre-wrap; max-height: 200px; overflow-y: auto; }
        .output.show { display: block; }
        .section { margin-bottom: 30px; }
        .section h2 { margin-bottom: 15px; color: #00d4ff; border-bottom: 2px solid rgba(0,212,255,0.3); padding-bottom: 10px; }
        .meta { text-align: center; color: #666; margin-bottom: 20px; font-size: 0.9em; }
        .arrow { margin: 0 10px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ CIS Benchmark Report</h1>
        <p class="meta">Host: <strong>HOSTNAME_PLACEHOLDER</strong> | Generated: <strong>DATE_PLACEHOLDER</strong></p>
        
        <div class="summary">
            <div class="card info">
                <h3>Total Rules</h3>
                <div class="value">TOTAL_PLACEHOLDER</div>
            </div>
            <div class="card pass">
                <h3>Before: Pass</h3>
                <div class="value">BEFORE_PASS_PLACEHOLDER</div>
            </div>
            <div class="card fail">
                <h3>Before: Fail</h3>
                <div class="value">BEFORE_FAIL_PLACEHOLDER</div>
            </div>
            <div class="card fixed">
                <h3>Fixed</h3>
                <div class="value">FIXED_PLACEHOLDER</div>
            </div>
            <div class="card pass">
                <h3>After: Pass</h3>
                <div class="value">AFTER_PASS_PLACEHOLDER</div>
            </div>
            <div class="card fail">
                <h3>After: Fail</h3>
                <div class="value">AFTER_FAIL_PLACEHOLDER</div>
            </div>
        </div>

        <div class="section">
            <h2>📋 Detailed Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>Before</th>
                        <th></th>
                        <th>After</th>
                        <th>Status</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
HTMLEOF

# Generate table rows
for rule_id in "${RULES_LIST[@]}"; do
    before_status="FAIL"
    before_class="fail"
    after_status="FAIL"
    after_class="fail"
    overall_status="FAIL"
    overall_class="fail"
    
    # Before status
    if [ "${BEFORE_RESULTS[$rule_id]}" -eq 0 ]; then
        before_status="PASS"
        before_class="pass"
    elif [ "${BEFORE_RESULTS[$rule_id]}" -eq 2 ]; then
        before_status="N/A"
        before_class="na"
    fi
    
    # After status
    if [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
        after_status="PASS"
        after_class="pass"
    elif [ "${AFTER_RESULTS[$rule_id]}" -eq 2 ]; then
        after_status="N/A"
        after_class="na"
    fi
    
    # Overall status
    if [ "${BEFORE_RESULTS[$rule_id]}" -eq 2 ] || [ "${AFTER_RESULTS[$rule_id]}" -eq 2 ]; then
        overall_status="N/A"
        overall_class="na"
    elif [ "${BEFORE_RESULTS[$rule_id]}" -eq 1 ] && [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
        overall_status="FIXED"
        overall_class="fixed"
    elif [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
        overall_status="PASS"
        overall_class="pass"
    fi
    
    # Escape HTML in output
    before_out=$(echo "${BEFORE_OUTPUT[$rule_id]}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    after_out=$(echo "${AFTER_OUTPUT[$rule_id]}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
    
    cat >> "$REPORT_FILE" << ROWEOF
                    <tr>
                        <td><strong>$rule_id</strong></td>
                        <td><span class="status $before_class">$before_status</span></td>
                        <td class="arrow">→</td>
                        <td><span class="status $after_class">$after_status</span></td>
                        <td><span class="status $overall_class">$overall_status</span></td>
                        <td>
                            <button class="toggle-btn" onclick="this.nextElementSibling.classList.toggle('show')">Show Output</button>
                            <div class="output"><strong>Before:</strong>
$before_out

<strong>After:</strong>
$after_out</div>
                        </td>
                    </tr>
ROWEOF
done

cat >> "$REPORT_FILE" << 'HTMLEOF'
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
HTMLEOF

# Replace placeholders
sed -i "s/HOSTNAME_PLACEHOLDER/$HOSTNAME/g" "$REPORT_FILE"
sed -i "s/DATE_PLACEHOLDER/$REPORT_DATE/g" "$REPORT_FILE"
sed -i "s/TOTAL_PLACEHOLDER/$TOTAL_RULES/g" "$REPORT_FILE"
sed -i "s/BEFORE_PASS_PLACEHOLDER/$BEFORE_PASS/g" "$REPORT_FILE"
sed -i "s/BEFORE_FAIL_PLACEHOLDER/$BEFORE_FAIL/g" "$REPORT_FILE"
sed -i "s/AFTER_PASS_PLACEHOLDER/$AFTER_PASS/g" "$REPORT_FILE"
sed -i "s/AFTER_FAIL_PLACEHOLDER/$AFTER_FAIL/g" "$REPORT_FILE"
sed -i "s/FIXED_PLACEHOLDER/$FIXED_COUNT/g" "$REPORT_FILE"

# Finalize detailed log with summary
log_detailed "================================================================================"
log_detailed "EXECUTION SUMMARY"
log_detailed "================================================================================"
log_detailed ""
log_detailed "Execution Completed: $EXECUTION_END"
log_detailed ""
log_detailed "OVERALL STATISTICS:"
log_detailed "  Total Rules Checked: $TOTAL_RULES"
log_detailed "  Before Audit - Passed: $BEFORE_PASS"
log_detailed "  Before Audit - Failed: $BEFORE_FAIL"
log_detailed "  Rules Remediated: $REMEDIATED_COUNT"
log_detailed "  After Audit - Passed: $AFTER_PASS"
log_detailed "  After Audit - Failed: $AFTER_FAIL"
log_detailed "  Successfully Fixed: $FIXED_COUNT"
log_detailed ""

# List failed rules after remediation
if [ "$AFTER_FAIL" -gt 0 ]; then
    log_detailed "RULES STILL FAILING AFTER REMEDIATION:"
    for rule_id in "${RULES_LIST[@]}"; do
        if [ "${AFTER_RESULTS[$rule_id]}" -ne 0 ]; then
            log_detailed "  - $rule_id (exit code: ${AFTER_RESULTS[$rule_id]})"
        fi
    done
    log_detailed ""
fi

# List successfully fixed rules
if [ "$FIXED_COUNT" -gt 0 ]; then
    log_detailed "SUCCESSFULLY FIXED RULES:"
    for rule_id in "${RULES_LIST[@]}"; do
        if [ "${BEFORE_RESULTS[$rule_id]}" -ne 0 ] && [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
            log_detailed "  - $rule_id"
        fi
    done
    log_detailed ""
fi

# List rules that passed from the start
INITIAL_PASS=0
for rule_id in "${RULES_LIST[@]}"; do
    if [ "${BEFORE_RESULTS[$rule_id]}" -eq 0 ] && [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
        ((INITIAL_PASS++)) || true
    fi
done

if [ "$INITIAL_PASS" -gt 0 ]; then
    log_detailed "RULES THAT PASSED FROM THE START:"
    for rule_id in "${RULES_LIST[@]}"; do
        if [ "${BEFORE_RESULTS[$rule_id]}" -eq 0 ] && [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
            log_detailed "  - $rule_id"
        fi
    done
    log_detailed ""
fi

log_detailed "================================================================================"
log_detailed "GENERATED FILES:"
log_detailed "  HTML Report: $REPORT_FILE"
log_detailed "  Detailed Log: $DETAILED_LOG"
log_detailed "================================================================================"
log_detailed ""
log_detailed "End of report."

echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}  Reports generated successfully!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
echo "Report locations:"
echo "  HTML Report:    $REPORT_FILE"
echo "  Detailed Log:   $DETAILED_LOG"
echo ""
echo "Summary:"
echo "  Before: $BEFORE_PASS passed, $BEFORE_FAIL failed"
echo "  After:  $AFTER_PASS passed, $AFTER_FAIL failed"
echo "  Fixed:  $FIXED_COUNT rule(s)"
echo ""
