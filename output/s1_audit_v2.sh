#!/usr/bin/env bash
###############################################################################
#
# CIS Benchmark Audit & Remediation Script
#
# Generated on    : 2025-12-20 13:20:51
# Source registry : platforms\linux\ubuntu\desktop\rules\index.json
# Rule count      : 5
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

TOTAL_RULES=5
RULES_LIST=("1.1.1.1" "1.1.1.2" "1.1.1.3" "1.4.2" "1.5.1")

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
    conf_dir="/etc/modprobe.d"
    conf_file="${conf_dir}/cramfs.conf"
    kernel_ver="$(uname -r)"

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

    # Create or update configuration file (idempotent)
    {
        echo "# CIS 1.1.1.1 - Disable cramfs filesystem"
        echo "install ${mod_name} /bin/false"
        echo "blacklist ${mod_name}"
    } > "${conf_file}"

    echo "[CONFIGURED] ${conf_file} created/updated"

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
    conf_dir="/etc/modprobe.d"
    conf_file="${conf_dir}/freevxfs.conf"
    kernel_ver="$(uname -r)"

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

    # Create or update configuration file (idempotent)
    {
        echo "# CIS 1.1.1.2 - Disable freevxfs filesystem"
        echo "install ${mod_name} /bin/false"
        echo "blacklist ${mod_name}"
    } > "${conf_file}"

    echo "[CONFIGURED] ${conf_file} created/updated"

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
    conf_dir="/etc/modprobe.d"
    conf_file="${conf_dir}/hfs.conf"
    kernel_ver="$(uname -r)"

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

    # Create or update configuration file (idempotent)
    {
        echo "# CIS 1.1.1.3 - Disable hfs filesystem"
        echo "install ${mod_name} /bin/false"
        echo "blacklist ${mod_name}"
    } > "${conf_file}"

    echo "[CONFIGURED] ${conf_file} created/updated"

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


# --- Before Audit: 1.1.1.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [1/5]: 1.1.1.1"
RULE_START_TIME["1.1.1.1"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[1/5] Auditing 1.1.1.1... "
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
log_detailed "Auditing Rule [2/5]: 1.1.1.2"
RULE_START_TIME["1.1.1.2"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[2/5] Auditing 1.1.1.2... "
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
log_detailed "Auditing Rule [3/5]: 1.1.1.3"
RULE_START_TIME["1.1.1.3"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[3/5] Auditing 1.1.1.3... "
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


# --- Before Audit: 1.4.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Auditing Rule [4/5]: 1.4.2"
RULE_START_TIME["1.4.2"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[4/5] Auditing 1.4.2... "
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
log_detailed "Auditing Rule [5/5]: 1.5.1"
RULE_START_TIME["1.5.1"]=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[5/5] Auditing 1.5.1... "
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
            "1.4.2")
                REMEDIATION_OUTPUT=$(remediate_1_4_2 2>&1)
                REMEDIATION_EXIT=$?
                ;;
            "1.5.1")
                REMEDIATION_OUTPUT=$(remediate_1_5_1 2>&1)
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
log_detailed "Re-auditing Rule [1/5]: 1.1.1.1"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[1/5] Re-auditing 1.1.1.1... "
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
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.1.1.1"]}"
log_detailed ""

# Log comparison
if [ "${BEFORE_RESULTS["1.1.1.1"]}" -ne 0 ] && [ "${AFTER_RESULTS["1.1.1.1"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.1.1.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.1"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.1.1.1"]}" -ne 0 ] && [ "${AFTER_RESULTS["1.1.1.1"]}" -ne 0 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
else
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.1.1.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [2/5]: 1.1.1.2"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[2/5] Re-auditing 1.1.1.2... "
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
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.1.1.2"]}"
log_detailed ""

# Log comparison
if [ "${BEFORE_RESULTS["1.1.1.2"]}" -ne 0 ] && [ "${AFTER_RESULTS["1.1.1.2"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.1.1.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.2"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.1.1.2"]}" -ne 0 ] && [ "${AFTER_RESULTS["1.1.1.2"]}" -ne 0 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
else
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.1.1.3 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [3/5]: 1.1.1.3"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[3/5] Re-auditing 1.1.1.3... "
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
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.1.1.3"]}"
log_detailed ""

# Log comparison
if [ "${BEFORE_RESULTS["1.1.1.3"]}" -ne 0 ] && [ "${AFTER_RESULTS["1.1.1.3"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.1.1.3"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.1.1.3"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.1.1.3"]}" -ne 0 ] && [ "${AFTER_RESULTS["1.1.1.3"]}" -ne 0 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
else
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.4.2 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [4/5]: 1.4.2"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[4/5] Re-auditing 1.4.2... "
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
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.4.2"]}"
log_detailed ""

# Log comparison
if [ "${BEFORE_RESULTS["1.4.2"]}" -ne 0 ] && [ "${AFTER_RESULTS["1.4.2"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.4.2"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.4.2"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.4.2"]}" -ne 0 ] && [ "${AFTER_RESULTS["1.4.2"]}" -ne 0 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
else
    log_detailed "RESULT: REGRESSION - Rule was passing, now failing (unexpected)"
    log_detailed "WARNING: This is unexpected and requires investigation!"
fi
log_detailed ""


# --- After Audit: 1.5.1 ---
log_detailed "--------------------------------------------------------------------------------"
log_detailed "Re-auditing Rule [5/5]: 1.5.1"
AFTER_START=$(date +%s)
log_detailed "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"

echo -n "[5/5] Re-auditing 1.5.1... "
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
else
    echo -e "${RED}FAIL${NC}"
    log_detailed "Status: FAIL"
fi

log_detailed ""
log_detailed "OUTPUT:"
log_detailed "${AFTER_OUTPUT["1.5.1"]}"
log_detailed ""

# Log comparison
if [ "${BEFORE_RESULTS["1.5.1"]}" -ne 0 ] && [ "${AFTER_RESULTS["1.5.1"]}" -eq 0 ]; then
    log_detailed "RESULT: FIXED - Rule was failing, now passing after remediation"
elif [ "${BEFORE_RESULTS["1.5.1"]}" -eq 0 ] && [ "${AFTER_RESULTS["1.5.1"]}" -eq 0 ]; then
    log_detailed "RESULT: PASSED - Rule passed both before and after"
elif [ "${BEFORE_RESULTS["1.5.1"]}" -ne 0 ] && [ "${AFTER_RESULTS["1.5.1"]}" -ne 0 ]; then
    log_detailed "RESULT: STILL FAILING - Rule failed before and after remediation"
    log_detailed "WARNING: Remediation did not fix this rule. Manual intervention may be required."
else
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
AFTER_PASS=0
AFTER_FAIL=0
FIXED_COUNT=0

for rule_id in "${RULES_LIST[@]}"; do
    if [ "${BEFORE_RESULTS[$rule_id]}" -eq 0 ]; then
        ((BEFORE_PASS++)) || true
    else
        ((BEFORE_FAIL++)) || true
    fi
    if [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
        ((AFTER_PASS++)) || true
    else
        ((AFTER_FAIL++)) || true
    fi
    if [ "${BEFORE_RESULTS[$rule_id]}" -ne 0 ] && [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
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
    
    [ "${BEFORE_RESULTS[$rule_id]}" -eq 0 ] && before_status="PASS" && before_class="pass"
    [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ] && after_status="PASS" && after_class="pass"
    
    if [ "${BEFORE_RESULTS[$rule_id]}" -ne 0 ] && [ "${AFTER_RESULTS[$rule_id]}" -eq 0 ]; then
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
