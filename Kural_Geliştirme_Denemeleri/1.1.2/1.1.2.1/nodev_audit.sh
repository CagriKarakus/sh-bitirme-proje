#!/usr/bin/env bash
# CIS 1.1.2.1.2 Audit - Ensure nodev option set on /tmp partition
#
# RATIONALE:
# The nodev mount option specifies that the filesystem cannot contain special devices.
# Since /tmp is a world-writable directory, it should not be trusted to contain device files.
#
# Security benefits of nodev on /tmp:
# - Prevents creation of block or character special devices
# - Blocks device-based privilege escalation attacks
# - Attackers cannot create malicious device nodes (e.g., /dev/sda, /dev/mem)
# - Prevents unauthorized access to hardware devices through /tmp
# - Defense-in-depth: even if attacker creates device file, it cannot be used
#
# Attack scenario without nodev:
# 1. Attacker gains limited write access to /tmp
# 2. Creates malicious device node: mknod /tmp/evil-device c 1 1 (access to /dev/mem)
# 3. Uses device node to read/write kernel memory
# 4. Escalates privileges to root
#
# PREREQUISITES:
# - /tmp must be mounted as a separate partition
# - This check depends on CIS 1.1.2.1 being compliant first

# Exit codes
# 0 = PASS (nodev is set)
# 1 = FAIL (nodev is not set or /tmp not separate partition)
# 2 = NOT_APPLICABLE (/tmp is not a separate partition)

TMP_DIR="/tmp"

echo "[CHECK] Auditing nodev option on /tmp partition..."
echo ""

###########################################
# STEP 1: Verify /tmp is a separate partition
###########################################

echo "[PREREQUISITE] Checking if /tmp is a separate partition..."

is_separate_partition=false

# Method 1: Use findmnt with TARGET verification
if command -v findmnt >/dev/null 2>&1; then
    target=$(findmnt -kn -o TARGET "${TMP_DIR}" 2>/dev/null)
    
    if [[ "${target}" == "${TMP_DIR}" ]]; then
        is_separate_partition=true
        echo "[PASS] /tmp is a separate partition"
    fi
fi

# Method 2: Fallback to mountpoint
if [[ "${is_separate_partition}" == false ]]; then
    if mountpoint -q "${TMP_DIR}" 2>/dev/null; then
        if mount | grep -q "on ${TMP_DIR} type"; then
            is_separate_partition=true
            echo "[PASS] /tmp is a separate partition (detected via mountpoint)"
        fi
    fi
fi

# Method 3: Check /proc/mounts
if [[ "${is_separate_partition}" == false ]]; then
    if awk '$2 == "/tmp" {found=1; exit} END {exit !found}' /proc/mounts 2>/dev/null; then
        is_separate_partition=true
        echo "[PASS] /tmp is a separate partition (detected via /proc/mounts)"
    fi
fi

# If /tmp is not a separate partition, this check is not applicable
if [[ "${is_separate_partition}" == false ]]; then
    echo "[NOT_APPLICABLE] /tmp is NOT a separate partition"
    echo ""
    echo "[INFO] This check requires /tmp to be a separate partition first"
    echo "[ACTION] Configure /tmp as separate partition (CIS 1.1.2.1) before applying nodev"
    echo ""
    echo "=========================================="
    echo "[RESULT] NOT APPLICABLE"
    echo "Prerequisite not met: /tmp must be separate partition"
    echo "=========================================="
    exit 2
fi

echo ""

###########################################
# STEP 2: Check for nodev mount option
###########################################

echo "[CHECK] Verifying nodev mount option on /tmp..."
echo ""

# Get current mount options
mount_options=""

# Method 1: Use findmnt to get mount options (most reliable)
if command -v findmnt >/dev/null 2>&1; then
    mount_options=$(findmnt -kn -o OPTIONS "${TMP_DIR}" 2>/dev/null)
    
    if [[ -n "${mount_options}" ]]; then
        echo "[INFO] Current mount options: ${mount_options}"
        echo ""
        
        # Check if nodev is present in mount options
        # Use word boundary matching to avoid false positives (e.g., "mynodev")
        if echo "${mount_options}" | grep -qw "nodev"; then
            echo "[PASS] nodev option is set on /tmp"
            
            # Show security benefit
            echo ""
            echo "[SECURITY] nodev protection is active:"
            echo "  ✓ Special device files cannot be created in /tmp"
            echo "  ✓ Block devices (e.g., /dev/sda) blocked"
            echo "  ✓ Character devices (e.g., /dev/mem) blocked"
            echo "  ✓ Device-based privilege escalation prevented"
            
            # Additional verification: try to show what's protected
            echo ""
            echo "[VERIFICATION] Testing device file restrictions..."
            
            # Create a test filename (don't actually create the device)
            test_device="${TMP_DIR}/test-device-$$"
            
            # Try to create a device node (this should fail with nodev)
            if mknod "${test_device}" c 1 3 2>/dev/null; then
                echo "[WARNING] Device creation succeeded - nodev may not be enforced!"
                rm -f "${test_device}" 2>/dev/null
                echo "[FAIL] nodev is set but not enforced by kernel"
                echo ""
                echo "=========================================="
                echo "[RESULT] NON-COMPLIANT (FAIL)"
                echo "nodev option present but not enforced"
                echo "=========================================="
                exit 1
            else
                echo "[PASS] Device creation blocked (nodev is enforced)"
                rm -f "${test_device}" 2>/dev/null  # Clean up if somehow created
            fi
            
            echo ""
            echo "=========================================="
            echo "[RESULT] FULLY COMPLIANT (PASS)"
            echo ""
            echo "SUMMARY:"
            echo "  - /tmp is a separate partition: YES"
            echo "  - nodev option is set: YES"
            echo "  - nodev is enforced: YES"
            echo ""
            echo "PROTECTION ACTIVE:"
            echo "  - Device nodes cannot be created in /tmp"
            echo "  - System protected from device-based attacks"
            echo "=========================================="
            exit 0
        else
            echo "[FAIL] nodev option is NOT set on /tmp"
            
            # Show what options are currently set
            echo ""
            echo "[CURRENT] Active mount options:"
            echo "  ${mount_options}"
            
            # Explain the security risk
            echo ""
            echo "[SECURITY RISK] Without nodev:"
            echo "  ✗ Attackers can create malicious device nodes"
            echo "  ✗ Potential privilege escalation via device files"
            echo "  ✗ Unauthorized hardware access possible"
            echo "  ✗ No protection against device-based attacks"
            
            # Show example attack scenario
            echo ""
            echo "[ATTACK SCENARIO]"
            echo "  1. Attacker creates: mknod /tmp/evil c 1 1 (/dev/mem)"
            echo "  2. Uses device to read/write kernel memory"
            echo "  3. Escalates to root privileges"
            echo "  4. Compromises entire system"
        fi
    else
        echo "[ERROR] Could not retrieve mount options for /tmp"
        exit 1
    fi
fi

# Method 2: Fallback to parsing mount command output
if [[ -z "${mount_options}" ]]; then
    mount_line=$(mount | grep " on ${TMP_DIR} type " | head -n 1)
    
    if [[ -n "${mount_line}" ]]; then
        # Extract options from mount output (between parentheses)
        mount_options=$(echo "${mount_line}" | grep -oP '\(.*?\)' | tr -d '()')
        
        echo "[INFO] Current mount options: ${mount_options}"
        echo ""
        
        if echo "${mount_options}" | grep -qw "nodev"; then
            echo "[PASS] nodev option is set on /tmp"
            echo ""
            echo "=========================================="
            echo "[RESULT] COMPLIANT (PASS)"
            echo "=========================================="
            exit 0
        else
            echo "[FAIL] nodev option is NOT set on /tmp"
        fi
    else
        echo "[ERROR] Could not retrieve mount information for /tmp"
        exit 1
    fi
fi

# Method 3: Final fallback - check /proc/mounts
if [[ -z "${mount_options}" ]]; then
    proc_mount_line=$(awk '$2 == "/tmp" {print; exit}' /proc/mounts 2>/dev/null)
    
    if [[ -n "${proc_mount_line}" ]]; then
        # Fourth field in /proc/mounts is mount options
        mount_options=$(echo "${proc_mount_line}" | awk '{print $4}')
        
        echo "[INFO] Current mount options: ${mount_options}"
        echo ""
        
        if echo "${mount_options}" | grep -qw "nodev"; then
            echo "[PASS] nodev option is set on /tmp"
            echo ""
            echo "=========================================="
            echo "[RESULT] COMPLIANT (PASS)"
            echo "=========================================="
            exit 0
        else
            echo "[FAIL] nodev option is NOT set on /tmp"
        fi
    fi
fi

###########################################
# STEP 3: Check persistent configuration
###########################################

echo ""
echo "[PERSISTENCE] Checking if nodev is configured persistently..."
echo ""

persistent_config_ok=false

# Check /etc/fstab for nodev option
if grep -E "^\s*[^#].*\s+/tmp\s+" /etc/fstab >/dev/null 2>&1; then
    fstab_entry=$(grep -E "^\s*[^#].*\s+/tmp\s+" /etc/fstab | head -n 1)
    echo "[INFO] /tmp entry in /etc/fstab:"
    echo "  ${fstab_entry}"
    echo ""
    
    # Check if nodev is in fstab entry
    if echo "${fstab_entry}" | grep -qw "nodev"; then
        echo "[WARNING] nodev is configured in /etc/fstab but not active in current mount"
        echo "[ACTION] May need to remount: mount -o remount /tmp"
        persistent_config_ok=true
    else
        echo "[FAIL] nodev is NOT configured in /etc/fstab"
        echo "[IMPACT] nodev will not persist after reboot"
    fi
else
    echo "[INFO] /tmp not found in /etc/fstab (may be using systemd)"
fi

# Check systemd mount unit if applicable
if command -v systemctl >/dev/null 2>&1; then
    if [[ -f /etc/systemd/system/tmp.mount ]] || [[ -f /usr/lib/systemd/system/tmp.mount ]]; then
        echo ""
        echo "[SYSTEMD] Checking systemd mount unit..."
        
        # Find the unit file
        if [[ -f /etc/systemd/system/tmp.mount ]]; then
            unit_file="/etc/systemd/system/tmp.mount"
        else
            unit_file="/usr/lib/systemd/system/tmp.mount"
        fi
        
        echo "[INFO] Found systemd unit: ${unit_file}"
        
        # Check Options line in [Mount] section
        if grep -A 10 "^\[Mount\]" "${unit_file}" | grep -q "^Options=.*nodev"; then
            echo "[WARNING] nodev is configured in systemd unit but not active"
            echo "[ACTION] May need to: systemctl daemon-reload && systemctl restart tmp.mount"
            persistent_config_ok=true
        else
            echo "[FAIL] nodev is NOT configured in systemd unit"
            echo "[IMPACT] nodev will not persist after reboot"
        fi
    fi
fi

if [[ "${persistent_config_ok}" == false ]]; then
    echo ""
    echo "[WARNING] No persistent configuration found for nodev"
fi

###########################################
# STEP 4: Final result
###########################################

echo ""
echo "=========================================="
echo "[RESULT] NON-COMPLIANT (FAIL)"
echo ""
echo "ISSUES:"
echo "  - /tmp is a separate partition: YES"
echo "  - nodev option is set: NO"
echo ""
echo "ACTION REQUIRED:"
echo "  1. Run remediation script to add nodev option"
echo "  2. Or manually remount: mount -o remount,nodev /tmp"
echo "  3. Update /etc/fstab or systemd unit for persistence"
echo ""
echo "SECURITY IMPACT:"
echo "  - Device files can be created in /tmp"
echo "  - System vulnerable to device-based privilege escalation"
echo "  - Attackers could access hardware through /tmp"
echo ""
echo "EXAMPLE ATTACK:"
echo "  # Attacker with write access to /tmp:"
echo "  mknod /tmp/evil c 1 1    # Creates /dev/mem access"
echo "  # Read/write kernel memory through /tmp/evil"
echo "  # Escalate to root privileges"
echo "=========================================="

exit 1