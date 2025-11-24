#!/usr/bin/env bash
# CIS 1.1.1.2 Remediation Script - Disable freevxfs Kernel Module (Simplified)
# Safe for personal systems / homelabs

mod_name="freevxfs"
conf_file="/etc/modprobe.d/${mod_name}.conf"

echo "=== Remediation: Disabling ${mod_name} kernel module ==="

# 1. Check if freevxfs exists in kernel modules
if find /lib/modules/$(uname -r) -type f -path "*/fs/${mod_name}/*.ko*" >/dev/null 2>&1; then
    echo "Module ${mod_name} found in kernel modules."

    # 2. If currently loaded, unload it
    if lsmod | grep -q "^${mod_name}"; then
        echo "Unloading ${mod_name} module..."
        modprobe -r ${mod_name} 2>/dev/null || rmmod ${mod_name} 2>/dev/null
    else
        echo "Module ${mod_name} not loaded."
    fi

    # 3. Ensure /etc/modprobe.d/freevxfs.conf exists with disable rules
    echo "Creating or updating ${conf_file}..."
    {
        echo "install ${mod_name} /bin/false"
        echo "blacklist ${mod_name}"
    } > "${conf_file}"

    chmod 644 "${conf_file}"
    echo "Module denylisted and disabled."

    # 4. Optional: update initramfs if your distro uses it
    if command -v update-initramfs >/dev/null 2>&1; then
        echo "Updating initramfs (Debian/Ubuntu)..."
        update-initramfs -u
    elif command -v dracut >/dev/null 2>&1; then
        echo "Updating initramfs (RHEL/Fedora)..."
        dracut -f
    elif command -v mkinitrd >/dev/null 2>&1; then
        echo "Updating initramfs (SUSE)..."
        mkinitrd
    fi

else
    echo "Module ${mod_name} not present or built into kernel."
    echo "No remediation necessary."
fi

echo "=== Remediation complete for ${mod_name} ==="