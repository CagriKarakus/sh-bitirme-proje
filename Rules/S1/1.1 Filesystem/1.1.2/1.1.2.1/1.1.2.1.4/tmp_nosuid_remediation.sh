#!/bin/bash

# Remediation for Rule 1.1.2.4: Ensure nosuid option set on /tmp partition
# Source: xccdf_org.ssgproject.content_profile_cis_level1_server_customized-20250524.0033.sh

# Remediation is applicable only in certain platforms
if ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) && { findmnt --kernel "/tmp" > /dev/null || findmnt --fstab "/tmp" > /dev/null; }; then

    # the mount point /tmp has to be defined in /etc/fstab
    # before this remediation can be executed. In case it is not defined, the
    # remediation aborts and no changes regarding the mount point are done.
    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/tmp")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/tmp' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /tmp in /etc/fstab" >&2; exit 1; }
    
    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /tmp)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        echo " /tmp  defaults,${previous_mount_opts}nosuid 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nosuid"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nosuid|" /etc/fstab
    fi

    if mkdir -p "/tmp"; then
        if mountpoint -q "/tmp"; then
            mount -o remount --target "/tmp"
        fi
    fi
    
    echo "Remediation applied successfully."

else
    echo 'Remediation is not applicable, nothing was done'
fi
