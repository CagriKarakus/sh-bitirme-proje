#!/usr/bin/env bash
# CIS 1.1.2.1.1 Ensure /tmp is a separate partition (Automated)

set -euo pipefail

FSTAB_FILE="/etc/fstab"
SYSTEMD_UNIT="tmp.mount"
TMP_MOUNT_OPTS="defaults,rw,nosuid,nodev,noexec,relatime,size=2G"

usage() {
    cat <<USAGE
Usage: ${0##*/} <audit|remediate>

 audit      Check whether /tmp is mounted on its own filesystem and report status
 remediate  Configure the system to mount /tmp as tmpfs with recommended options
USAGE
}

require_root() {
    if [[ ${EUID} -ne 0 ]]; then
        echo "This action requires root privileges." >&2
        exit 1
    fi
}

check_tmp_mount() {
    if findmnt -kn /tmp >/dev/null 2>&1; then
        echo "PASS: /tmp is mounted."
        findmnt -kn /tmp
    else
        echo "FAIL: /tmp is not mounted as a separate filesystem."
        return 1
    fi
}

check_systemd_unit() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "WARN: systemctl not available; skipping unit status check."
        return 0
    fi

    status=$(systemctl is-enabled "${SYSTEMD_UNIT}" 2>/dev/null || true)
    case "${status}" in
        masked|disabled)
            echo "FAIL: ${SYSTEMD_UNIT} is ${status}."
            return 1
            ;;
        "")
            echo "WARN: ${SYSTEMD_UNIT} unit status unavailable."
            ;;
        *)
            echo "PASS: ${SYSTEMD_UNIT} is ${status}."
            ;;
    esac
}

check_fstab_entry() {
    if grep -Eq '^\s*[^#]+\s+/tmp\s+' "${FSTAB_FILE}"; then
        echo "PASS: /tmp entry found in ${FSTAB_FILE}."
        grep -E '^\s*[^#]+\s+/tmp\s+' "${FSTAB_FILE}"
    else
        echo "FAIL: No /tmp entry present in ${FSTAB_FILE}."
        return 1
    fi
}

remediate_systemd_unit() {
    systemctl unmask "${SYSTEMD_UNIT}" >/dev/null 2>&1 || true
    systemctl enable "${SYSTEMD_UNIT}" >/dev/null 2>&1 || true
}

ensure_fstab_entry() {
    if grep -Eq '^\s*[^#]+\s+/tmp\s+' "${FSTAB_FILE}"; then
        echo "INFO: /tmp entry already present in ${FSTAB_FILE}."
    else
        echo "INFO: Adding tmpfs entry for /tmp to ${FSTAB_FILE}."
        printf '\ntmpfs\t/tmp\ttmpfs\t%s\t0\t0\n' "${TMP_MOUNT_OPTS}" >> "${FSTAB_FILE}"
    fi
}

remount_tmp() {
    if findmnt -kn /tmp >/dev/null 2>&1; then
        echo "INFO: Remounting /tmp with updated options."
        mount -o remount,"${TMP_MOUNT_OPTS}" /tmp
    else
        echo "INFO: Mounting /tmp using configured entry."
        mount /tmp
    fi
}

audit() {
    result=0

    check_tmp_mount || result=1
    check_systemd_unit || result=1
    check_fstab_entry || result=1

    exit ${result}
}

remediate() {
    require_root

    if command -v systemctl >/dev/null 2>&1; then
        remediate_systemd_unit
    else
        echo "WARN: systemctl not available; skipping unit remediation."
    fi

    ensure_fstab_entry
    remount_tmp

    echo "Remediation completed."
}

main() {
    if [[ $# -ne 1 ]]; then
        usage
        exit 1
    fi

    case "$1" in
        audit)
            audit
            ;;
        remediate)
            remediate
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"

