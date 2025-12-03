#!/bin/bash
set -e

GRUB_FILE="/etc/default/grub"
[[ ! -f "${GRUB_FILE}.original" ]] && cp "$GRUB_FILE" "${GRUB_FILE}.original"

current=$(grep '^GRUB_CMDLINE_LINUX=' "$GRUB_FILE" 2>/dev/null | sed 's/^GRUB_CMDLINE_LINUX="\(.*\)"$/\1/' || echo "")

new="$current"
[[ ! "$new" =~ (^|[[:space:]])apparmor=1([[:space:]]|$) ]] && new="$new apparmor=1" && changed=1
[[ ! "$new" =~ (^|[[:space:]])security=apparmor([[:space:]]|$) ]] && new="$new security=apparmor" && changed=1

if [[ -n "$changed" ]]; then
    new=$(echo "$new" | xargs)
    sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"$new\"|" "$GRUB_FILE" || \
        echo "GRUB_CMDLINE_LINUX=\"$new\"" >> "$GRUB_FILE"
    
    update-grub 2>/dev/null || grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || \
        grub2-mkconfig -o /boot/grub/grub.cfg
    
    echo "CONFIGURED: Reboot required"
else
    echo "ALREADY CONFIGURED"
fi