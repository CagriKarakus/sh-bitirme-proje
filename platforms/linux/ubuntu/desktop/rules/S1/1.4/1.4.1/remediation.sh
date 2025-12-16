#!/bin/bash

# CIS Ubuntu 24.04 Benchmark
# 1.4.1 Ensure bootloader password is set (Automated)
# Remediation Script

set -euo pipefail  # Exit on error, undefined variables, pipe failures

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
CUSTOM_CFG="/etc/grub.d/40_custom_password"
BACKUP_DIR="/root/grub_backup_$(date +%Y%m%d_%H%M%S)"

echo "=========================================="
echo "CIS 1.4.1 - Bootloader Password Setup"
echo "=========================================="
echo ""
echo -e "${YELLOW}WARNING:${NC} This modifies bootloader configuration"
echo "Incorrect setup may prevent system boot"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}ERROR:${NC} Must run as root"
    exit 1
fi

# Check required commands
REQUIRED_CMDS=("grub-mkpasswd-pbkdf2")

# Detect GRUB update command
if command -v update-grub &> /dev/null; then
    UPDATE_CMD="update-grub"
    GRUB_DIR="/etc/grub.d"
    GRUB_CFG="/boot/grub/grub.cfg"
elif command -v grub2-mkconfig &> /dev/null; then
    UPDATE_CMD="grub2-mkconfig -o /boot/grub2/grub.cfg"
    GRUB_DIR="/etc/grub.d"
    GRUB_CFG="/boot/grub2/grub.cfg"
elif command -v grub-mkconfig &> /dev/null; then
    UPDATE_CMD="grub-mkconfig -o /boot/grub/grub.cfg"
    GRUB_DIR="/etc/grub.d"
    GRUB_CFG="/boot/grub/grub.cfg"
else
    echo -e "${RED}ERROR:${NC} No GRUB configuration command found"
    echo "Expected: update-grub, grub2-mkconfig, or grub-mkconfig"
    exit 1
fi

echo "Checking required commands..."
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$(echo "$cmd" | awk '{print $1}')" &> /dev/null; then
        echo -e "${RED}ERROR:${NC} Required command not found: $cmd"
        echo "Install: apt install grub2-common (Debian/Ubuntu)"
        echo "     or: yum install grub2-tools (RHEL/CentOS)"
        exit 1
    fi
done
echo -e "${GREEN}✓${NC} All required commands available"
echo ""

# Check if already configured
if [ -f "$CUSTOM_CFG" ]; then
    echo -e "${YELLOW}WARNING:${NC} Password configuration already exists: $CUSTOM_CFG"
    read -p "Continue and overwrite? [y/N]: " -r OVERWRITE
    if [[ ! "$OVERWRITE" =~ ^[Yy]$ ]]; then
        echo "Aborted by user"
        exit 0
    fi
    echo ""
fi

# Create backup
echo "Step 1: Creating backup"
echo "---------------------------------------"
mkdir -p "$BACKUP_DIR"
cp -r "$GRUB_DIR" "$BACKUP_DIR/" 2>/dev/null || true
[ -f "$GRUB_CFG" ] && cp "$GRUB_CFG" "$BACKUP_DIR/grub.cfg" || true
echo -e "${GREEN}✓${NC} Backup created: $BACKUP_DIR"
echo ""

# Get username
echo "Step 2: Configure superuser"
echo "---------------------------------------"
read -p "Enter GRUB superuser name [grubadmin]: " GRUB_USER
GRUB_USER=${GRUB_USER:-grubadmin}

# Validate username
if ! [[ "$GRUB_USER" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo -e "${RED}ERROR:${NC} Invalid username (use only: a-z A-Z 0-9 _ -)"
    exit 1
fi

echo -e "${GREEN}✓${NC} Superuser: $GRUB_USER"
echo ""

# Generate password
echo "Step 3: Generate encrypted password"
echo "---------------------------------------"
echo "You will be prompted to enter a password twice"
echo -e "${YELLOW}Important:${NC} Choose a strong password and store it securely!"
echo ""

# Generate password with proper parameters
TEMP_FILE=$(mktemp)
grub-mkpasswd-pbkdf2 --iteration-count=600000 > "$TEMP_FILE" 2>&1

# Extract hash
PBKDF2_HASH=$(grep -oP "(?<=PBKDF2 hash of your password is ).*" "$TEMP_FILE" | tr -d '\n\r')
rm -f "$TEMP_FILE"

# Validate hash format
if [ -z "$PBKDF2_HASH" ] || ! [[ "$PBKDF2_HASH" =~ ^grub\.pbkdf2\.sha512\. ]]; then
    echo -e "${RED}ERROR:${NC} Failed to generate valid password hash"
    exit 1
fi

echo -e "${GREEN}✓${NC} Password encrypted successfully"
echo ""

# Create configuration file
echo "Step 4: Create GRUB password configuration"
echo "---------------------------------------"

# Write the file directly without nested heredocs that confuse grub-script-check
cat > "$CUSTOM_CFG" << EOF
#!/bin/sh
exec tail -n +3 \$0
# CIS 1.4.1 - GRUB bootloader password protection
# This file is managed by CIS remediation script
# Do not edit manually - changes may be overwritten

set superusers="$GRUB_USER"
password_pbkdf2 $GRUB_USER $PBKDF2_HASH
EOF

chmod 755 "$CUSTOM_CFG"

# Verify file creation
if [ ! -f "$CUSTOM_CFG" ] || [ ! -x "$CUSTOM_CFG" ]; then
    echo -e "${RED}ERROR:${NC} Failed to create configuration file"
    exit 1
fi

echo -e "${GREEN}✓${NC} Configuration file created: $CUSTOM_CFG"
echo ""

# Optional: Unrestricted boot
echo "Step 5: Boot restriction settings"
echo "---------------------------------------"
echo "Choose boot behavior:"
echo "  [1] Require password for boot (Most Secure - CIS Recommended)"
echo "  [2] Allow boot without password (Only require for GRUB editing)"
echo ""
read -p "Enter choice [1]: " -r BOOT_CHOICE
BOOT_CHOICE=${BOOT_CHOICE:-1}

if [ "$BOOT_CHOICE" = "2" ]; then
    echo ""
    echo "Adding --unrestricted flag to boot entries..."
    
    # Find the Linux boot entry configuration file
    LINUX_CFG=""
    for file in "$GRUB_DIR/10_linux" "$GRUB_DIR/10-linux"; do
        if [ -f "$file" ]; then
            LINUX_CFG="$file"
            break
        fi
    done
    
    if [ -n "$LINUX_CFG" ]; then
        # Backup
        cp "$LINUX_CFG" "$BACKUP_DIR/"
        
        # Check if already has --unrestricted
        if grep -q 'CLASS=.*--unrestricted' "$LINUX_CFG"; then
            echo -e "${YELLOW}ℹ${NC} --unrestricted already present"
        else
            # Add --unrestricted only once, at the beginning of CLASS value
            sed -i '/^[[:space:]]*CLASS=/s/CLASS="/CLASS="--unrestricted /' "$LINUX_CFG"
            echo -e "${GREEN}✓${NC} Added --unrestricted to boot entries"
        fi
    else
        echo -e "${YELLOW}WARNING:${NC} Linux boot configuration not found"
        echo "You may need to manually add --unrestricted to boot entries"
    fi
    echo ""
    echo -e "${BLUE}Note:${NC} System will boot without password"
    echo "      Password required only for editing GRUB menu"
else
    echo -e "${GREEN}✓${NC} Password will be required for boot (Secure mode)"
fi

echo ""

# Validate configuration syntax if possible
# Note: grub-script-check may fail on /etc/grub.d/ scripts that use heredocs
# We'll validate the final grub.cfg instead after update-grub
echo "Step 6: Validating configuration"
echo "---------------------------------------"

# Check if the file has the expected content
if grep -q "^set superusers=\"$GRUB_USER\"" "$CUSTOM_CFG" && \
   grep -q "^password_pbkdf2 $GRUB_USER" "$CUSTOM_CFG"; then
    echo -e "${GREEN}✓${NC} Configuration content validated"
else
    echo -e "${RED}ERROR:${NC} Configuration validation failed"
    echo "File content:"
    cat "$CUSTOM_CFG"
    exit 1
fi

echo ""

# Update GRUB
echo "Step 7: Updating GRUB configuration"
echo "---------------------------------------"
echo "Running: $UPDATE_CMD"
echo ""

# Capture output and check for errors
UPDATE_OUTPUT=$($UPDATE_CMD 2>&1)
UPDATE_EXIT=$?

echo "$UPDATE_OUTPUT"

if [ $UPDATE_EXIT -ne 0 ] || echo "$UPDATE_OUTPUT" | grep -qi "error.*syntax\|syntax error"; then
    echo ""
    echo -e "${RED}ERROR:${NC} GRUB update failed"
    echo "Restoring backup..."
    cp -r "$BACKUP_DIR/grub.d/"* "$GRUB_DIR/" 2>/dev/null || true
    rm -f "$CUSTOM_CFG"
    $UPDATE_CMD 2>&1 || true
    echo ""
    echo "Backup location: $BACKUP_DIR"
    exit 1
fi

# Verify configuration was applied
echo ""
echo "Step 8: Verifying final configuration"
echo "---------------------------------------"

if grep -q "set superusers=\"$GRUB_USER\"" "$GRUB_CFG" && \
   grep -q "password_pbkdf2 $GRUB_USER" "$GRUB_CFG"; then
    echo -e "${GREEN}✓${NC} Password configuration successfully applied"
else
    echo -e "${RED}ERROR:${NC} Configuration not found in $GRUB_CFG"
    echo "Manual verification required"
    exit 1
fi

# Final syntax check on generated grub.cfg
if command -v grub-script-check &> /dev/null; then
    echo ""
    echo "Checking final GRUB configuration syntax..."
    if grub-script-check "$GRUB_CFG" 2>&1 | grep -qi "error\|syntax"; then
        echo -e "${YELLOW}WARNING:${NC} grub-script-check reported issues"
        echo "However, configuration was applied. Monitor next boot carefully."
    else
        echo -e "${GREEN}✓${NC} Final configuration syntax valid"
    fi
fi

echo ""
echo "=========================================="
echo "Configuration Completed Successfully"
echo "=========================================="
echo ""
echo -e "${GREEN}Summary:${NC}"
echo "  • Superuser: $GRUB_USER"
echo "  • Encryption: PBKDF2-SHA512 (600,000 iterations)"
echo "  • Config file: $CUSTOM_CFG"
echo "  • Backup: $BACKUP_DIR"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Store your password securely"
echo "  2. Test the configuration:"
echo "     - Reboot the system"
echo "     - Press 'e' in GRUB menu (should prompt for password)"
echo "     - Verify system boots correctly"
echo ""
echo -e "${RED}Recovery Instructions (if locked out):${NC}"
echo "  1. Boot from Live CD/USB"
echo "  2. Mount root partition: mount /dev/sdXn /mnt"
echo "  3. Remove password: rm /mnt$CUSTOM_CFG"
echo "  4. Update GRUB: chroot /mnt && $UPDATE_CMD"
echo "  5. Or restore backup from: $BACKUP_DIR"
echo ""
echo -e "${BLUE}CIS Compliance:${NC}"
echo "  ✓ CIS Control 1.4.1 implemented"
echo "  ✓ Boot parameters protected"
echo "  ✓ Unauthorized modifications prevented"
echo ""