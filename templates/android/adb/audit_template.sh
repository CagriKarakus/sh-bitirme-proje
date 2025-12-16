#!/usr/bin/env bash
# Android CIS Benchmark Audit Script Template
# Requires: adb (Android Debug Bridge)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASS_COUNT=0
FAIL_COUNT=0
DEVICE_ID=""

# Check if adb is installed
if ! command -v adb &> /dev/null; then
    echo -e "${RED}Error: adb command not found. Please install Android SDK Platform Tools.${NC}"
    exit 1
fi

# Check for connected devices
echo "Checking for connected Android devices..."
DEVICE_COUNT=$(adb devices | grep -v "List of devices" | grep -c "device$" || true)

if [ "$DEVICE_COUNT" -eq 0 ]; then
    echo -e "${RED}Error: No Android devices connected.${NC}"
    echo "Please connect a device and enable USB debugging."
    exit 1
elif [ "$DEVICE_COUNT" -gt 1 ]; then
    echo -e "${YELLOW}Warning: Multiple devices connected.${NC}"
    adb devices
    echo "Please specify device with: export ANDROID_SERIAL=<device_id>"
    exit 1
else
    DEVICE_ID=$(adb devices | grep "device$" | awk '{print $1}')
    echo -e "${GREEN}Connected to device: $DEVICE_ID${NC}"
fi

# Get device information
echo ""
echo "Device Information:"
echo "==================="
echo "Model: $(adb shell getprop ro.product.model)"
echo "Android Version: $(adb shell getprop ro.build.version.release)"
echo "API Level: $(adb shell getprop ro.build.version.sdk)"
echo "Security Patch: $(adb shell getprop ro.build.version.security_patch)"
echo ""

# Function to run audit check
audit_check() {
    local rule_id="$1"
    local title="$2"
    local command="$3"
    local expected="$4"

    echo -n "[$rule_id] $title ... "

    result=$(eval "$command" 2>/dev/null || echo "ERROR")

    if [[ "$result" == "$expected" ]] || [[ "$result" =~ $expected ]]; then
        echo -e "${GREEN}PASS${NC}"
        ((PASS_COUNT++))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        echo "  Expected: $expected"
        echo "  Got: $result"
        ((FAIL_COUNT++))
        return 1
    fi
}

# Function to check if app is installed
check_app_installed() {
    local package_name="$1"
    adb shell pm list packages | grep -q "package:$package_name"
}

# Function to check setting value
check_setting() {
    local namespace="$1"  # system, secure, or global
    local key="$2"
    adb shell settings get "$namespace" "$key" 2>/dev/null
}

# Start audit
echo "Starting CIS Benchmark Audit for Android"
echo "=========================================="
echo ""

# Example audit rules (these will be replaced by actual rules)

# Rule: Check screen lock timeout
audit_check "1.1.1" \
    "Screen lock timeout is configured" \
    "adb shell settings get secure lock_screen_lock_after_timeout" \
    "[0-9]+"

# Rule: Check if device encryption is enabled
audit_check "1.2.1" \
    "Device encryption is enabled" \
    "adb shell getprop ro.crypto.state" \
    "encrypted"

# Rule: Check if unknown sources is disabled
audit_check "2.1.1" \
    "Installation from unknown sources is disabled" \
    "adb shell settings get global install_non_market_apps" \
    "0"

# Rule: Check if ADB is disabled (will fail if checking via ADB)
echo "[INFO] ADB debugging status (should be disabled in production):"
adb shell getprop persist.sys.usb.config | grep -q "adb" && \
    echo -e "${YELLOW}  Warning: ADB is enabled${NC}" || \
    echo -e "${GREEN}  ADB is disabled${NC}"

# Rule: Check if device admin apps are present
echo ""
echo "Device Admin Apps:"
adb shell pm list packages -e | while read -r line; do
    package=$(echo "$line" | cut -d':' -f2)
    if adb shell dpm list-owners 2>/dev/null | grep -q "$package"; then
        echo "  - $package"
    fi
done

# Additional audit rules will be inserted here by compose script

# Summary
echo ""
echo "=========================================="
echo "AUDIT SUMMARY"
echo "=========================================="
echo -e "Total Checks: $((PASS_COUNT + FAIL_COUNT))"
echo -e "${GREEN}Passed: $PASS_COUNT${NC}"
echo -e "${RED}Failed: $FAIL_COUNT${NC}"
echo "=========================================="

# Exit with failure if any checks failed
[ "$FAIL_COUNT" -eq 0 ] && exit 0 || exit 1
