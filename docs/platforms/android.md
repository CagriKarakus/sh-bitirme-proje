# Android Platform Documentation

## Overview

This document describes Android platform support in the CIS Benchmark Automation Framework. The framework supports Android devices with security rules based on CIS Google Android Benchmark.

## Supported Versions

- **Android 14** (API Level 34)
- **Android 13** (API Level 33)
- **Android 12** (API Level 32/31)
- **Android 11** (API Level 30)

**Benchmark**: CIS Google Android Benchmark v1.0.0
**Location**: `platforms/android/`

## Directory Structure

```
platforms/android/
├── rules/
│   ├── device-security/      # Device-level security settings
│   ├── app-security/          # Application security policies
│   ├── network-security/      # Network and connectivity settings
│   └── index.json
└── metadata.json
```

## Rule Categories

### Device Security
- Screen lock configuration
- Device encryption
- Biometric authentication
- Device administrator settings
- Factory reset protection
- Secure boot verification

### Application Security
- App installation sources
- App permissions management
- Play Protect configuration
- Unknown sources blocking
- App verification settings
- Package verification

### Network Security
- Wi-Fi security settings
- Bluetooth configuration
- VPN requirements
- Mobile data restrictions
- Network location settings
- Certificate management

### Data Protection
- Storage encryption
- Secure file storage
- Backup configuration
- Cloud sync settings
- External storage controls

## Prerequisites

### Android Debug Bridge (ADB)

#### Installation

**Windows:**
```powershell
# Download Android SDK Platform Tools
# https://developer.android.com/studio/releases/platform-tools

# Extract and add to PATH
$env:PATH += ";C:\platform-tools"

# Verify installation
adb version
```

**Linux/macOS:**
```bash
# Ubuntu/Debian
sudo apt install android-tools-adb

# macOS with Homebrew
brew install android-platform-tools

# Verify installation
adb version
```

### Device Setup

1. Enable Developer Options:
   - Go to Settings → About phone
   - Tap "Build number" 7 times

2. Enable USB Debugging:
   - Go to Settings → System → Developer options
   - Enable "USB debugging"

3. Connect device:
   ```bash
   # Connect via USB
   adb devices

   # Connect via Wi-Fi (if supported)
   adb connect 192.168.1.100:5555
   ```

## Usage

### Device Connection

```bash
# List connected devices
adb devices

# Connect to specific device
export ANDROID_SERIAL=<device_id>

# Check device info
adb shell getprop ro.build.version.release  # Android version
adb shell getprop ro.build.version.sdk      # API level
```

### Run Audit

```bash
# Navigate to Android platform
cd platforms/android

# Run audit script
sudo bash templates/android/adb/audit_template.sh

# Run specific rule audit
cd rules/device-security/screen-lock
adb shell settings get secure lock_screen_lock_after_timeout
```

### Apply Remediation

```bash
# Run remediation script
sudo bash rules/device-security/screen-lock/remediation.sh

# Manual remediation example
adb shell settings put secure lock_screen_lock_after_timeout 5000
```

## Automation Methods

### Method 1: ADB Scripts

Direct ADB commands for testing and automation.

```bash
# Set screen lock timeout (5 seconds)
adb shell settings put secure lock_screen_lock_after_timeout 5000

# Disable installation from unknown sources
adb shell settings put global install_non_market_apps 0

# Enable device encryption (requires reboot)
adb shell sm set-virtual-disk true
```

### Method 2: MDM/EMM Solutions

Enterprise Mobile Management for organization-wide deployment.

**Supported Solutions:**
- Microsoft Intune
- Google Workspace (formerly G Suite)
- VMware Workspace ONE
- MobileIron
- BlackBerry UEM

**Example: Microsoft Intune**
```json
{
  "displayName": "CIS Android Baseline",
  "description": "CIS Benchmark compliance policy",
  "passwordRequired": true,
  "passwordMinimumLength": 8,
  "passwordRequiredType": "numeric",
  "deviceThreatProtectionEnabled": true,
  "securityRequireVerifyApps": true
}
```

### Method 3: Android Enterprise

Use Android Enterprise APIs for managed devices.

```bash
# Set device policy via ADB
adb shell dpm set-device-owner com.example.mdm/.AdminReceiver

# Apply password policy
adb shell dpm set-password-quality 131072  # PASSWORD_QUALITY_NUMERIC

# Set password length
adb shell dpm set-password-minimum-length 8
```

## Common Security Checks

### Screen Lock

```bash
# Check if screen lock is enabled
adb shell settings get secure lockscreen.disabled
# Expected: 0 (screen lock enabled)

# Check lock timeout
adb shell settings get secure lock_screen_lock_after_timeout
# Expected: <= 30000 (30 seconds or less)
```

### Device Encryption

```bash
# Check encryption status
adb shell getprop ro.crypto.state
# Expected: encrypted

# Check encryption type
adb shell getprop ro.crypto.type
# Expected: file (Android 10+) or block (Android 9 and below)
```

### App Verification

```bash
# Check if app verification is enabled
adb shell settings get global package_verifier_enable
# Expected: 1 (enabled)

# Check Play Protect status
adb shell settings get global package_verifier_user_consent
# Expected: 1 (enabled)
```

### Unknown Sources

```bash
# Check unknown sources setting (Android 7 and below)
adb shell settings get global install_non_market_apps
# Expected: 0 (disabled)

# Android 8+: Check per-app basis
adb shell appops get <package_name> REQUEST_INSTALL_PACKAGES
```

## Platform Detection

```bash
# Auto-detect Android device
python3 tools/platform_detector.py

# Get device information
python3 tools/platform_detector.py --json
```

## Generate Registry

```bash
# Generate index.json for Android rules
python3 tools/build_registry.py --platform platforms/android
```

## Testing

### Local Device Testing

```bash
# Run audit on connected device
cd platforms/android
bash ../../templates/android/adb/audit_template.sh

# Test specific rule
cd rules/device-security/encryption
bash audit.sh
```

### Emulator Testing

```bash
# Create Android emulator
avdmanager create avd -n test_device -k "system-images;android-33;google_apis;x86_64"

# Start emulator
emulator -avd test_device

# Run audit on emulator
adb -e shell settings list secure
```

## Creating Custom Rules

### Rule Structure

```
platforms/android/rules/category/rule-name/
├── audit.sh           # Audit script using adb commands
├── remediation.sh     # Remediation script
├── README.md          # Documentation
└── metadata.json      # Rule metadata
```

### Example Rule: Screen Lock Timeout

**audit.sh:**
```bash
#!/usr/bin/env bash

TIMEOUT=$(adb shell settings get secure lock_screen_lock_after_timeout)
MAX_TIMEOUT=30000  # 30 seconds

if [ "$TIMEOUT" -le "$MAX_TIMEOUT" ]; then
    echo "PASS: Screen lock timeout is $TIMEOUT ms (within limit)"
    exit 0
else
    echo "FAIL: Screen lock timeout is $TIMEOUT ms (exceeds $MAX_TIMEOUT ms)"
    exit 1
fi
```

**remediation.sh:**
```bash
#!/usr/bin/env bash

# Set screen lock timeout to 5 seconds
adb shell settings put secure lock_screen_lock_after_timeout 5000
echo "Screen lock timeout set to 5 seconds"
```

## Enterprise Deployment

### Prerequisites
- Android Enterprise enrolled devices
- MDM/EMM solution configured
- Device owner or profile owner mode

### Deployment Methods

1. **Zero-Touch Enrollment**
   - Pre-configure devices before distribution
   - Automatic policy application

2. **QR Code Provisioning**
   - Generate QR code with configuration
   - Scan during device setup

3. **NFC Provisioning**
   - Bump devices to transfer configuration

4. **DPC Identifier**
   - Enter identifier during setup
   - Download and apply policies

## Best Practices

1. **Test on Non-Production Devices**
   - Use test devices or emulators
   - Verify all functionality

2. **User Communication**
   - Inform users of security changes
   - Provide training on new policies

3. **Backup Before Changes**
   - Backup device data
   - Document current settings

4. **Gradual Rollout**
   - Test with pilot group
   - Monitor for issues
   - Expand to all devices

5. **Regular Audits**
   - Schedule compliance checks
   - Generate audit reports
   - Track remediation

## Limitations

### ADB Restrictions
- Requires USB debugging enabled
- Limited in production environments
- Some settings require root access

### MDM Advantages
- No USB debugging required
- Remote management
- Scalable to thousands of devices
- Better for production

### Android Versions
- Some settings vary by version
- API level compatibility
- OEM customizations

## Troubleshooting

### Device Not Detected

```bash
# Check ADB server
adb kill-server
adb start-server

# Check USB connection
adb devices
```

### Permission Denied

```bash
# Some commands require shell user
adb shell

# Or root access (for rooted devices)
adb root
adb shell
```

### Setting Not Persisting

```bash
# Some settings reset on reboot
# Use persistent methods:
# - MDM policies
# - Device owner policies
# - System app modifications
```

## References

- [CIS Google Android Benchmark](https://www.cisecurity.org/benchmark/google_android)
- [Android Debug Bridge (ADB)](https://developer.android.com/studio/command-line/adb)
- [Android Enterprise](https://www.android.com/enterprise/)
- [Android Security Documentation](https://source.android.com/security)
- [Mobile Device Management](https://developer.android.com/work/dpc)
