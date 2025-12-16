# Usage Examples

This document provides practical examples for using the CIS Benchmark Automation Framework across different platforms.

## Table of Contents

1. [Platform Detection](#platform-detection)
2. [Registry Generation](#registry-generation)
3. [Linux Examples](#linux-examples)
4. [Windows Examples](#windows-examples)
5. [Android Examples](#android-examples)
6. [Multi-Platform Workflows](#multi-platform-workflows)

## Platform Detection

### Detect Current Platform

```bash
# Basic detection
python3 tools/platform_detector.py

# Output:
# Detected Platform:
# --------------------------------------------------------------------------------
#   Platform:     linux
#   Distribution: ubuntu
#   Variant:      desktop
#   Version:      22.04
#   Architecture: x86_64
#   Rules Path:   platforms/linux/ubuntu/desktop/rules
```

### List All Available Platforms

```bash
python3 tools/platform_detector.py --list

# Output:
# Available Platforms (6):
# --------------------------------------------------------------------------------
#   android    | android         | mobile     | 11
#   windows    | windows_server  | server     | 2022
#   windows    | windows11       | desktop    | 21H2
#   linux      | common          | all        | all
#   linux      | ubuntu          | desktop    | 20.04
#   linux      | ubuntu          | server     | 20.04 LTS
```

### Get Platform Info in JSON

```bash
python3 tools/platform_detector.py --json

# Output:
# {
#   "platform": "linux",
#   "distribution": "ubuntu",
#   "variant": "desktop",
#   "version": "22.04",
#   "architecture": "x86_64"
# }
```

## Registry Generation

### Auto-detect and Generate Registry

```bash
# Automatically detect platform and generate registry
python3 tools/build_registry.py --auto-detect
```

### Generate Registry for Specific Platform

```bash
# Ubuntu Desktop
python3 tools/build_registry.py --platform platforms/linux/ubuntu/desktop

# Windows 11
python3 tools/build_registry.py --platform platforms/windows/desktop/win11

# Android
python3 tools/build_registry.py --platform platforms/android
```

### Generate Registry for All Platforms

```bash
python3 tools/build_registry.py --all-platforms

# Output:
# [ALL PLATFORMS MODE] Scanning all platforms...
#
# Processing platform: platforms/linux/ubuntu/desktop
# Discovering rules in platforms/linux/ubuntu/desktop/rules...
# Found 308 rules
# [OK] Successfully generated platforms/linux/ubuntu/desktop/rules/index.json
# ...
```

### Legacy Mode (Backward Compatibility)

```bash
# Use old Rules/ directory
python3 tools/build_registry.py --rules-dir Rules
```

## Linux Examples

### Individual Rule Execution

```bash
# Navigate to Ubuntu Desktop rules
cd platforms/linux/ubuntu/desktop/rules/S1/1.5/1.5.1

# Run audit
sudo bash audit.sh

# Apply remediation if needed
sudo bash remediation.sh

# Verify fix
sudo bash audit.sh
```

### Generate Bash Script for Multiple Rules

```bash
# Create audit & remediation script for specific rules
python3 tools/compose_rule_scripts.py \
    --registry platforms/linux/ubuntu/desktop/rules/index.json \
    --output output/linux/ubuntu_hardening.sh \
    1.5.1 1.5.2 2.1.1 5.3.1.1

# Run the script
sudo bash output/linux/ubuntu_hardening.sh

# View report
firefox /tmp/cis_report_*/cis_report.html
```

### Generate Ansible Playbook

```bash
# Create playbook for SSH hardening
python3 tools/compose_ansible.py \
    --registry platforms/linux/ubuntu/desktop/rules/index.json \
    --output output/linux/ssh_hardening.yml \
    5.1.1 5.1.2 5.1.3 5.1.4 5.1.5

# Create inventory
cat > inventory.ini << EOF
[servers]
server1.example.com
server2.example.com

[servers:vars]
ansible_user=root
EOF

# Run playbook (check mode)
ansible-playbook output/linux/ssh_hardening.yml -i inventory.ini --check

# Run playbook (apply changes)
ansible-playbook output/linux/ssh_hardening.yml -i inventory.ini

# Run playbook (audit only)
ansible-playbook output/linux/ssh_hardening.yml -i inventory.ini \
    --extra-vars "cis_apply_remediation=false"
```

### All Rules in a Section

```bash
# Get all Section 1 rules
SECTION1_RULES=$(jq -r '.[] | select(.section == "Section 1 Initial Setup") | .id' \
    platforms/linux/ubuntu/desktop/rules/index.json)

# Create comprehensive Section 1 hardening script
python3 tools/compose_rule_scripts.py \
    --registry platforms/linux/ubuntu/desktop/rules/index.json \
    --output output/linux/section1_hardening.sh \
    $SECTION1_RULES
```

### Common Linux Rules (Distribution-Independent)

```bash
# Navigate to common rules
cd platforms/linux/common/rules

# These rules work across all Linux distributions
# Currently empty - ready for distribution-independent rules
```

## Windows Examples

### PowerShell Audit Script

```powershell
# Navigate to Windows 11 rules (when implemented)
cd platforms\windows\desktop\win11\rules\S1\1.1\1.1.1

# Run audit
.\audit.ps1

# Run with report generation
.\audit.ps1 -GenerateReport -ReportPath "C:\Reports"

# Apply remediation
.\remediation.ps1

# Verify
.\audit.ps1
```

### Group Policy Object (GPO) Backup

```powershell
# Backup current GPO before applying CIS hardening
Backup-GPO -All -Path "C:\GPO_Backups\Pre_CIS"

# Create system restore point
Checkpoint-Computer -Description "Before CIS Hardening" -RestorePointType MODIFY_SETTINGS
```

### Desired State Configuration (DSC)

```powershell
# Compile DSC configuration (when available)
.\platforms\windows\desktop\win11\dsc\CISBenchmark.ps1

# Apply configuration
Start-DscConfiguration -Path .\CISBenchmark -Wait -Verbose

# Test compliance
Test-DscConfiguration -Path .\CISBenchmark
```

## Android Examples

### ADB Connection

```bash
# Enable USB debugging on device first
# Settings > Developer Options > USB Debugging

# Connect device
adb devices

# Check connection
adb shell getprop ro.build.version.release
```

### Run Android Audit

```bash
# Navigate to Android platform
cd platforms/android

# Run audit template (when rules are implemented)
bash ../../templates/android/adb/audit_template.sh

# Or specific rule category
cd rules/device-security/screen-lock
bash audit.sh
```

### Common Android Checks

```bash
# Check screen lock timeout
adb shell settings get secure lock_screen_lock_after_timeout

# Check device encryption
adb shell getprop ro.crypto.state

# Disable unknown sources
adb shell settings put global install_non_market_apps 0

# Check Play Protect
adb shell settings get global package_verifier_enable
```

### MDM/EMM Deployment

For enterprise deployment, use MDM solutions like:
- Microsoft Intune
- Google Workspace
- VMware Workspace ONE

Example Intune policy export:
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All"

# Import CIS baseline profile
.\deploy_intune_profile.ps1 -ProfilePath ".\intune_profiles\cis_android_baseline.json"
```

## Multi-Platform Workflows

### Generate Reports for All Platforms

```bash
# Generate registries for all platforms
python3 tools/build_registry.py --all-platforms

# Create platform-specific reports
for platform in platforms/*/; do
    echo "Processing $platform"
    # Add your reporting logic here
done
```

### Inventory Management

```bash
# Create multi-platform inventory
cat > inventory.ini << EOF
[linux_servers]
ubuntu1.example.com ansible_platform=platforms/linux/ubuntu/server
debian1.example.com ansible_platform=platforms/linux/debian/server

[windows_servers]
win1.example.com ansible_platform=platforms/windows/server/2022
win2.example.com ansible_platform=platforms/windows/server/2019

[android_devices]
# Android devices managed via MDM
EOF
```

### CI/CD Integration

```yaml
# .github/workflows/cis-audit.yml
name: CIS Benchmark Audit

on:
  schedule:
    - cron: '0 2 * * 0'  # Weekly on Sunday at 2 AM
  push:
    branches: [main]

jobs:
  audit-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.x'

      - name: Generate Registry
        run: python3 tools/build_registry.py --platform platforms/linux/ubuntu/desktop

      - name: Run Audit
        run: |
          python3 tools/compose_rule_scripts.py \
            --registry platforms/linux/ubuntu/desktop/rules/index.json \
            --output audit_script.sh \
            1.5.1 1.5.2
          sudo bash audit_script.sh

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: cis-audit-report
          path: /tmp/cis_report_*/
```

### Docker Container Example

```dockerfile
# Dockerfile for CIS audit container
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    sudo \
    && rm -rf /var/lib/apt/lists/*

COPY . /opt/cis-benchmark
WORKDIR /opt/cis-benchmark

# Generate registry
RUN python3 tools/build_registry.py --platform platforms/linux/ubuntu/desktop

# Set entrypoint
ENTRYPOINT ["/bin/bash"]
```

Build and run:
```bash
docker build -t cis-audit .
docker run -it --rm cis-audit
```

### Terraform Integration

```hcl
# terraform/main.tf - Deploy CIS-hardened VM
resource "azurerm_linux_virtual_machine" "cis_hardened" {
  name                = "cis-hardened-vm"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  size                = "Standard_B2s"

  # Custom data - run CIS hardening on first boot
  custom_data = base64encode(templatefile("${path.module}/scripts/cis_bootstrap.sh", {
    rules = "1.5.1 1.5.2 2.1.1 5.3.1.1"
  }))

  # ... other configuration
}
```

## Troubleshooting

### Registry Generation Issues

```bash
# Check if rules directory exists
ls -la platforms/linux/ubuntu/desktop/rules/

# Verify rule structure
find platforms/linux/ubuntu/desktop/rules/ -name "audit.sh" | head -5

# Check for syntax errors
python3 -m py_compile tools/build_registry.py
```

### Permission Issues (Linux)

```bash
# Ensure scripts are executable
find platforms/linux/ubuntu/desktop/rules/ -name "*.sh" -exec chmod +x {} \;

# Check if running as root/sudo
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi
```

### Platform Detection Issues

```bash
# Check OS information
cat /etc/os-release  # Linux
systeminfo  # Windows
adb shell getprop ro.build.version.release  # Android

# Debug platform detector
python3 tools/platform_detector.py --json
```

## Best Practices

1. **Always test in non-production first**
2. **Backup before applying changes**
3. **Review generated scripts before execution**
4. **Use version control for custom rules**
5. **Schedule regular audits**
6. **Document any deviations from CIS benchmarks**
7. **Keep platform metadata updated**

## Additional Resources

- [Linux Platform Guide](platforms/linux.md)
- [Windows Platform Guide](platforms/windows.md)
- [Android Platform Guide](platforms/android.md)
- [Adding New Platforms](development/adding-new-platform.md)

---

For more examples, check the `samples/` directory in the repository.
