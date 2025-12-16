# Adding a New Platform

This guide explains how to add support for a new operating system or platform to the CIS Benchmark Automation Framework.

## Overview

The framework is designed to be extensible. Adding a new platform involves:
1. Creating the directory structure
2. Adding platform metadata
3. Creating or porting security rules
4. Updating tools and documentation

## Step-by-Step Guide

### Step 1: Create Directory Structure

```bash
# Example: Adding FreeBSD support
mkdir -p platforms/bsd/freebsd/server/rules/{S1,S2,S3,S4,S5,S6,S7}
```

For a new platform family (e.g., macOS):
```bash
mkdir -p platforms/macos/desktop/ventura/rules
mkdir -p platforms/macos/desktop/sonoma/rules
mkdir -p platforms/macos/server/rules
```

### Step 2: Create metadata.json

Create `platforms/<platform>/<variant>/metadata.json`:

```json
{
  "platform": "bsd",
  "distribution": "freebsd",
  "variant": "server",
  "versions": ["13.2", "14.0"],
  "benchmark": "CIS FreeBSD Benchmark",
  "benchmark_version": "v1.0.0",
  "benchmark_level": ["Level 1", "Level 2"],
  "supported_automation": ["bash", "ansible"],
  "inherits_from": [],
  "description": "CIS Benchmark security hardening rules for FreeBSD",
  "maintainer": "Security Team",
  "last_updated": "2024-12-16",
  "notes": "Initial platform support"
}
```

### Step 3: Create Rule Structure

Each rule follows this structure:

```
platforms/<platform>/<variant>/rules/S1/1.1/1.1.1/
├── audit.sh           # or audit.ps1 for Windows
├── remediation.sh     # or remediation.ps1 for Windows
├── README.md          # Rule documentation
└── metadata.json      # Optional rule-specific metadata
```

#### Audit Script Example (audit.sh)

```bash
#!/usr/bin/env bash
#
# CIS Benchmark Rule 1.1.1
# Description: Check if some security feature is enabled
#
# Returns:
#   0 - PASS
#   1 - FAIL

# Your audit logic here
if some_check_command; then
    echo "PASS: Security feature is enabled"
    exit 0
else
    echo "FAIL: Security feature is not enabled"
    exit 1
fi
```

#### Remediation Script Example (remediation.sh)

```bash
#!/usr/bin/env bash
#
# CIS Benchmark Rule 1.1.1 Remediation
# Description: Enable security feature
#

echo "Enabling security feature..."

# Your remediation logic here
enable_security_feature_command

if [ $? -eq 0 ]; then
    echo "SUCCESS: Security feature enabled"
    exit 0
else
    echo "ERROR: Failed to enable security feature"
    exit 1
fi
```

#### Rule README Template

```markdown
# 1.1.1 - Enable Security Feature

## Profile Applicability
- Level 1 - Server
- Level 1 - Workstation

## Description
Detailed description of what this security control does.

## Rationale
Explanation of why this control is important for security.

## Audit
Steps to manually verify compliance:
1. Step one
2. Step two
3. Expected result

## Remediation
Steps to manually implement the control:
1. Step one
2. Step two
3. Verification step

## Impact
Potential impact on system functionality or applications.

## Default Value
What the default setting is on a fresh installation.

## References
- CIS Benchmark Section X.X.X
- Vendor documentation link
```

### Step 4: Update Platform Detector

Edit `tools/platform_detector.py` to add detection logic:

```python
def detect_bsd_variant() -> tuple[str, str, str]:
    """Detect BSD variant and version."""
    try:
        with open("/etc/os-release") as f:
            # Parse OS information
            pass
        return "freebsd", "server", "13.2"
    except FileNotFoundError:
        # Fallback detection
        return "unknown", "unknown", "unknown"

def detect_platform() -> PlatformInfo:
    """Detect the current platform."""
    system = platform.system().lower()

    if system == "freebsd":
        distro, variant, version = detect_bsd_variant()
        return PlatformInfo(
            platform="bsd",
            distribution=distro,
            variant=variant,
            version=version,
            architecture=platform.machine()
        )
    # ... existing code ...
```

### Step 5: Create Templates

Create platform-specific templates in `templates/<platform>/`:

#### Example: Ansible Template for BSD

```yaml
# templates/bsd/ansible/playbook_template.yml
---
- name: CIS Benchmark for FreeBSD
  hosts: all
  become: yes
  gather_facts: yes

  vars:
    cis_apply_remediation: true

  tasks:
    - name: Verify FreeBSD system
      assert:
        that:
          - ansible_os_family == "FreeBSD"
        fail_msg: "This playbook is for FreeBSD systems only"

    # Rule tasks will be inserted here
```

### Step 6: Add Common Rules (Optional)

If multiple variants share common rules, create:

```bash
mkdir -p platforms/<platform>/common/rules
```

Reference in metadata.json:
```json
{
  "inherits_from": ["platforms/<platform>/common"]
}
```

### Step 7: Generate Registry

```bash
# Generate index.json for your platform
python3 tools/build_registry.py --platform platforms/bsd/freebsd/server

# Or generate for all platforms
python3 tools/build_registry.py --all-platforms
```

### Step 8: Create Documentation

Create `docs/platforms/<platform>.md` with:
- Platform overview
- Supported versions
- Directory structure
- Usage examples
- Platform-specific notes
- Troubleshooting

### Step 9: Update Main README

Add your platform to the main README.md:

```markdown
## Supported Platforms

- **Linux**: Ubuntu, Debian, RHEL, CentOS, Arch, Fedora
- **Windows**: Windows 10, Windows 11, Server 2019, Server 2022
- **Android**: Android 11-14
- **BSD**: FreeBSD ← Add your platform
```

### Step 10: Test Your Platform

```bash
# Test platform detection
python3 tools/platform_detector.py

# Test registry generation
python3 tools/build_registry.py --platform platforms/bsd/freebsd/server

# Test individual rule
cd platforms/bsd/freebsd/server/rules/S1/1.1/1.1.1
sudo bash audit.sh
sudo bash remediation.sh
sudo bash audit.sh  # Verify remediation
```

## Platform-Specific Considerations

### Shell Scripts (Linux/BSD/Unix)

```bash
#!/usr/bin/env bash
set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi
```

### PowerShell Scripts (Windows)

```powershell
#Requires -Version 5.1
#Requires -RunAsAdministrator

# Error handling
$ErrorActionPreference = "Stop"

# Your code here
```

### ADB Scripts (Android)

```bash
#!/usr/bin/env bash

# Check for ADB
if ! command -v adb &> /dev/null; then
    echo "adb not found"
    exit 1
fi

# Check for device
if ! adb devices | grep -q "device$"; then
    echo "No device connected"
    exit 1
fi
```

## Best Practices

### 1. Consistent Rule Numbering
Follow CIS Benchmark section numbering:
- S1: Initial Setup / Account Policies
- S2: Services / Local Policies
- S3: Network Configuration
- S4: Firewall / Access Control
- S5: Access Control / Authentication
- S6: Logging and Auditing
- S7: System Maintenance

### 2. Error Handling

```bash
# Good error handling example
if ! command -v tool &> /dev/null; then
    echo "ERROR: Required tool not found"
    exit 1
fi

result=$(some_command 2>&1) || {
    echo "ERROR: Command failed: $result"
    exit 1
}
```

### 3. Idempotency
Ensure remediation scripts can be run multiple times safely:

```bash
# Check before changing
if [ ! -f /etc/security.conf ]; then
    echo "Creating security.conf"
    create_security_conf
else
    echo "security.conf already exists"
fi
```

### 4. Logging

```bash
LOG_FILE="/var/log/cis_audit.log"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "Starting audit..."
```

### 5. Testing

Create test cases:
```bash
# tests/test_rule_1_1_1.sh
source ../platforms/bsd/freebsd/server/rules/S1/1.1/1.1.1/audit.sh

test_audit_pass() {
    setup_pass_condition
    run_audit
    assert_exit_code 0
}

test_audit_fail() {
    setup_fail_condition
    run_audit
    assert_exit_code 1
}
```

## Submitting Your Platform

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/add-freebsd-support
   ```

3. **Commit your changes**
   ```bash
   git add platforms/bsd/
   git commit -m "Add FreeBSD platform support

   - Add FreeBSD directory structure
   - Implement CIS Benchmark rules for FreeBSD
   - Add platform detection
   - Add documentation
   "
   ```

4. **Test thoroughly**
   - Test on actual platform
   - Test all rules
   - Verify documentation

5. **Submit Pull Request**
   - Describe what you've added
   - Include test results
   - Reference any issues

## Example: Complete Rule Implementation

**platforms/bsd/freebsd/server/rules/S1/1.5/1.5.1/audit.sh:**
```bash
#!/usr/bin/env bash
# Rule 1.5.1: Ensure kernel module loading is disabled

if sysctl kern.module_path | grep -q "kernel"; then
    echo "PASS: Kernel module loading configured"
    exit 0
else
    echo "FAIL: Kernel module loading not properly configured"
    exit 1
fi
```

**platforms/bsd/freebsd/server/rules/S1/1.5/1.5.1/remediation.sh:**
```bash
#!/usr/bin/env bash
# Rule 1.5.1: Configure kernel module loading

echo 'kern.module_path="/boot/kernel"' >> /boot/loader.conf
echo "Kernel module path configured"
```

**platforms/bsd/freebsd/server/rules/S1/1.5/1.5.1/README.md:**
```markdown
# 1.5.1 - Ensure Kernel Module Loading is Disabled

## Profile Applicability
- Level 1 - Server

## Description
Restrict kernel module loading to prevent unauthorized kernel modifications.

## Rationale
Unrestricted kernel module loading can allow attackers to load malicious
kernel modules, compromising system security.

## Audit
Check kernel module path configuration:
```
sysctl kern.module_path
```

## Remediation
Configure kernel module path:
```
echo 'kern.module_path="/boot/kernel"' >> /boot/loader.conf
```

Reboot required for changes to take effect.
```

## Maintenance

After adding a platform:
1. **Keep benchmarks updated** - Monitor CIS for new versions
2. **Test on new OS versions** - Verify compatibility
3. **Update documentation** - Keep examples current
4. **Respond to issues** - Address user reports
5. **Improve rules** - Refine based on feedback

## Questions?

- Check existing platforms for examples
- Review documentation in `docs/`
- Open an issue for clarification
- Discuss in pull request

Happy contributing! 🚀
