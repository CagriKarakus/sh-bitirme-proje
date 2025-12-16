# Linux Platform Documentation

## Overview

This document describes the Linux platform support in the CIS Benchmark Automation Framework. The framework supports multiple Linux distributions with distribution-specific and common security rules.

## Supported Distributions

### Ubuntu
- **Variants**: Desktop, Server
- **Versions**: 20.04 LTS, 22.04 LTS, 24.04 LTS
- **Benchmark**: CIS Ubuntu Linux Benchmark v2.0.0
- **Location**: `platforms/linux/ubuntu/`

### Debian
- **Variants**: Desktop, Server
- **Versions**: 11 (Bullseye), 12 (Bookworm)
- **Benchmark**: CIS Debian Linux Benchmark v2.0.0
- **Location**: `platforms/linux/debian/`

### RHEL (Red Hat Enterprise Linux)
- **Variants**: Server
- **Versions**: 8, 9
- **Benchmark**: CIS Red Hat Enterprise Linux Benchmark v3.0.0
- **Location**: `platforms/linux/rhel/`

### CentOS
- **Variants**: Server
- **Versions**: 8, 9 (Stream)
- **Benchmark**: CIS CentOS Linux Benchmark v3.0.0
- **Location**: `platforms/linux/centos/`

## Directory Structure

```
platforms/linux/
├── ubuntu/
│   ├── desktop/
│   │   ├── rules/
│   │   │   ├── S1/    # Initial Setup
│   │   │   ├── S2/    # Services
│   │   │   ├── S3/    # Network Configuration
│   │   │   ├── S4/    # Host-Based Firewall
│   │   │   ├── S5/    # Access Control
│   │   │   ├── S6/    # Logging and Auditing
│   │   │   ├── S7/    # System Maintenance
│   │   │   └── index.json
│   │   └── metadata.json
│   └── server/
│       ├── rules/
│       └── metadata.json
├── debian/
├── rhel/
├── centos/
└── common/
    └── rules/    # Distribution-independent rules
```

## Rule Categories

### Section 1: Initial Setup
- Filesystem configuration and security
- Software updates and package management
- Bootloader security (GRUB)
- Process hardening (ASLR, kernel parameters)
- Warning banners and access control

### Section 2: Services
- Time synchronization (systemd-timesyncd, chrony)
- System service hardening
- Service configuration security
- Unnecessary service removal

### Section 3: Network Configuration
- Network parameter hardening
- IPv4/IPv6 security settings
- Wireless interface management
- Firewall prerequisites

### Section 4: Host-Based Firewall
- UFW (Uncomplicated Firewall) configuration
- nftables configuration
- iptables configuration
- Firewall rule management

### Section 5: Access Control
- SSH server hardening
- PAM (Pluggable Authentication Modules)
- User account security
- Password policies
- Login restrictions
- Sudo configuration

### Section 6: Logging and Auditing
- System logging configuration (rsyslog, journald)
- Audit daemon setup (auditd)
- Log rotation and retention
- Audit rules implementation

### Section 7: System Maintenance
- System file permissions
- User and group file security
- World writable files management
- SUID/SGID file review

## Usage

### Generate Registry for Ubuntu Desktop

```bash
python3 tools/build_registry.py --platform platforms/linux/ubuntu/desktop
```

### Generate Registry for All Linux Platforms

```bash
python3 tools/build_registry.py --all-platforms
```

### Auto-detect Current Platform

```bash
python3 tools/build_registry.py --auto-detect
```

### Run Audit on Ubuntu

```bash
cd platforms/linux/ubuntu/desktop/rules/S1/1.5/1.5.1
sudo ./audit.sh
```

### Apply Remediation

```bash
cd platforms/linux/ubuntu/desktop/rules/S1/1.5/1.5.1
sudo ./remediation.sh
```

### Generate Ansible Playbook

```bash
python3 tools/compose_ansible.py \
    --registry platforms/linux/ubuntu/desktop/rules/index.json \
    --output output/linux/ubuntu_hardening.yml \
    1.5.1 1.5.2 2.1.1 5.1.1
```

## Platform Detection

The framework includes automatic platform detection:

```bash
# Detect current platform
python3 tools/platform_detector.py

# Get rules path for current platform
python3 tools/platform_detector.py --rules-path

# List all available platforms
python3 tools/platform_detector.py --list
```

## Common Rules

Rules in `platforms/linux/common/` are distribution-independent and can be inherited by any Linux distribution. These include:

- Basic filesystem security
- Core network hardening
- Universal SSH settings
- Standard PAM configurations

## Adding a New Distribution

1. Create directory structure:
   ```bash
   mkdir -p platforms/linux/newdistro/{desktop,server}/rules
   ```

2. Create metadata.json:
   ```json
   {
     "platform": "linux",
     "distribution": "newdistro",
     "variant": "desktop",
     "versions": ["1.0"],
     "benchmark": "CIS New Distro Benchmark",
     "inherits_from": ["platforms/linux/common"]
   }
   ```

3. Add distribution-specific rules or link to common rules

4. Generate registry:
   ```bash
   python3 tools/build_registry.py --platform platforms/linux/newdistro/desktop
   ```

## Testing

### Test on Local System

```bash
# Run single rule audit
sudo bash platforms/linux/ubuntu/desktop/rules/S1/1.5/1.5.1/audit.sh

# Run remediation
sudo bash platforms/linux/ubuntu/desktop/rules/S1/1.5/1.5.1/remediation.sh

# Verify remediation
sudo bash platforms/linux/ubuntu/desktop/rules/S1/1.5/1.5.1/audit.sh
```

### Test with Ansible

```bash
# Check mode (dry run)
ansible-playbook output/linux/ubuntu_hardening.yml -i inventory.ini --check

# Run on test systems
ansible-playbook output/linux/ubuntu_hardening.yml -i inventory.ini
```

## Best Practices

1. **Always test in non-production first**
2. **Review rules before applying**
3. **Backup system configuration**
4. **Use version control for custom rules**
5. **Document any customizations**
6. **Schedule regular compliance audits**

## Troubleshooting

### Registry Generation Fails

```bash
# Check if rules directory exists
ls -la platforms/linux/ubuntu/desktop/rules/

# Verify script structure
find platforms/linux/ubuntu/desktop/rules/ -name "audit.sh" | head -5
```

### Rule Execution Fails

```bash
# Check script permissions
chmod +x platforms/linux/ubuntu/desktop/rules/S1/1.5/1.5.1/*.sh

# Run with verbose output
bash -x platforms/linux/ubuntu/desktop/rules/S1/1.5/1.5.1/audit.sh
```

### Platform Not Detected

```bash
# Manually check OS info
cat /etc/os-release

# Check detection script
python3 tools/platform_detector.py --json
```

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Ubuntu Security Guide](https://ubuntu.com/security)
- [RHEL Security Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/index)
