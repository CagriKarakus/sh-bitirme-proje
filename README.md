# CIS Benchmark Automation Framework

A comprehensive **multi-platform** security hardening automation framework based on CIS (Center for Internet Security) Benchmarks. This project provides automated audit and remediation scripts for securing systems across Linux, Windows, and Android platforms according to industry-standard security practices.

## Overview

This framework automates the implementation and verification of CIS Benchmark security controls for multiple operating systems and platforms. It provides a systematic approach to security hardening through automated audit checks and remediation scripts.

### Key Features

- **🌐 Multi-Platform Support** - Linux, Windows, Android (with plans for more)
- **251+ Automated Security Rules** across multiple platforms
- **Automated Audit Scripts** for compliance verification
- **Automated Remediation Scripts** for security hardening
- **Multiple Automation Methods** - Bash, Ansible, PowerShell, DSC, ADB
- **HTML Reporting** with before/after comparison
- **Modular Architecture** for flexible rule selection
- **Platform Auto-Detection** - automatically detect and apply correct rules
- **Scalable Structure** - easily add new platforms and distributions
- **Production-Ready** scripts tested on multiple platforms

## Supported Platforms

### 🐧 Linux
- **Ubuntu**: Desktop & Server (20.04, 22.04, 24.04 LTS)
- **Debian**: Desktop & Server (11, 12)
- **RHEL**: Server (8, 9)
- **CentOS**: Server (8, 9 Stream)
- **Arch Linux**: Desktop
- **Fedora**: Desktop
- **Common**: Distribution-independent rules

### 🪟 Windows
- **Windows 11**: 21H2, 22H2, 23H2
- **Windows 10**: 21H2, 22H2
- **Windows Server 2022**: Standard, Datacenter
- **Windows Server 2019**: Standard, Datacenter

### 📱 Android
- **Android 14** (API 34)
- **Android 13** (API 33)
- **Android 12** (API 32/31)
- **Android 11** (API 30)

### 🚀 Coming Soon
- macOS (Ventura, Sonoma)
- iOS
- Additional Linux distributions

## Implementation Progress

### CIS Benchmark Coverage

```
Total Rules Implemented: 251/251 (100%)
```

| Section | Category | Rules | Progress |
|---------|----------|-------|----------|
| **Section 1** | Initial Setup | 65 | ![100%](https://progress-bar.dev/100) |
| **Section 2** | Services | 42 | ![100%](https://progress-bar.dev/100) |
| **Section 3** | Network Configuration | 18 | ![100%](https://progress-bar.dev/100) |
| **Section 4** | Host-Based Firewall | 32 | ![100%](https://progress-bar.dev/100) |
| **Section 5** | Access Control | 71 | ![100%](https://progress-bar.dev/100) |
| **Section 6** | Logging and Auditing | 0 | ![100%](https://progress-bar.dev/0) |
| **Section 7** | System Maintenance | 23 | ![100%](https://progress-bar.dev/100) |

### Section Breakdown

#### Section 1: Initial Setup (65 rules)
- Filesystem configuration and security
- Software updates and package management
- Bootloader security
- Process hardening and security features
- Warning banners and access control

#### Section 2: Services (42 rules)
- Time synchronization
- System service hardening
- Service configuration security
- Unnecessary service removal

#### Section 3: Network Configuration (18 rules)
- Network parameter hardening
- IPv4/IPv6 security settings
- Wireless interface management
- Firewall prerequisites

#### Section 4: Host-Based Firewall (32 rules)
- UFW (Uncomplicated Firewall) configuration
- nftables configuration
- iptables configuration
- Firewall rule management

#### Section 5: Access Control (71 rules)
- SSH server hardening
- PAM (Pluggable Authentication Modules)
- User account security
- Password policies
- Login restrictions
- Sudo configuration

#### Section 6: Logging and Auditing (0 rules)
- System logging configuration
- Audit daemon setup
- Log rotation and retention
- Audit rules implementation
- *Currently under development*

#### Section 7: System Maintenance (23 rules)
- System file permissions
- /etc/passwd, /etc/shadow security
- /etc/group, /etc/gshadow security
- World writable files management
- SUID/SGID file review
- User and group settings
- Duplicate UID/GID detection
- Home directory configuration
- Dot files access control

## Project Structure

```
sh-bitirme-proje/
├── platforms/                      # Multi-platform support
│   ├── linux/
│   │   ├── ubuntu/
│   │   │   ├── desktop/rules/     # Ubuntu Desktop rules
│   │   │   └── server/rules/      # Ubuntu Server rules
│   │   ├── debian/
│   │   ├── rhel/
│   │   ├── centos/
│   │   └── common/rules/          # Common Linux rules
│   ├── windows/
│   │   ├── desktop/
│   │   │   ├── win11/rules/       # Windows 11 rules
│   │   │   └── win10/rules/       # Windows 10 rules
│   │   └── server/
│   │       ├── 2022/rules/        # Server 2022 rules
│   │       └── 2019/rules/        # Server 2019 rules
│   └── android/
│       └── rules/                 # Android rules
│           ├── device-security/
│           ├── app-security/
│           └── network-security/
├── Rules/                         # Legacy rules (backward compatibility)
│   ├── S1/                        # Section 1: Initial Setup
│   ├── S2/                        # Section 2: Services
│   ├── S3/                        # Section 3: Network
│   ├── S4/                        # Section 4: Host-Based Firewall
│   ├── S5/                        # Section 5: Access Control
│   ├── S6/                        # Section 6: Logging and Auditing
│   ├── S7/                        # Section 7: System Maintenance
│   └── index.json                 # Rule registry
├── tools/                          # Automation tools
│   ├── platform_detector.py       # Auto-detect current platform
│   ├── build_registry.py          # Generate rule registry (multi-platform aware)
│   ├── compose_rule_scripts.py    # Compose bash audit/remediation scripts
│   └── compose_ansible.py         # Compose Ansible playbooks from selected rules
├── templates/                      # Platform-specific templates
│   ├── linux/
│   │   ├── ansible/               # Ansible playbook templates
│   │   └── bash/                  # Bash script templates
│   ├── windows/
│   │   ├── powershell/            # PowerShell templates
│   │   └── dsc/                   # DSC templates
│   └── android/
│       └── adb/                   # ADB script templates
├── docs/                           # Documentation
│   ├── platforms/
│   │   ├── linux.md               # Linux platform guide
│   │   ├── windows.md             # Windows platform guide
│   │   └── android.md             # Android platform guide
│   └── development/
│       └── adding-new-platform.md # Guide for adding platforms
├── output/                         # Generated scripts and playbooks
│   ├── linux/
│   ├── windows/
│   └── android/
├── samples/                        # Sample configurations
└── LICENSE                         # MIT License
```

### Rule Structure

Each rule follows a consistent directory structure:

```
Rules/SX/X.X/X.X.X/
├── audit.sh           # Compliance verification script
├── remediation.sh     # Security hardening script
├── README.md          # Detailed documentation
└── metadata.json      # Rule metadata (optional)
```

## Quick Start

### Prerequisites

**General:**
- Python 3.6 or higher
- Git

**Linux:**
- Linux system (Ubuntu, Debian, RHEL, CentOS, etc.)
- Root/sudo access for audit and remediation
- Bash shell

**Windows:**
- PowerShell 5.1 or higher
- Administrator privileges
- .NET Framework 4.5+

**Android:**
- Android Debug Bridge (ADB)
- USB debugging enabled on device
- Or MDM/EMM solution for enterprise deployment

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sh-bitirme-proje.git
cd sh-bitirme-proje
```

2. Detect your platform (optional):
```bash
python3 tools/platform_detector.py
```

3. Build the rule registry:

**Auto-detect current platform:**
```bash
python3 tools/build_registry.py --auto-detect
```

**Or build for all platforms:**
```bash
python3 tools/build_registry.py --all-platforms
```

**Or build for specific platform:**
```bash
# Linux Ubuntu Desktop
python3 tools/build_registry.py --platform platforms/linux/ubuntu/desktop

# Windows 11
python3 tools/build_registry.py --platform platforms/windows/desktop/win11

# Android
python3 tools/build_registry.py --platform platforms/android
```

**Legacy mode (backward compatibility):**
```bash
python3 tools/build_registry.py --rules-dir Rules
```

### Usage

#### Option 1: Run Individual Rules

**Linux (Ubuntu Desktop):**
```bash
cd platforms/linux/ubuntu/desktop/rules/S1/1.5/1.5.1
sudo ./audit.sh
sudo ./remediation.sh  # if needed
```

**Windows (PowerShell):**
```powershell
cd platforms\windows\desktop\win11\rules\S1\1.1\1.1.1
.\audit.ps1
.\remediation.ps1  # if needed
```

**Android (via ADB):**
```bash
cd platforms/android/rules/device-security/screen-lock
bash audit.sh
bash remediation.sh  # if needed
```

**Legacy (backward compatibility):**
```bash
cd Rules/S1/1.5/1.5.1
sudo ./audit.sh
sudo ./remediation.sh
```

#### Option 2: Automated Batch Execution

Generate a combined audit and remediation script:

```bash
# Create script for specific rules
python3 tools/compose_rule_scripts.py \
    --registry Rules/index.json \
    --output output/cis_audit.sh \
    1.5.1 1.5.2 1.5.3 2.1.1 2.1.2

# Or run all rules in a section
python3 tools/compose_rule_scripts.py \
    --registry Rules/index.json \
    --output output/section1_audit.sh \
    $(jq -r '.[] | select(.section == "Section 1 Initial Setup") | .id' Rules/index.json)
```

Run the generated script:
```bash
sudo bash output/cis_audit.sh
```

The script will:
1. Run initial audit (BEFORE state)
2. Apply remediation for failed rules
3. Run final audit (AFTER state)
4. Generate HTML report with comparison

#### Option 3: Ansible Automation (Recommended for Multiple Servers)

Create a custom Ansible playbook with only the rules you want:

```bash
# Create playbook for specific rules
python3 tools/compose_ansible.py 1.5.1 1.5.2 2.1.1 5.1.1 \
    --output output/my_custom_hardening.yml

# Create simple inventory file
cat > inventory.ini << EOF
[servers]
server1.example.com
server2.example.com

[servers:vars]
ansible_user=root
EOF

# Run the custom playbook
ansible-playbook output/my_custom_hardening.yml -i inventory.ini

# Dry-run (check mode)
ansible-playbook output/my_custom_hardening.yml -i inventory.ini --check

# Audit only (no remediation)
ansible-playbook output/my_custom_hardening.yml -i inventory.ini \
    --extra-vars "cis_apply_remediation=false"
```

**Common Use Cases:**
```bash
# SSH hardening
python3 tools/compose_ansible.py 5.1.1 5.1.2 5.1.3 5.1.4 5.1.5 \
    --output output/ssh_hardening.yml

# Filesystem security
python3 tools/compose_ansible.py 1.1.1.1 1.1.1.2 1.1.1.3 1.1.1.4 \
    --output output/filesystem.yml

# Basic system hardening
python3 tools/compose_ansible.py 1.5.1 2.1.1 3.1.1 5.1.1 \
    --output output/basic_hardening.yml
```

#### Option 4: View HTML Report

After execution, open the generated report:
```bash
# Report is generated in /tmp/cis_report_TIMESTAMP/
firefox /tmp/cis_report_*/cis_report.html
```

## Tools

### build_registry.py

Scans the Rules directory and generates `index.json` registry:

```bash
python3 tools/build_registry.py \
    --rules-dir Rules \
    --output Rules/index.json
```

**Features:**
- Automatic rule discovery
- Natural sorting of rule IDs
- Metadata extraction
- Section categorization

### compose_rule_scripts.py

Combines multiple rules into a single executable script:

```bash
python3 tools/compose_rule_scripts.py [rule_ids...] \
    --registry Rules/index.json \
    --output output/script.sh
```

**Features:**
- Modular rule selection
- Before/after audit comparison
- Automated remediation workflow
- HTML report generation
- Color-coded console output

### compose_ansible.py

Creates a custom Ansible playbook from selected rules:

```bash
python3 tools/compose_ansible.py [rule_ids...] \
    --registry Rules/index.json \
    --output output/custom.yml
```

**Features:**
- Select only the rules you want to apply
- Generates a single, self-contained playbook
- Perfect for centralized multi-server deployment
- Easy to customize and version control
- No complex role structure needed

**Examples:**
```bash
# Specific rules
python3 tools/compose_ansible.py 1.5.1 1.5.2 2.1.1 \
    --output output/custom.yml

# All filesystem rules
python3 tools/compose_ansible.py 1.1.1.1 1.1.1.2 1.1.1.3 1.1.1.4 \
    --output output/filesystem.yml

# SSH hardening only
python3 tools/compose_ansible.py 5.1.1 5.1.2 5.1.3 5.1.4 \
    --output output/ssh_hardening.yml

# Run the playbook
ansible-playbook output/ssh_hardening.yml -i inventory.ini
```

## Rule Documentation

Each rule includes comprehensive documentation:

- **Profile Applicability**: Target system types (Server/Workstation, Level 1/2)
- **Description**: Detailed explanation of the security control
- **Rationale**: Security justification and threat mitigation
- **Audit Instructions**: How to verify compliance
- **Remediation Steps**: How to implement the control
- **Default Values**: OS distribution defaults
- **CIS Controls Mapping**: Alignment with CIS Controls framework
- **MITRE ATT&CK Mapping**: Related attack techniques and mitigations

Example: [1.5.1 - Address Space Layout Randomization](Rules/S1/1.5/1.5.1/README.md)

## Development

### Adding New Rules

1. Create rule directory structure:
```bash
mkdir -p Rules/SX/X.X/X.X.X
```

2. Create audit script:
```bash
# Rules/SX/X.X/X.X.X/audit.sh
#!/usr/bin/env bash
# Audit logic here
# exit 0 = PASS, exit 1 = FAIL
```

3. Create remediation script:
```bash
# Rules/SX/X.X/X.X.X/remediation.sh
#!/usr/bin/env bash
# Remediation logic here
```

4. Rebuild registry:
```bash
python3 tools/build_registry.py
```

### Testing

Test individual rules:
```bash
# Run audit
sudo bash Rules/S1/1.5/1.5.1/audit.sh
echo $?  # Should be 0 (PASS) or 1 (FAIL)

# Run remediation
sudo bash Rules/S1/1.5/1.5.1/remediation.sh

# Verify remediation
sudo bash Rules/S1/1.5/1.5.1/audit.sh
```

## Security Considerations

- **Always test in non-production environment first**
- Review remediation scripts before execution
- Backup system configuration before applying changes
- Some remediations may require system reboot
- Certain rules may impact system functionality
- Review organizational security policies before implementation

## CIS Benchmark Reference

This framework implements controls from:
- **CIS Ubuntu Linux Benchmark**
- **CIS Red Hat Enterprise Linux Benchmark**
- **CIS Debian Linux Benchmark**

Benchmark levels:
- **Level 1**: Basic security hardening (recommended for all systems)
- **Level 2**: Advanced security hardening (may impact functionality)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Follow the existing rule structure
4. Test thoroughly on multiple distributions
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Center for Internet Security (CIS) for benchmark standards
- Linux security community for best practices
- Contributors and testers

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Review existing documentation in rule READMEs
- Check the [ProjeYazılari](ProjeYazılari/) directory for additional documentation

## Platform-Specific Documentation

For detailed platform-specific information:
- 📖 [Linux Platform Guide](docs/platforms/linux.md)
- 📖 [Windows Platform Guide](docs/platforms/windows.md)
- 📖 [Android Platform Guide](docs/platforms/android.md)
- 📖 [Adding New Platforms](docs/development/adding-new-platform.md)

## Roadmap

### Completed ✅
- [x] Multi-platform architecture
- [x] Linux support (Ubuntu, Debian, RHEL, CentOS)
- [x] Windows support (Desktop & Server)
- [x] Android support
- [x] Platform auto-detection
- [x] Bash script automation
- [x] Ansible playbook generation
- [x] PowerShell script support
- [x] Centralized multi-server deployment

### In Progress 🚧
- [ ] Complete all Windows CIS rules
- [ ] Complete all Android CIS rules
- [ ] Enhanced reporting (PDF, JSON export)
- [ ] Web-based management interface

### Planned 🎯
- [ ] macOS support (Ventura, Sonoma)
- [ ] iOS support
- [ ] FreeBSD support
- [ ] Docker container support
- [ ] Automated rollback capability
- [ ] Kubernetes deployment
- [ ] REST API for automation
- [ ] Integration with SIEM systems

---

**Disclaimer**: This tool modifies system configurations. Always test in a non-production environment first. Review all changes before applying to production systems.
