# CIS Benchmark Automation Framework

A comprehensive Linux security hardening automation framework based on CIS (Center for Internet Security) Benchmarks. This project provides automated audit and remediation scripts for securing Linux systems according to industry-standard security practices.

## Overview

This framework automates the implementation and verification of CIS Benchmark security controls for Linux systems. It provides a systematic approach to security hardening through automated audit checks and remediation scripts.

### Key Features

- **251 Automated Security Rules** across 7 major security categories
- **Automated Audit Scripts** for compliance verification
- **Automated Remediation Scripts** for security hardening
- **Ansible Automation** for centralized deployment and management
- **HTML Reporting** with before/after comparison
- **Modular Architecture** for flexible rule selection
- **Production-Ready** scripts tested on Linux systems

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
├── Rules/                          # Security rule implementations
│   ├── S1/                        # Section 1: Initial Setup
│   ├── S2/                        # Section 2: Services
│   ├── S3/                        # Section 3: Network
│   ├── S4/                        # Section 4: Host-Based Firewall
│   ├── S5/                        # Section 5: Access Control
│   ├── S6/                        # Section 6: Logging and Auditing
│   ├── S7/                        # Section 7: System Maintenance
│   └── index.json                 # Rule registry
├── tools/                          # Automation tools
│   ├── build_registry.py          # Generate rule registry
│   ├── compose_rule_scripts.py    # Compose bash audit/remediation scripts
│   └── compose_ansible.py         # Compose Ansible playbooks from selected rules
├── output/                         # Generated scripts and playbooks
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

- Linux system (Ubuntu/Debian or RHEL/CentOS)
- Python 3.6 or higher
- Root/sudo access for audit and remediation
- Bash shell

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sh-bitirme-proje.git
cd sh-bitirme-proje
```

2. Build the rule registry:
```bash
python3 tools/build_registry.py
```

### Usage

#### Option 1: Run Individual Rules

Execute a specific rule's audit:
```bash
cd Rules/S1/1.5/1.5.1
sudo ./audit.sh
```

Apply remediation if needed:
```bash
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

## Roadmap

- [x] Bash script automation (compose_rule_scripts.py)
- [x] Ansible playbook generation (compose_ansible.py)
- [x] Centralized multi-server deployment
- [ ] Additional Linux distribution support
- [ ] Compliance report export (PDF, JSON)
- [ ] Automated rollback capability
- [ ] Web-based management interface
- [ ] Docker container support

---

**Disclaimer**: This tool modifies system configurations. Always test in a non-production environment first. Review all changes before applying to production systems.
