# CIS Benchmark Automation Framework

A comprehensive **multi-platform** security hardening automation framework based on CIS (Center for Internet Security) Benchmarks. This project provides automated audit and remediation scripts for securing systems across Linux, Windows, and Android platforms according to industry-standard security practices.

## Overview

This framework automates the implementation and verification of CIS Benchmark security controls for multiple operating systems. It provides a systematic approach to security hardening through a **modern web interface (React/FastAPI)**, automated audit checks, and versatile artifact generation.

### Key Features

- **🌐 Multi-Platform Support** - Linux, Windows, Android (with plans for more)
- **🖥️ Web-Based Management Interface** - React frontend with FastAPI backend for easy rule selection and execution
- **📦 Multi-Format Artifact Generation** - Generate Ansible playbooks, Bash scripts, PowerShell scripts, and GPO backup files (`.zip`)
- **Automated Audit & Remediation Scripts** for compliance verification and security hardening
- **JSON-based Rule Definitions** for Windows enabling easier maintainability
- **HTML Reporting** with before/after comparison
- **Modular Architecture** for flexible rule selection
- **Platform Auto-Detection** - automatically detect and apply correct rules
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

The project is currently tracking progress across multiple platforms, with a focus on comprehensive Windows and Linux coverage.
*See `CLAUDE.md` for specific rule definition structures.*

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
│   │   └── common/rules/          # Common Linux rules
│   ├── windows/
│   │   ├── rules/                 # Windows JSON rule definitions
│   │   │   ├── S1_Account_Policies/
│   │   │   ├── S2_Local_Policies/
│   │   │   ├── S5_System_Services/
│   │   │   └── S18_Administrative_Templates/
│   │   └── tools/                 # PowerShell Generators (GPO/Script)
│   └── android/
│       └── rules/                 # Android rules
├── web/                            # Web-based Management Interface
│   ├── backend/                    # FastAPI Application
│   │   ├── routers/                # API Endpoints
│   │   ├── services/               # Rule Loading & Artifact Generation
│   │   └── main.py                 # App Entry Point
│   └── frontend/                   # React + TypeScript Frontend
│       ├── src/components/         # UI Components
│       ├── src/pages/              # Views
│       └── src/services/           # API Client
├── Tools/                          # Python CLI tools
├── docs/                           # Documentation
│   └── WINDOWS_HARDENING_ARCHITECTURE.md # Windows Architecture Specs
├── output/                         # Generated custom scripts and playbooks
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

### Running the Web Platform (Recommended)

The Web Platform provides the easiest way to browse rules, resolve dependencies, and generate artifact scripts/playbooks for target environments.

**Backend (FastAPI):**
```bash
cd web/backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Frontend (React/Vite):**
```bash
cd web/frontend
npm install
npm run dev        # Starts Vite server on :5173
```

#### Option 1: Web Platform Generation (Recommended)

1. Open the Web Platform in your browser (`http://localhost:5173`).
2. Navigate to the Rules section for your desired OS.
3. Select the rules you want to apply.
4. Click "Generate Artifact".
5. Choose your desired output format:
   - **Windows:** PowerShell script (`.ps1`) or GPO Backup (`.zip`)
   - **Linux:** Ansible Playbook (`.yml`) or Bash script (`.sh`)
6. Download the generated artifact and apply it to your target machine.

#### Option 2: Run Individual Rules (CLI)

You can still run individual rules manually if needed.

**Linux (Ubuntu):**
```bash
cd platforms/linux/ubuntu/server/rules/S1/1.5/1.5.1
sudo ./audit.sh
sudo ./remediation.sh  # if needed
```

**Windows (PowerShell):**
Some rules have raw PowerShell scripts, though generation via the web app is highly recommended.
```powershell
# Requires Administrator
cd platforms\windows\rules\S1_Account_Policies\
# (Note: Windows rules are primarily defined in JSON and executed via generated artifacts)
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

## Architecture & Documentation

### Web Platform Architecture
- **Backend**: FastAPI serves the REST API, validating rule selections and resolving dependencies (`web/backend/services/resolver.py`).
- **Generators**: Artifact generation logic invokes Python/PowerShell scripts under the hood to compile the selected JSON/Bash rules into deployable formats.
- **Frontend**: React application for easy browsing of the CIS rules.

### Rule Documentation

Each rule directory (Linux) or JSON file (Windows) includes comprehensive metadata:

- **Profile Applicability**: Target system types (Server/Workstation, Level 1/2)
- **Description**: Detailed explanation of the security control
- **Rationale**: Security justification and threat mitigation
- **Audit/Remediation Logic**: How to verify and implement the control

Example: [Windows Architecture Guide](docs/WINDOWS_HARDENING_ARCHITECTURE.md)

## Development

### Adding New Rules

**Windows:**
Use the included workflow to generate a new Windows CIS rule definition in the appropriate JSON format:
```bash
# Discuss with the assistant or use the workflow
/windows-hardening-rule
```

**Linux:**
1. Create rule directory structure:
```bash
mkdir -p platforms/linux/ubuntu/server/rules/SX/X.X/X.X.X
```

2. Create `audit.sh` and `remediation.sh` scripts under the new directory.
3. Reload rules starting the Web Platform or backend server.

### Testing

**Web Platform / API:**
```bash
cd web/backend
pytest
```

**Individual Rule Scripts (Linux Example):**
```bash
# Run audit
sudo bash platforms/linux/ubuntu/server/rules/S1/1.5/1.5.1/audit.sh
echo $?  # Should be 0 (PASS) or 1 (FAIL)

# Run remediation
sudo bash platforms/linux/ubuntu/server/rules/S1/1.5/1.5.1/remediation.sh
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
- [ ] Docker container support
- [ ] Automated rollback capability
- [ ] Kubernetes deployment
- [ ] REST API for automation
- [ ] Integration with SIEM systems

---

**Disclaimer**: This tool modifies system configurations. Always test in a non-production environment first. Review all changes before applying to production systems.
