# Windows Platform Documentation

## Overview

This document describes Windows platform support in the CIS Benchmark Automation Framework. The framework supports Windows Desktop and Windows Server editions with version-specific security rules.

## Supported Versions

### Windows Desktop
- **Windows 11**: 21H2, 22H2, 23H2
- **Windows 10**: 21H2, 22H2
- **Benchmark**: CIS Microsoft Windows 11/10 Enterprise Benchmark v2.0.0
- **Location**: `platforms/windows/desktop/`

### Windows Server
- **Windows Server 2022**: Standard, Datacenter
- **Windows Server 2019**: Standard, Datacenter
- **Benchmark**: CIS Microsoft Windows Server 2022/2019 Benchmark v2.0.0
- **Location**: `platforms/windows/server/`

## Directory Structure

```
platforms/windows/
├── desktop/
│   ├── win11/
│   │   ├── rules/
│   │   │   ├── S1/    # Account Policies
│   │   │   ├── S2/    # Local Policies
│   │   │   ├── S3/    # Event Log
│   │   │   ├── S4/    # System Services
│   │   │   ├── S5/    # Windows Firewall
│   │   │   └── index.json
│   │   └── metadata.json
│   └── win10/
│       ├── rules/
│       └── metadata.json
└── server/
    ├── 2022/
    │   ├── rules/
    │   └── metadata.json
    ├── 2019/
    │   ├── rules/
    │   └── metadata.json
    └── common/
        └── rules/    # Common server rules
```

## Rule Categories

### Section 1: Account Policies
- Password Policy
- Account Lockout Policy
- Kerberos Policy

### Section 2: Local Policies
- Audit Policy
- User Rights Assignment
- Security Options

### Section 3: Event Log
- Application Log configuration
- Security Log configuration
- System Log configuration

### Section 4: System Services
- Service hardening
- Unnecessary service disabling
- Service permissions

### Section 5: Windows Firewall
- Domain Profile settings
- Private Profile settings
- Public Profile settings
- Firewall rules management

### Section 6: Advanced Audit Policy
- Account Logon
- Account Management
- Detailed Tracking
- Logon/Logoff events
- Object Access
- Policy Change
- Privilege Use
- System events

### Section 7: Windows Defender
- Real-time Protection
- Cloud-delivered Protection
- Network Protection
- Exploit Protection

## Prerequisites

### PowerShell Requirements
- PowerShell 5.1 or higher
- Administrator privileges
- Execution policy: RemoteSigned or Unrestricted

```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Set execution policy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Required Modules
```powershell
# Install required modules
Install-Module -Name Microsoft.PowerShell.LocalAccounts
Install-Module -Name Microsoft.PowerShell.Security
```

## Usage

### Generate Registry for Windows 11

```powershell
python tools/build_registry.py --platform platforms/windows/desktop/win11
```

### Run Audit Script

```powershell
# Navigate to platform directory
cd platforms/windows/desktop/win11/rules

# Run audit
.\audit.ps1 -GenerateReport -ReportPath "C:\Reports"
```

### Apply Remediation

```powershell
# Run remediation script
.\remediation.ps1 -Confirm:$false

# Or with confirmation prompts
.\remediation.ps1
```

### Generate Group Policy Report

```powershell
# Export current GPO settings
gpresult /H C:\Reports\current_gpo.html

# Compare with CIS recommendations
.\compare_gpo.ps1 -BaselineFile "cis_baseline.xml" -CurrentGPO "C:\Reports\current_gpo.html"
```

## Automation Methods

### Method 1: PowerShell Scripts

Direct execution of PowerShell audit and remediation scripts.

```powershell
# Run audit
.\platforms\windows\desktop\win11\rules\audit.ps1

# Apply remediation
.\platforms\windows\desktop\win11\rules\remediation.ps1
```

### Method 2: Desired State Configuration (DSC)

Use DSC for configuration management.

```powershell
# Compile MOF file
.\platforms\windows\desktop\win11\dsc\CISBenchmark.ps1

# Apply configuration
Start-DscConfiguration -Path .\CISBenchmark -Wait -Verbose
```

### Method 3: Group Policy Objects (GPO)

Import CIS Benchmark GPO templates.

```powershell
# Import GPO backup
Import-GPO -BackupId "{GUID}" -Path ".\gpo_backups" -TargetName "CIS Benchmark"

# Link to OU
New-GPLink -Name "CIS Benchmark" -Target "OU=Computers,DC=domain,DC=com"
```

### Method 4: Microsoft Intune

Deploy configuration profiles via Intune for cloud-managed devices.

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All"

# Import configuration profile
.\deploy_intune_profile.ps1 -ProfilePath ".\intune_profiles\cis_baseline.json"
```

## Platform Detection

```powershell
# Detect Windows version
python tools/platform_detector.py

# Output in JSON
python tools/platform_detector.py --json

# Get rules path
python tools/platform_detector.py --rules-path
```

## Common Rules

Rules in `platforms/windows/server/common/` apply to all Windows Server versions:

- Core security policies
- Base service configurations
- Common firewall rules
- Standard audit policies

## Adding a New Windows Version

1. Create directory structure:
   ```powershell
   New-Item -ItemType Directory -Path "platforms/windows/desktop/win12/rules"
   ```

2. Create metadata.json:
   ```json
   {
     "platform": "windows",
     "distribution": "windows12",
     "variant": "desktop",
     "versions": ["12"],
     "benchmark": "CIS Microsoft Windows 12 Benchmark",
     "supported_automation": ["powershell", "dsc", "intune"]
   }
   ```

3. Add version-specific rules

4. Generate registry:
   ```powershell
   python tools/build_registry.py --platform platforms/windows/desktop/win12
   ```

## Testing

### Test on Local System

```powershell
# Run audit in test mode
.\audit.ps1 -WhatIf

# Run single rule
.\platforms\windows\desktop\win11\rules\S1\1.1\1.1.1\audit.ps1

# Apply remediation
.\platforms\windows\desktop\win11\rules\S1\1.1\1.1.1\remediation.ps1
```

### Test with DSC

```powershell
# Test configuration
Test-DscConfiguration -Path .\CISBenchmark

# Get current configuration
Get-DscConfiguration
```

## Registry Settings

Many CIS Benchmark rules involve registry modifications. Example structure:

```powershell
# Audit registry key
function Test-RegistryValue {
    param($Path, $Name, $ExpectedValue)

    $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    return ($value.$Name -eq $ExpectedValue)
}

# Remediate registry key
function Set-RegistryValue {
    param($Path, $Name, $Value, $Type = "DWORD")

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}
```

## Security Policy Settings

Use `secedit` for security policy configuration:

```powershell
# Export current security policy
secedit /export /cfg C:\secpol.cfg

# Import CIS security template
secedit /configure /db secedit.sdb /cfg cis_template.inf /overwrite

# Validate policy
secedit /analyze /db secedit.sdb /cfg cis_template.inf /log analysis.log
```

## Best Practices

1. **Create System Restore Point**
   ```powershell
   Checkpoint-Computer -Description "Before CIS Hardening" -RestorePointType MODIFY_SETTINGS
   ```

2. **Backup Group Policy**
   ```powershell
   Backup-GPO -All -Path "C:\GPO_Backups"
   ```

3. **Document Changes**
   - Keep audit logs
   - Track remediation actions
   - Record any custom modifications

4. **Test in Non-Production First**
   - Use virtual machines
   - Test all functionality
   - Verify application compatibility

5. **Schedule Regular Audits**
   ```powershell
   # Create scheduled task for audits
   $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\audit.ps1"
   $trigger = New-ScheduledTaskTrigger -Weekly -At 2am -DaysOfWeek Sunday
   Register-ScheduledTask -TaskName "CIS Audit" -Action $action -Trigger $trigger
   ```

## Troubleshooting

### Execution Policy Errors

```powershell
# Bypass for single script
PowerShell.exe -ExecutionPolicy Bypass -File .\audit.ps1

# Set for current user
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Permission Errors

```powershell
# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "This script requires Administrator privileges"
}
```

### Module Not Found

```powershell
# Install required modules
Install-Module -Name PSDesiredStateConfiguration -Force
Install-Module -Name AuditPolicyDsc -Force
```

## References

- [CIS Microsoft Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows)
- [Windows Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines)
- [PowerShell DSC Documentation](https://docs.microsoft.com/en-us/powershell/dsc/overview)
- [Group Policy Management](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11))
