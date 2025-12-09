# CIS Benchmark Rule Relationships and Dependencies

This document outlines the dependencies, conflicts, and logical groupings between the implemented CIS Benchmark rules. Understanding these relationships is crucial for generating valid and effective remediation scripts.

## 1. Partition & Mount Option Dependencies (Section 1.1)

These rules follow a **Parent-Child** relationship. The "Separate Partition" rule is a prerequisite for the "Mount Option" rules. If the partition does not exist, setting mount options for it is logically impossible or requires a different approach (remounting root), which these rules are not designed for.

| Parent Rule (Partition Existence) | Child Rules (Mount Options) | Logic |
| :--- | :--- | :--- |
| **1.1.3.1** Ensure `/var` is a separate partition | **1.1.3.2** (`nodev`), **1.1.3.3** (`nosuid`) | If 1.1.3.1 fails, child rules should be skipped or will fail. |
| **1.1.4.1** Ensure `/var/tmp` is a separate partition | **1.1.4.2** (`nodev`), **1.1.4.3** (`nosuid`), **1.1.4.4** (`noexec`) | Same as above. |
| **1.1.5.1** Ensure `/var/log` is a separate partition | **1.1.5.2** (`nodev`), **1.1.5.3** (`nosuid`), **1.1.5.4** (`noexec`) | Same as above. |
| **1.1.6.1** Ensure `/var/log/audit` is a separate partition | **1.1.6.2** (`nodev`), **1.1.6.3** (`nosuid`), **1.1.6.4** (`noexec`) | Same as above. |
| **1.1.7.1** Ensure `/home` is a separate partition | **1.1.7.2** (`nodev`), **1.1.7.3** (`nosuid`) | Same as above. |
| **1.1.8.1** Ensure `/dev/shm` is a separate partition | **1.1.8.2** (`nodev`), **1.1.8.3** (`nosuid`), **1.1.8.4** (`noexec`) | Same as above. |

## 2. Time Synchronization Conflicts (Section 2.3)

These rules represent a **Mutually Exclusive Selection**. You must choose **EXACTLY ONE** time synchronization method.

*   **Parent Requirement**: `2.3.1 Ensure time synchronization is in use` (This is a general check).
*   **Selection**: Choose **ONE** of the following:
    *   **Option A**: `2.3.2 Ensure ntp is configured`
    *   **Option B**: `2.3.3 Ensure chrony is configured`
    *   **Option C**: `2.3.4 Ensure systemd-timesyncd is configured`

**Conflict Logic**:
*   If **Option A** is selected, Options B and C should be ignored/disabled.
*   If **Option B** is selected, Options A and C should be ignored/disabled.
*   If **Option C** is selected, Options A and B should be ignored/disabled.

## 3. Host Based Firewall Conflicts (Section 4)

This section contains the most significant conflicts. You must choose **EXACTLY ONE** firewall utility.

*   **Meta-Rule**: `4.1.1 Ensure a single firewall configuration utility is in use`.

### Option A: Uncomplicated Firewall (UFW) (Section 4.2)
*   **Prerequisite**: `4.2.1 Ensure ufw is installed`.
*   **Conflict Resolution**: `4.2.2 Ensure iptables-persistent is not installed with ufw`.
*   **Dependencies**: Rules `4.2.3` through `4.2.7` depend on `4.2.1`.
*   **Exclusion**: If UFW is selected, **Section 4.3 (nftables)** and **Section 4.4 (iptables)** rules should be **DISABLED**.

### Option B: nftables (Section 4.3)
*   **Prerequisite**: `4.3.1 Ensure nftables is installed`.
*   **Conflict Resolution**:
    *   `4.3.2 Ensure ufw is uninstalled or disabled with nftables`.
    *   `4.3.3 Ensure iptables are flushed with nftables`.
*   **Dependencies**: Rules `4.3.4` through `4.3.10` depend on `4.3.1`.
*   **Exclusion**: If nftables is selected, **Section 4.2 (UFW)** and **Section 4.4 (iptables)** rules should be **DISABLED**.

### Option C: iptables (Section 4.4)
*   **Prerequisite**: `4.4.1.1 Ensure iptables packages are installed`.
*   **Conflict Resolution**:
    *   `4.4.1.2 Ensure nftables is not in use with iptables`.
    *   `4.4.1.3 Ensure ufw is not in use with iptables`.
*   **Dependencies**: Rules `4.4.2.x` (IPv4) and `4.4.3.x` (IPv6) depend on `4.4.1.1`.
*   **Exclusion**: If iptables is selected, **Section 4.2 (UFW)** and **Section 4.3 (nftables)** rules should be **DISABLED**.

## 4. Mandatory Access Control (Section 1.6)

*   **Prerequisite**: `1.6.1 Ensure AppArmor is installed`.
*   **Dependencies**: `1.6.2` (Bootloader config) and `1.6.3` (Profile mode) depend on AppArmor being installed.

## 5. Service Disabling (Section 2.1 & 2.2)

These rules are generally independent but represent a "Negative Requirement".
*   **Logic**: If a specific service is **REQUIRED** for the system's function (e.g., it is a Web Server), then the corresponding rule (e.g., `2.1.18 Ensure web server services are not in use`) must be **DISABLED/IGNORED**.

## 6. Logging and Auditing (Section 6)

**Note**: Section 6 is currently under development and contains no implemented rules yet.

This section will contain rules for:
- System logging configuration (rsyslog/syslog-ng)
- Audit daemon (auditd) setup and configuration
- Log rotation and retention policies
- Audit rules for system events
- Journal upload and remote logging

### Expected Dependencies:
- Logging service conflicts (similar to time sync - choose rsyslog OR syslog-ng)
- Audit daemon prerequisites for audit rules
- Log partition dependencies (relates to 1.1.6.1 /var/log/audit partition)

## 7. System Maintenance (Section 7)

Section 7 rules focus on system file permissions and user/group configurations. Most rules are **independent** but some have logical relationships.

### 7.1 System File Permissions

**Independent Rules** - These can run in any order:
*   **7.1.1** - /etc/passwd permissions
*   **7.1.2** - /etc/passwd- permissions
*   **7.1.3** - /etc/group permissions
*   **7.1.4** - /etc/group- permissions
*   **7.1.5** - /etc/shadow permissions
*   **7.1.6** - /etc/shadow- permissions
*   **7.1.7** - /etc/gshadow permissions
*   **7.1.8** - /etc/gshadow- permissions
*   **7.1.9** - /etc/shells permissions
*   **7.1.10** - /etc/security/opasswd permissions

**File System Scan Rules** - These are resource-intensive:
*   **7.1.11** - World writable files and directories
*   **7.1.12** - Files without owner/group
*   **7.1.13** - SUID/SGID files review (Manual)

**Best Practice**: Run scan rules (7.1.11-7.1.13) separately or after other rules due to system-wide file scanning.

### 7.2 Local User and Group Settings

**Logical Sequence** - These rules should be run in order for best results:

1.  **7.2.1** - Shadowed passwords (Prerequisite for 7.2.2)
2.  **7.2.2** - Empty password fields (Depends on shadow system)
3.  **7.2.3** - Group existence check
4.  **7.2.4** - Shadow group emptiness

**Independent Checks** - Can run in any order:
*   **7.2.5** - Duplicate UIDs
*   **7.2.6** - Duplicate GIDs
*   **7.2.7** - Duplicate user names
*   **7.2.8** - Duplicate group names

**User Environment Rules** - Should run after user/group validation:
*   **7.2.9** - Home directory configuration (Run after 7.2.5, 7.2.7)
*   **7.2.10** - Dot files access (Run after 7.2.9)

**Recommended Execution Order**:
```
7.2.1 → 7.2.2 → 7.2.3 → 7.2.4 → 7.2.5/6/7/8 (parallel) → 7.2.9 → 7.2.10
```

---

## Summary: Rule Relationship Types

The CIS Benchmark rules across all 7 sections exhibit the following relationship patterns:

### 1. **Parent-Child Dependencies** (Hierarchical)
- Partition existence before mount options (Section 1.1)
- AppArmor installation before configuration (Section 1.6)
- Firewall installation before rules (Section 4)
- Shadow password system before empty password checks (Section 7.2)

### 2. **Mutually Exclusive Conflicts** (Choose One)
- Time synchronization services (Section 2.3): ntp XOR chrony XOR systemd-timesyncd
- Firewall utilities (Section 4): UFW XOR nftables XOR iptables
- *Future: Logging services (Section 6): rsyslog XOR syslog-ng*

### 3. **Negative Requirements** (Conditional)
- Service disabling rules (Section 2): Disable if not required by system role
- Example: Web server rule ignored if system IS a web server

### 4. **Sequential Dependencies** (Order Matters)
- User/group validation sequence (Section 7.2): shadows → validation → home dirs → dot files

### 5. **Independent Parallel Rules** (No Dependencies)
- Most file permission rules (Section 7.1.1-7.1.10)
- Network configuration rules (Section 3)
- Individual SSH hardening rules (Section 5)
- Duplicate detection rules (Section 7.2.5-7.2.8)

### 6. **Resource-Intensive Rules** (Performance Consideration)
- System-wide file scans (Section 7.1.11-7.1.13)
- SUID/SGID searches
- World-writable file detection

### 7. **Cross-Section Dependencies**
- Log partition (1.1.6.1) ← Audit configuration (Section 6 - future)
- PAM configuration (Section 5) ← Shadow system (Section 7.2.1)

---

## Recommendations for Script Generation

When generating combined audit/remediation scripts:

1. **Always check parent rules first** before running dependent children
2. **Implement conflict detection** to prevent concurrent conflicting rules
3. **Group independent rules** for parallel execution when possible
4. **Separate resource-intensive scans** into optional phases
5. **Validate prerequisites** before attempting remediation
6. **Provide user warnings** for mutually exclusive selections
7. **Log skipped rules** due to failed prerequisites or conflicts

### Optimal Section Execution Order:
```
Section 1 (Initial Setup)
  ↓
Section 2 (Services) - after package management ready
  ↓
Section 4 (Firewall) - after network services configured
  ↓
Section 3 (Network) - can run parallel with Section 4
  ↓
Section 5 (Access Control) - after services hardened
  ↓
Section 6 (Logging) - after audit partition ready
  ↓
Section 7 (Maintenance) - final validation
```

---

## Version History

- **v1.0** - Initial documentation (Sections 1-5)
- **v1.1** - Added Section 6 (placeholder) and Section 7 relationships
- **Last Updated**: 2025-12-09