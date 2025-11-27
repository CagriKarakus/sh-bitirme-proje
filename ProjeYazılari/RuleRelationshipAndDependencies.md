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