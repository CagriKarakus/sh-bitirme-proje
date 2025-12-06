# 4.4.3 Ensure iptables software is installed

## Description
Ensure iptables packages are installed if using iptables.

## Rationale
Required for legacy firewall configuration.

## Note
Ubuntu 24.04 uses nftables by default. iptables commands are translated to nftables.

## Audit
```bash
dpkg -l | grep iptables
```

## Remediation
```bash
apt install iptables iptables-persistent
```
