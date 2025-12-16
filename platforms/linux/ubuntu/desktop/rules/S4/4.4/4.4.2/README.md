# 4.4.2 Configure ip6tables (IPv6)

## Description
This section covers ip6tables (IPv6) configuration for legacy iptables-based systems.

## Rationale
IPv6 traffic should be filtered similarly to IPv4.

## Note
Ubuntu 24.04 defaults to nftables which handles IPv6 natively. This section is for legacy configurations.

## Audit
```bash
ip6tables -L
```

## Remediation
Apply similar rules as iptables but for IPv6:
```bash
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```
