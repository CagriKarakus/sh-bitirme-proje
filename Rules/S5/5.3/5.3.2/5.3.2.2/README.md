# 5.3.2.2 Ensure pam_faillock module is enabled (Automated)

**Profile Applicability:**
- Level 1 - Server
- Level 1 - Workstation

## Description
The `pam_faillock` module is responsible for locking accounts after a specified number of failed login attempts.

## Rationale
Account lockout helps prevent brute-force password attacks.

## Audit
```bash
grep -P -- '\bpam_faillock\.so\b' /etc/pam.d/common-{auth,account}
```

## Remediation
```bash
pam-auth-update --enable faillock
```

## References
- NIST SP 800-53 Rev. 5: AC-7
