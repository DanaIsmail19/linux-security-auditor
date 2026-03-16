# 🔒 Linux Security Auditor

A simple, open-source Python CLI tool that audits common Linux security settings and reports issues with clear recommendations.

**Perfect for sysadmins, security learners, and CTF players.**

---

## Features

| Check | What it looks for |
|---|---|
| SSH Configuration | Root login, password auth, protocol version, X11 forwarding |
| World-Writable Files | Files in `/etc`, `/usr/bin` writable by anyone |
| SUID/SGID Binaries | Unexpected setuid binaries outside known-safe paths |
| Empty Password Accounts | Accounts with blank passwords in `/etc/shadow` |
| Firewall Status | Active ufw / firewalld / iptables rules |
| Open Ports | Dangerous services (telnet, FTP, rsh, X11) |
| Password Policy | Max age, min length, warning days in `/etc/login.defs` |
| Auto Security Updates | Unattended upgrades (apt) / dnf-automatic |
| Core Dumps | Sensitive memory leak prevention |

---

## Install

```bash
# From source
git clone https://github.com/yourname/linux-security-auditor
cd linux-security-auditor
pip install -e .
```

---

## Usage

```bash
# Run all checks
linuxaudit

# Show recommendations for every check (not just failures)
linuxaudit --verbose

# Run only specific checks
linuxaudit --check ssh_config firewall_status

# Save report as JSON
linuxaudit --json report.json

# List all available checks
linuxaudit --list

# For checks requiring root (shadow file, full port listing):
sudo linuxaudit
```

---

## Example Output

```
  [✖ FAIL]  SSH Configuration
             Issues found: PermitRootLogin = yes; PasswordAuthentication = yes
             → Set 'PermitRootLogin no' — Root login should be disabled or key-only.
             → Set 'PasswordAuthentication no' — Password auth should be disabled; use SSH keys.

  [✔ PASS]  World-Writable Files
             No world-writable files found in critical directories.

  [⚠ WARN]  Password Policy
             Weak password policy: PASS_MIN_LEN=6 (should be ≥12)
             → Set PASS_MIN_LEN to 12 or higher in /etc/login.defs
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Contributing

Contributions are welcome! Ideas for new checks:

- AppArmor / SELinux status
- Cron job permissions
- `/tmp` mount options (noexec)
- sudo configuration audit
- File system mount hardening

Open an issue or pull request on GitHub.

---

## License

MIT — free to use, modify, and distribute.
