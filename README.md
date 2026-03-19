# 🔒 Linux Security Auditor

A simple, open-source Python CLI tool that audits common Linux security misconfigurations and generates hardened AppArmor profiles — ready to load directly into the kernel.

**Built for sysadmins, security engineers, CTF players, and open source contributors.**

---

## Features

### Security Audit Checks

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

### AppArmor Profile Generator

Automatically generates a hardened AppArmor profile for any binary by:
- Detecting the binary category (web server, SSH, interpreter, shell, network tool, database, TLS app, GUI app)
- Scanning linked libraries via `ldd`
- Detecting if the process is currently running
- Applying the right rule template with deny rules for sensitive paths

---

## Install

```bash
git clone https://github.com/DanaIsmail19/linux-security-auditor
cd linux-security-auditor

python3 -m venv venv
source venv/bin/activate

pip install .
```

---

## Usage

### Security Audit

```bash
# Run all checks
linuxaudit

# Full audit with root (unlocks shadow file, port listing)
sudo linuxaudit

# Show recommendations for every check
linuxaudit --verbose

# Run only specific checks
linuxaudit --check ssh_config
linuxaudit --check firewall_status open_ports

# List all available checks
linuxaudit --list

# Save report as JSON
linuxaudit --json report.json
```

### AppArmor Profile Generator

```bash
# Generate a profile for any binary
linuxaudit --apparmor curl
linuxaudit --apparmor nginx
linuxaudit --apparmor sshd
linuxaudit --apparmor /usr/bin/python3

# Print the profile to terminal
linuxaudit --apparmor curl --print

# Save to a specific path
linuxaudit --apparmor nginx --output /tmp/nginx-profile
```

#### Loading a generated profile

```bash
# 1. Review it first
cat /tmp/usr.bin.curl.apparmor

# 2. Test in complain mode (logs violations, doesn't block)
sudo aa-complain /usr/bin/curl

# 3. Copy to the standard location
sudo cp /tmp/usr.bin.curl.apparmor /etc/apparmor.d/usr.bin.curl

# 4. Load it
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.curl

# 5. Verify
sudo aa-status | grep curl
```

---

## Example Output

### Audit
```
  [✖ FAIL]  SSH Configuration
             Issues found: PermitRootLogin = yes; PasswordAuthentication = yes
             → Set 'PermitRootLogin no'
             → Set 'PasswordAuthentication no'

  [✔ PASS]  World-Writable Files
             No world-writable files found in critical directories.

  [⚠ WARN]  Password Policy
             Weak policy: PASS_MIN_LEN=6 (should be ≥12)
             → Set PASS_MIN_LEN to 12 in /etc/login.defs
```

### AppArmor Generator
```
  AppArmor Profile Generator

  Target  : curl
  Binary  : /usr/bin/curl
  Category: network_tool
  Libs    : 32 linked libraries detected
  Running : yes — live process found
  Output  : /tmp/usr.bin.curl.apparmor
```

---

## Project Structure

```
linux-security-auditor/
├── linuxaudit/
│   ├── __init__.py
│   ├── checks.py        ← 9 security audit checks
│   ├── cli.py           ← CLI entry point (argparse)
│   ├── report.py        ← colorized terminal + JSON output
│   └── apparmor_gen.py  ← AppArmor profile generator
├── tests/
│   ├── test_checks.py       ← audit check tests
│   └── test_apparmor_gen.py ← AppArmor generator tests (19 tests)
├── .github/workflows/ci.yml ← GitHub Actions CI
├── pyproject.toml
└── README.md
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---
### CVE Tracking
linuxaudit actively tracks Ubuntu Security Notices (USN) and checks
whether your installed packages are patched against known vulnerabilities.

| CVE | Severity | Affected | Fixed in |
|---|---|---|---|
| CVE-2026-3497 | Critical | OpenSSH GSSAPI Key Exchange | USN-8090-1 |
| CVE-2025-61984 | High | OpenSSH username control chars | USN-8090-1 |
| CVE-2025-61985 | High | OpenSSH NULL chars in URIs | USN-8090-1 | 
## Contributing

Contributions are welcome! Ideas for new checks and features:

- AppArmor status check (integrate into main audit)
- SELinux / AppArmor enforcement mode check
- `/tmp` and `/var/tmp` mount options (noexec, nosuid)
- Cron job permission audit
- sudo configuration review
- `--fix` flag for auto-remediation of safe issues
- HTML report output
- Live `aa-logprof` integration for profile refinement

Open an issue or pull request on GitHub.

---

## License

MIT — free to use, modify, and distribute.
