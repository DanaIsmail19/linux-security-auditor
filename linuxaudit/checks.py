"""
Core security audit checks for Linux systems.
Each check returns a dict with: name, status, severity, message, recommendation
"""

import os
import pwd
import grp
import stat
import subprocess
import re
from pathlib import Path
from typing import Any

PASS  = "PASS"
WARN  = "WARN"
FAIL  = "FAIL"
INFO  = "INFO"


def _run(cmd: list[str]) -> tuple[str, str, int]:
    """Run a subprocess and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", 1
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except PermissionError:
        return "", "Permission denied", 1


def check_ssh_config() -> dict[str, Any]:
    """Check SSH server configuration for insecure settings."""
    issues = []
    recommendations = []
    status = PASS
    sshd_config = Path("/etc/ssh/sshd_config")

    if not sshd_config.exists():
        return {
            "name": "SSH Configuration",
            "status": INFO,
            "severity": "low",
            "message": "sshd_config not found — SSH server may not be installed.",
            "recommendation": "No action needed if SSH is not in use.",
        }

    content = sshd_config.read_text()
    lines = content.splitlines()

    def get_value(key: str) -> str | None:
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == key.lower():
                return parts[1].strip()
        return None

    checks = [
        ("PermitRootLogin", ["no", "prohibit-password"], "Root login should be disabled or key-only."),
        ("PasswordAuthentication", ["no"], "Password auth should be disabled; use SSH keys."),
        ("PermitEmptyPasswords", ["no"], "Empty passwords must never be permitted."),
        ("Protocol", ["2"], "Only SSH protocol 2 is secure."),
        ("X11Forwarding", ["no"], "X11 forwarding exposes security risks if unused."),
    ]

    for key, safe_values, rec in checks:
        val = get_value(key)
        if val is not None and val.lower() not in safe_values:
            issues.append(f"{key} = {val}")
            recommendations.append(f"Set '{key} {safe_values[0]}' — {rec}")
            status = FAIL

    message = (
        f"Issues found: {'; '.join(issues)}" if issues
        else "SSH configuration looks secure."
    )

    return {
        "name": "SSH Configuration",
        "status": status,
        "severity": "high",
        "message": message,
        "recommendation": "\n  ".join(recommendations) if recommendations else "No changes needed.",
    }


def check_world_writable_files() -> dict[str, Any]:
    """Scan /etc and /usr for world-writable files (excluding sticky-bit dirs)."""
    risky_files = []
    scan_dirs = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]

    for directory in scan_dirs:
        if not os.path.isdir(directory):
            continue
        for root, dirs, files in os.walk(directory, followlinks=False):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for name in files:
                path = os.path.join(root, name)
                try:
                    file_stat = os.stat(path)
                    mode = file_stat.st_mode
                    # World-writable without sticky bit
                    if (mode & stat.S_IWOTH) and not (mode & stat.S_ISVTX):
                        risky_files.append(path)
                except (PermissionError, FileNotFoundError):
                    continue

    if risky_files:
        sample = risky_files[:5]
        extra = f" (+{len(risky_files)-5} more)" if len(risky_files) > 5 else ""
        return {
            "name": "World-Writable Files",
            "status": FAIL,
            "severity": "high",
            "message": f"Found {len(risky_files)} world-writable file(s): {', '.join(sample)}{extra}",
            "recommendation": "Run: chmod o-w <file> for each listed file.",
        }

    return {
        "name": "World-Writable Files",
        "status": PASS,
        "severity": "high",
        "message": "No world-writable files found in critical directories.",
        "recommendation": "No action needed.",
    }


def check_suid_sgid_binaries() -> dict[str, Any]:
    """List unexpected SUID/SGID binaries outside of standard known-safe paths."""
    known_safe = {
        "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/newgrp",
        "/usr/bin/gpasswd", "/usr/bin/chsh", "/usr/bin/chfn",
        "/usr/bin/su", "/bin/su", "/usr/bin/mount", "/usr/bin/umount",
        "/bin/mount", "/bin/umount", "/usr/sbin/pam_timestamp_check",
        "/usr/lib/openssh/ssh-keysign", "/usr/bin/ssh-agent",
        "/usr/bin/crontab", "/usr/bin/at", "/usr/bin/write",
        "/usr/sbin/unix_chkpwd",
    }

    stdout, _, _ = _run([
        "find", "/", "-xdev",
        "(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
        "-type", "f", "-print"
    ])

    if not stdout:
        # Try without parens if shell escaping was an issue — use Python directly
        found = []
        scan_dirs = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib"]
        for directory in scan_dirs:
            if not os.path.isdir(directory):
                continue
            for root, _, files in os.walk(directory, followlinks=False):
                for name in files:
                    path = os.path.join(root, name)
                    try:
                        mode = os.stat(path).st_mode
                        if mode & (stat.S_ISUID | stat.S_ISGID):
                            found.append(path)
                    except (PermissionError, FileNotFoundError):
                        continue
    else:
        found = [f for f in stdout.splitlines() if f.strip()]

    unexpected = [f for f in found if f not in known_safe]

    if unexpected:
        sample = unexpected[:5]
        extra = f" (+{len(unexpected)-5} more)" if len(unexpected) > 5 else ""
        return {
            "name": "SUID/SGID Binaries",
            "status": WARN,
            "severity": "medium",
            "message": f"Found {len(unexpected)} unexpected SUID/SGID binary(ies): {', '.join(sample)}{extra}",
            "recommendation": "Review each binary. Remove SUID if unneeded: chmod u-s <file>",
        }

    return {
        "name": "SUID/SGID Binaries",
        "status": PASS,
        "severity": "medium",
        "message": f"Found {len(found)} SUID/SGID binaries — all are standard system utilities.",
        "recommendation": "No action needed.",
    }


def check_empty_password_accounts() -> dict[str, Any]:
    """Detect user accounts with empty passwords in /etc/shadow."""
    empty_pw_users = []

    shadow = Path("/etc/shadow")
    if not shadow.exists():
        return {
            "name": "Empty Password Accounts",
            "status": INFO,
            "severity": "high",
            "message": "/etc/shadow not readable — run as root for full check.",
            "recommendation": "Run the auditor with sudo for complete shadow file analysis.",
        }

    try:
        for line in shadow.read_text().splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                username = parts[0]
                password = parts[1]
                # Empty password field or just "!" prefix variants
                if password == "" or password == "::":
                    empty_pw_users.append(username)
    except PermissionError:
        return {
            "name": "Empty Password Accounts",
            "status": INFO,
            "severity": "high",
            "message": "Cannot read /etc/shadow — insufficient privileges.",
            "recommendation": "Run with sudo: sudo linuxaudit",
        }

    if empty_pw_users:
        return {
            "name": "Empty Password Accounts",
            "status": FAIL,
            "severity": "high",
            "message": f"Accounts with empty passwords: {', '.join(empty_pw_users)}",
            "recommendation": "Set a password or lock each account: passwd -l <username>",
        }

    return {
        "name": "Empty Password Accounts",
        "status": PASS,
        "severity": "high",
        "message": "No accounts with empty passwords found.",
        "recommendation": "No action needed.",
    }


def check_firewall_status() -> dict[str, Any]:
    """Check if a firewall (ufw, firewalld, or iptables) is active."""
    # Try ufw
    stdout, _, rc = _run(["ufw", "status"])
    if rc == 0:
        active = "active" in stdout.lower()
        return {
            "name": "Firewall Status (ufw)",
            "status": PASS if active else FAIL,
            "severity": "high",
            "message": f"ufw is {'active' if active else 'INACTIVE'}.",
            "recommendation": "Enable ufw: sudo ufw enable" if not active else "No action needed.",
        }

    # Try firewalld
    stdout, _, rc = _run(["firewall-cmd", "--state"])
    if rc == 0:
        active = "running" in stdout.lower()
        return {
            "name": "Firewall Status (firewalld)",
            "status": PASS if active else FAIL,
            "severity": "high",
            "message": f"firewalld is {'running' if active else 'NOT running'}.",
            "recommendation": "Start firewalld: sudo systemctl start firewalld" if not active else "No action needed.",
        }

    # Try iptables
    stdout, _, rc = _run(["iptables", "-L", "-n"])
    if rc == 0:
        rules = [l for l in stdout.splitlines() if not l.startswith("Chain") and l.strip()]
        has_rules = len(rules) > 2
        return {
            "name": "Firewall Status (iptables)",
            "status": PASS if has_rules else WARN,
            "severity": "high",
            "message": f"iptables has {'rules configured' if has_rules else 'no custom rules (default ACCEPT policy)'}.",
            "recommendation": "Configure iptables rules or install ufw/firewalld." if not has_rules else "No action needed.",
        }

    return {
        "name": "Firewall Status",
        "status": WARN,
        "severity": "high",
        "message": "Could not detect any firewall (ufw, firewalld, iptables).",
        "recommendation": "Install and configure a firewall: sudo apt install ufw && sudo ufw enable",
    }


def check_open_ports() -> dict[str, Any]:
    """List listening network ports using ss or netstat."""
    stdout, _, rc = _run(["ss", "-tlnp"])
    if rc != 0:
        stdout, _, rc = _run(["netstat", "-tlnp"])

    if rc != 0 or not stdout:
        return {
            "name": "Open Ports",
            "status": INFO,
            "severity": "medium",
            "message": "Could not retrieve open ports (ss/netstat not available or no permission).",
            "recommendation": "Run with sudo for full port information.",
        }

    ports = []
    for line in stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            local = parts[3] if "ss" in stdout[:10] else parts[3]
            ports.append(local)

    risky_ports = ["23", "21", "512", "513", "514", "6000", "6001"]
    found_risky = []

    for port_str in ports:
        port_num = port_str.rsplit(":", 1)[-1]
        if port_num in risky_ports:
            found_risky.append(port_num)

    if found_risky:
        return {
            "name": "Open Ports",
            "status": WARN,
            "severity": "medium",
            "message": f"Potentially dangerous services listening on port(s): {', '.join(set(found_risky))}",
            "recommendation": "Disable telnet (23), FTP (21), rsh (512-514), X11 (6000) if not needed.",
        }

    return {
        "name": "Open Ports",
        "status": PASS,
        "severity": "medium",
        "message": f"No high-risk ports detected. {len(ports)} port(s) listening.",
        "recommendation": "Periodically review open ports with: ss -tlnp",
    }


def check_password_policy() -> dict[str, Any]:
    """Check /etc/login.defs for password aging and strength settings."""
    login_defs = Path("/etc/login.defs")
    if not login_defs.exists():
        return {
            "name": "Password Policy",
            "status": INFO,
            "severity": "medium",
            "message": "/etc/login.defs not found.",
            "recommendation": "Manually review your password policy configuration.",
        }

    content = login_defs.read_text()
    issues = []
    recommendations = []

    def get_val(key: str) -> int | None:
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) == 2 and parts[0] == key:
                try:
                    return int(parts[1])
                except ValueError:
                    return None
        return None

    pass_max_days = get_val("PASS_MAX_DAYS")
    pass_min_len  = get_val("PASS_MIN_LEN")
    pass_warn_age = get_val("PASS_WARN_AGE")

    if pass_max_days is None or pass_max_days > 90:
        issues.append(f"PASS_MAX_DAYS={pass_max_days} (should be ≤90)")
        recommendations.append("Set PASS_MAX_DAYS to 90 in /etc/login.defs")

    if pass_min_len is None or pass_min_len < 12:
        issues.append(f"PASS_MIN_LEN={pass_min_len} (should be ≥12)")
        recommendations.append("Set PASS_MIN_LEN to 12 or higher in /etc/login.defs")

    if pass_warn_age is None or pass_warn_age < 7:
        issues.append(f"PASS_WARN_AGE={pass_warn_age} (should be ≥7)")
        recommendations.append("Set PASS_WARN_AGE to 7 in /etc/login.defs")

    if issues:
        return {
            "name": "Password Policy",
            "status": WARN,
            "severity": "medium",
            "message": "Weak password policy: " + "; ".join(issues),
            "recommendation": "\n  ".join(recommendations),
        }

    return {
        "name": "Password Policy",
        "status": PASS,
        "severity": "medium",
        "message": f"Password policy looks reasonable (max_days={pass_max_days}, min_len={pass_min_len}).",
        "recommendation": "No action needed.",
    }


def check_unattended_upgrades() -> dict[str, Any]:
    """Check if automatic security updates are configured."""
    # Debian/Ubuntu
    ua_config = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if ua_config.exists():
        content = ua_config.read_text()
        enabled = 'APT::Periodic::Unattended-Upgrade "1"' in content
        return {
            "name": "Automatic Security Updates",
            "status": PASS if enabled else WARN,
            "severity": "medium",
            "message": f"Unattended upgrades are {'enabled' if enabled else 'NOT enabled'}.",
            "recommendation": (
                "No action needed." if enabled
                else "Enable: sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades"
            ),
        }

    # RHEL/CentOS/Fedora — check dnf-automatic
    dnf_timer = Path("/etc/dnf/automatic.conf")
    if dnf_timer.exists():
        stdout, _, rc = _run(["systemctl", "is-active", "dnf-automatic.timer"])
        active = rc == 0 and "active" in stdout
        return {
            "name": "Automatic Security Updates (dnf-automatic)",
            "status": PASS if active else WARN,
            "severity": "medium",
            "message": f"dnf-automatic timer is {'active' if active else 'not active'}.",
            "recommendation": "Enable: sudo systemctl enable --now dnf-automatic.timer" if not active else "No action needed.",
        }

    return {
        "name": "Automatic Security Updates",
        "status": WARN,
        "severity": "medium",
        "message": "Could not detect automatic update configuration.",
        "recommendation": "Set up automatic security updates for your distro.",
    }


def check_core_dumps() -> dict[str, Any]:
    """Check if core dumps are disabled (they can leak sensitive memory)."""
    limits_conf = Path("/etc/security/limits.conf")
    sysctl_conf = Path("/proc/sys/kernel/core_pattern")

    core_disabled = False

    if limits_conf.exists():
        for line in limits_conf.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "core" in stripped and "0" in stripped:
                core_disabled = True
                break

    core_pattern = sysctl_conf.read_text().strip() if sysctl_conf.exists() else ""

    if core_disabled:
        return {
            "name": "Core Dumps",
            "status": PASS,
            "severity": "low",
            "message": "Core dumps are disabled in limits.conf.",
            "recommendation": "No action needed.",
        }

    return {
        "name": "Core Dumps",
        "status": WARN,
        "severity": "low",
        "message": f"Core dumps may be enabled. Pattern: '{core_pattern}'",
        "recommendation": (
            "Add '* hard core 0' to /etc/security/limits.conf and "
            "set 'fs.suid_dumpable = 0' in /etc/sysctl.conf"
        ),
    }


# Registry of all checks
ALL_CHECKS = [
    check_ssh_config,
    check_world_writable_files,
    check_suid_sgid_binaries,
    check_empty_password_accounts,
    check_firewall_status,
    check_open_ports,
    check_password_policy,
    check_unattended_upgrades,
    check_core_dumps,
]
