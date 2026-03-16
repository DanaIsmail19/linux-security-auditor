"""
AppArmor profile generator for linuxaudit.

Generates a hardened AppArmor profile for a given executable by:
  1. Inspecting the binary (ELF, interpreter, linked libs)
  2. Checking if the process is currently running (live mode)
  3. Applying a rule template based on binary category
  4. Writing a ready-to-load .apparmor profile file

Usage (CLI):
    linuxaudit --apparmor /usr/bin/python3
    linuxaudit --apparmor nginx
    linuxaudit --apparmor /usr/sbin/sshd --output /etc/apparmor.d/usr.sbin.sshd
"""

import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

# ── helpers ──────────────────────────────────────────────────────────────────

def _run(cmd: list[str]) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return "", "", 1


def _resolve_binary(name: str) -> str | None:
    """Resolve a binary name or path to an absolute path."""
    if os.path.isabs(name):
        return name if os.path.isfile(name) else None
    resolved = shutil.which(name)
    return resolved


def _get_linked_libs(binary: str) -> list[str]:
    """Return shared libraries the binary links against (via ldd)."""
    stdout, _, rc = _run(["ldd", binary])
    if rc != 0:
        return []
    libs = []
    for line in stdout.splitlines():
        # ldd output: "    libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x...)"
        match = re.search(r"=> (/\S+)", line)
        if match:
            libs.append(match.group(1))
    return libs


def _get_interpreter(binary: str) -> str | None:
    """Detect script interpreter (python3, bash, etc.) from shebang."""
    try:
        with open(binary, "rb") as f:
            header = f.read(128)
        if header[:2] == b"#!":
            shebang = header[2:].split(b"\n")[0].decode(errors="ignore").strip()
            interp = shebang.split()[0]
            return interp
    except (PermissionError, OSError):
        return None
    return None


def _is_running(binary: str) -> bool:
    """Check if the binary is currently running as a process."""
    stdout, _, rc = _run(["pgrep", "-f", os.path.basename(binary)])
    return rc == 0 and bool(stdout.strip())


def _detect_category(binary: str, libs: list[str]) -> str:
    """Classify binary into a broad category to select a rule template."""
    name = os.path.basename(binary).lower()
    lib_names = " ".join(libs).lower()

    if any(x in name for x in ["nginx", "apache", "httpd", "lighttpd"]):
        return "web_server"
    if any(x in name for x in ["sshd", "ssh"]):
        return "ssh_server"
    if any(x in name for x in ["python", "python3", "ruby", "perl", "php", "node"]):
        return "interpreter"
    if any(x in name for x in ["bash", "sh", "zsh", "fish", "dash"]):
        return "shell"
    if any(x in name for x in ["curl", "wget", "nc", "ncat", "nmap"]):
        return "network_tool"
    if any(x in name for x in ["mysql", "postgres", "redis", "mongo", "sqlite"]):
        return "database"
    if "libssl" in lib_names or "libcrypto" in lib_names:
        return "tls_app"
    if "libx11" in lib_names or "libgtk" in lib_names or "libqt" in lib_names:
        return "gui_app"
    return "generic"


# ── rule templates ────────────────────────────────────────────────────────────

# Each template is a list of (comment, rule) tuples.
# Rules use standard AppArmor syntax.

BASE_RULES = [
    ("# Allow reading system libraries and config", "/lib/**           r,"),
    ("", "/lib64/**          r,"),
    ("", "/usr/lib/**        r,"),
    ("", "/usr/lib64/**      r,"),
    ("", "/etc/ld.so.cache   r,"),
    ("", "/etc/ld.so.conf    r,"),
    ("", "/etc/ld.so.conf.d/ r,"),
    ("# Allow reading locale and timezone data", "/usr/share/locale/** r,"),
    ("", "/usr/share/zoneinfo/** r,"),
    ("", "/etc/localtime     r,"),
    ("# Proc: allow reading own process info", "/proc/self/**      r,"),
    ("# Allow /dev/null, /dev/zero, /dev/urandom", "/dev/null          rw,"),
    ("", "/dev/zero          r,"),
    ("", "/dev/urandom       r,"),
    ("# Deny writes to sensitive paths", "deny /etc/passwd   w,"),
    ("", "deny /etc/shadow   rw,"),
    ("", "deny /etc/sudoers  rw,"),
    ("", "deny /root/**      rw,"),
    ("# Deny raw network sockets unless explicitly allowed", "deny network raw,"),
    ("# Deny ptrace", "deny ptrace,"),
    ("# Deny loading kernel modules", "deny /sbin/insmod  x,"),
    ("", "deny /sbin/rmmod   x,"),
    ("", "deny /sbin/modprobe x,"),
]

CATEGORY_RULES: dict[str, list[tuple[str, str]]] = {
    "web_server": [
        ("# Web server: serve files and bind to port 80/443", "network inet  stream,"),
        ("", "network inet6 stream,"),
        ("", "/var/www/**         r,"),
        ("", "/srv/www/**         r,"),
        ("", "/etc/nginx/**       r,"),
        ("", "/etc/apache2/**     r,"),
        ("", "/var/log/nginx/**   w,"),
        ("", "/var/log/apache2/** w,"),
        ("", "/var/run/nginx.pid  rw,"),
        ("", "/tmp/               rw,"),
        ("", "/tmp/**             rw,"),
        ("# Deny access to system config outside web dirs", "deny /etc/ssh/**   r,"),
        ("", "deny /home/**       rw,"),
    ],
    "ssh_server": [
        ("# SSH server: accept connections, manage keys", "network inet  stream,"),
        ("", "network inet6 stream,"),
        ("", "/etc/ssh/**         r,"),
        ("", "/var/log/auth.log   w,"),
        ("", "/var/log/syslog     w,"),
        ("", "/var/run/sshd.pid   rw,"),
        ("", "/home/*/.ssh/authorized_keys r,"),
        ("", "/root/.ssh/authorized_keys   r,"),
        ("# PAM stack", "/lib/*/security/**  mr,"),
        ("", "/etc/pam.d/**       r,"),
        ("", "/etc/security/**    r,"),
        ("# Deny browsing user home dirs beyond keys", "deny /home/**       rw,"),
    ],
    "interpreter": [
        ("# Interpreter: read scripts and standard paths", "network inet stream,"),
        ("", "network inet6 stream,"),
        ("", "/usr/lib/python3*/** r,"),
        ("", "/usr/local/lib/python3*/** r,"),
        ("", "@{HOME}/**          rw,"),
        ("", "/tmp/**             rw,"),
        ("", "/var/tmp/**         rw,"),
        ("# Allow executing child processes (controlled)", "/{usr/,}bin/**     ix,"),
        ("# Deny writing to system binaries", "deny /usr/bin/**    w,"),
        ("", "deny /usr/sbin/**   w,"),
        ("", "deny /bin/**        w,"),
        ("", "deny /sbin/**       w,"),
    ],
    "shell": [
        ("# Shell: read/execute common utilities", "/{usr/,}bin/**     rix,"),
        ("", "/{usr/,}sbin/**    rix,"),
        ("", "/etc/**            r,"),
        ("", "@{HOME}/**         rw,"),
        ("", "/tmp/**            rw,"),
        ("", "network inet stream,"),
        ("# Deny modifying other users home dirs", "deny /root/**      rw,"),
    ],
    "network_tool": [
        ("# Network tool: allow outbound connections", "network inet  stream,"),
        ("", "network inet6 stream,"),
        ("", "network inet  dgram,"),
        ("", "network inet6 dgram,"),
        ("", "/etc/ssl/**        r,"),
        ("", "/etc/ca-certificates/** r,"),
        ("", "/usr/share/ca-certificates/** r,"),
        ("", "/tmp/**            rw,"),
        ("# Deny writing to system paths", "deny /etc/**        w,"),
        ("", "deny /usr/**        w,"),
    ],
    "database": [
        ("# Database: data directories and sockets", "network inet  stream,"),
        ("", "network inet6 stream,"),
        ("", "/var/lib/mysql/**   rw,"),
        ("", "/var/lib/postgresql/** rw,"),
        ("", "/var/lib/redis/**   rw,"),
        ("", "/var/log/mysql/**   w,"),
        ("", "/var/log/postgresql/** w,"),
        ("", "/run/mysqld/**      rw,"),
        ("", "/run/postgresql/**  rw,"),
        ("", "/etc/mysql/**       r,"),
        ("", "/etc/postgresql/**  r,"),
        ("# Deny access to user home dirs", "deny /home/**       rw,"),
        ("", "deny /root/**       rw,"),
    ],
    "tls_app": [
        ("# TLS app: access to certificates", "network inet  stream,"),
        ("", "network inet6 stream,"),
        ("", "/etc/ssl/**        r,"),
        ("", "/etc/ca-certificates/** r,"),
        ("", "/usr/share/ca-certificates/** r,"),
        ("", "/tmp/**            rw,"),
    ],
    "gui_app": [
        ("# GUI app: X11/Wayland display access", "network inet  stream,"),
        ("", "/tmp/.X11-unix/**   rw,"),
        ("", "/run/user/[0-9]*/wayland-* rw,"),
        ("", "@{HOME}/**         rw,"),
        ("", "/usr/share/**      r,"),
        ("", "/etc/fonts/**      r,"),
        ("", "/var/cache/fontconfig/** rw,"),
        ("# Deny network by default unless needed", "deny network raw,"),
    ],
    "generic": [
        ("# Generic: minimal permissions", "/tmp/**            rw,"),
        ("", "/var/tmp/**        rw,"),
        ("", "@{HOME}/**         r,"),
        ("# No network by default — add manually if needed", "deny network inet  stream,"),
        ("", "deny network inet6 stream,"),
    ],
}


# ── profile writer ────────────────────────────────────────────────────────────

def _profile_name_from_path(binary: str) -> str:
    """Convert /usr/bin/nginx → usr.bin.nginx (AppArmor convention)."""
    return binary.lstrip("/").replace("/", ".")


def generate_profile(binary: str, libs: list[str], category: str, is_running: bool) -> str:
    """Render a complete AppArmor profile as a string."""
    profile_name = _profile_name_from_path(binary)
    now = datetime.now().strftime("%Y-%m-%d")

    lines = [
        f"# AppArmor profile for {binary}",
        f"# Generated by linuxaudit on {now}",
        f"# Category detected: {category}",
        f"# Binary running at scan time: {'yes' if is_running else 'no'}",
        "#",
        "# REVIEW BEFORE LOADING — adjust rules to match your environment.",
        "# To load:   sudo apparmor_parser -r /etc/apparmor.d/" + profile_name,
        "# To disable: sudo aa-disable " + binary,
        "# To set complain mode first: sudo aa-complain " + binary,
        "",
        f'profile {binary} flags=(attach_disconnected) {{',
        "",
        "  #include <abstractions/base>",
        "",
    ]

    # Emit binary itself as executable
    lines.append(f"  # The binary itself")
    lines.append(f"  {binary}  mr,")
    lines.append("")

    # Linked library rules
    if libs:
        lines.append("  # Detected linked libraries")
        seen_dirs = set()
        for lib in libs:
            lib_dir = str(Path(lib).parent) + "/"
            if lib_dir not in seen_dirs:
                lines.append(f"  {lib_dir}*  mr,")
                seen_dirs.add(lib_dir)
        lines.append("")

    # Base rules
    lines.append("  # Base rules (all profiles)")
    for comment, rule in BASE_RULES:
        if comment:
            lines.append(f"  {comment}")
        lines.append(f"  {rule}")
    lines.append("")

    # Category-specific rules
    cat_rules = CATEGORY_RULES.get(category, CATEGORY_RULES["generic"])
    lines.append(f"  # Category-specific rules ({category})")
    for comment, rule in cat_rules:
        if comment:
            lines.append(f"  {comment}")
        lines.append(f"  {rule}")
    lines.append("")

    lines.append("}")
    return "\n".join(lines)


# ── public API ────────────────────────────────────────────────────────────────

def build_apparmor_profile(
    target: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    """
    Main entry point: generate an AppArmor profile for `target`.

    Returns a result dict compatible with the linuxaudit check schema.
    """
    binary = _resolve_binary(target)
    if binary is None:
        return {
            "name": "AppArmor Profile Generator",
            "status": "FAIL",
            "severity": "high",
            "message": f"Could not find binary: '{target}'",
            "recommendation": "Check the binary name or provide an absolute path.",
            "profile": None,
            "output_path": None,
        }

    libs       = _get_linked_libs(binary)
    interp     = _get_interpreter(binary)
    is_running = _is_running(binary)
    category   = _detect_category(binary, libs)

    # If it's a script, use interpreter's category
    if interp and category == "generic":
        category = _detect_category(interp, [])

    profile_text  = generate_profile(binary, libs, category, is_running)
    profile_fname = _profile_name_from_path(binary)

    # Determine output path
    if output_path is None:
        output_path = f"/tmp/{profile_fname}.apparmor"

    try:
        with open(output_path, "w") as f:
            f.write(profile_text)
        written = True
    except PermissionError:
        output_path = f"/tmp/{profile_fname}.apparmor"
        with open(output_path, "w") as f:
            f.write(profile_text)
        written = True

    profile_name = _profile_name_from_path(binary)

    return {
        "name": "AppArmor Profile Generator",
        "status": "PASS",
        "severity": "medium",
        "message": (
            f"Profile generated for {binary} "
            f"[category: {category}, libs: {len(libs)}, running: {is_running}]"
        ),
        "recommendation": (
            f"Review the profile at: {output_path}\n"
            f"  Then test in complain mode:  sudo aa-complain {binary}\n"
            f"  Load it:                     sudo apparmor_parser -r {output_path}\n"
            f"  Copy to standard location:   sudo cp {output_path} /etc/apparmor.d/{profile_name}"
        ),
        "profile": profile_text,
        "output_path": output_path,
        "binary": binary,
        "category": category,
        "linked_libs": libs,
        "is_running": is_running,
    }
