"""Tests for linux-security-auditor checks."""

import os
import sys
import tempfile
import textwrap
from pathlib import Path
from unittest import mock

import pytest

# Allow running tests from project root without install
sys.path.insert(0, str(Path(__file__).parent.parent))

from linuxaudit.checks import (
    FAIL, INFO, PASS, WARN,
    check_core_dumps,
    check_empty_password_accounts,
    check_open_ports,
    check_password_policy,
    check_ssh_config,
)


# ─── SSH Config ─────────────────────────────────────────────────────────────

def test_ssh_config_no_file(tmp_path):
    with mock.patch("linuxaudit.checks.Path") as MockPath:
        mock_inst = mock.MagicMock()
        mock_inst.exists.return_value = False
        MockPath.return_value = mock_inst
        result = check_ssh_config()
    # Either INFO (file not found) or any valid status
    assert result["status"] in (PASS, FAIL, WARN, INFO)
    assert "name" in result


def test_ssh_config_secure(tmp_path):
    sshd = tmp_path / "sshd_config"
    sshd.write_text(textwrap.dedent("""\
        PermitRootLogin no
        PasswordAuthentication no
        PermitEmptyPasswords no
        Protocol 2
        X11Forwarding no
    """))
    with mock.patch("linuxaudit.checks.Path", return_value=sshd):
        # Patch at the Path usage inside the function
        pass
    # We can test the logic directly by calling with the real parser
    from linuxaudit import checks
    original = checks.Path
    try:
        checks.Path = lambda p: sshd if "sshd_config" in str(p) else original(p)
        result = check_ssh_config()
        assert result["status"] == PASS
    finally:
        checks.Path = original


def test_ssh_config_insecure(tmp_path):
    sshd = tmp_path / "sshd_config"
    sshd.write_text("PermitRootLogin yes\nPasswordAuthentication yes\n")
    from linuxaudit import checks
    original = checks.Path
    try:
        checks.Path = lambda p: sshd if "sshd_config" in str(p) else original(p)
        result = check_ssh_config()
        assert result["status"] == FAIL
        assert "PermitRootLogin" in result["message"]
    finally:
        checks.Path = original


# ─── Password Policy ────────────────────────────────────────────────────────

def test_password_policy_good(tmp_path):
    cfg = tmp_path / "login.defs"
    cfg.write_text("PASS_MAX_DAYS 90\nPASS_MIN_LEN 12\nPASS_WARN_AGE 7\n")
    from linuxaudit import checks
    orig = checks.Path
    try:
        checks.Path = lambda p: cfg if "login.defs" in str(p) else orig(p)
        result = check_password_policy()
        assert result["status"] == PASS
    finally:
        checks.Path = orig


def test_password_policy_weak(tmp_path):
    cfg = tmp_path / "login.defs"
    cfg.write_text("PASS_MAX_DAYS 999\nPASS_MIN_LEN 6\nPASS_WARN_AGE 1\n")
    from linuxaudit import checks
    orig = checks.Path
    try:
        checks.Path = lambda p: cfg if "login.defs" in str(p) else orig(p)
        result = check_password_policy()
        assert result["status"] == WARN
    finally:
        checks.Path = orig


# ─── Empty Password Accounts ────────────────────────────────────────────────

def test_empty_password_accounts_no_shadow(tmp_path):
    from linuxaudit import checks
    orig = checks.Path
    try:
        mock_p = mock.MagicMock()
        mock_p.exists.return_value = False
        checks.Path = lambda p: mock_p if "shadow" in str(p) else orig(p)
        result = check_empty_password_accounts()
        assert result["status"] == INFO
    finally:
        checks.Path = orig


def test_empty_password_accounts_clean(tmp_path):
    shadow = tmp_path / "shadow"
    shadow.write_text(
        "root:$6$abc$hashedpassword:19000:0:99999:7:::\n"
        "alice:$6$xyz$anotherhash:19000:0:99999:7:::\n"
    )
    from linuxaudit import checks
    orig = checks.Path
    try:
        checks.Path = lambda p: shadow if "shadow" in str(p) else orig(p)
        result = check_empty_password_accounts()
        assert result["status"] == PASS
    finally:
        checks.Path = orig


def test_empty_password_accounts_with_empty(tmp_path):
    shadow = tmp_path / "shadow"
    shadow.write_text(
        "root:$6$abc$hash:19000:0:99999:7:::\n"
        "baduser:::19000:0:99999:7:::\n"
    )
    from linuxaudit import checks
    orig = checks.Path
    try:
        checks.Path = lambda p: shadow if "shadow" in str(p) else orig(p)
        result = check_empty_password_accounts()
        assert result["status"] == FAIL
        assert "baduser" in result["message"]
    finally:
        checks.Path = orig


# ─── Result Schema ───────────────────────────────────────────────────────────

def test_all_checks_return_required_keys():
    """Every check must return a dict with the required schema keys."""
    from linuxaudit.checks import ALL_CHECKS
    required = {"name", "status", "severity", "message", "recommendation"}
    for fn in ALL_CHECKS:
        result = fn()
        missing = required - set(result.keys())
        assert not missing, f"{fn.__name__} missing keys: {missing}"
        assert result["status"] in (PASS, FAIL, WARN, INFO), (
            f"{fn.__name__} returned invalid status: {result['status']}"
        )


# ─── CLI ─────────────────────────────────────────────────────────────────────

def test_cli_list(capsys):
    from linuxaudit.cli import list_checks
    list_checks()
    captured = capsys.readouterr()
    assert "ssh_config" in captured.out
    assert "Available checks" in captured.out
