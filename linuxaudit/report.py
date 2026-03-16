"""Report generation: terminal (colorized) and JSON output."""

import json
import sys
from datetime import datetime
from typing import Any

# ANSI color codes
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

STATUS_STYLE = {
    "PASS": (GREEN,  "✔"),
    "FAIL": (RED,    "✖"),
    "WARN": (YELLOW, "⚠"),
    "INFO": (CYAN,   "ℹ"),
}


def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _colored(text: str, color: str) -> str:
    if _supports_color():
        return f"{color}{text}{RESET}"
    return text


def print_banner() -> None:
    banner = r"""
  _     _                  ____                      _ _
 | |   (_)_ __  _   ___  / ___|  ___  ___ _   _ _ __(_) |_ _   _
 | |   | | '_ \| | | \ \/ /\___ \/ _ \/ __| | | | '__| | __| | | |
 | |___| | | | | |_| |>  <  ___) |  __/ (__| |_| | |  | | |_| |_| |
 |_____|_|_| |_|\__,_/_/\_\|____/ \___|\___|\__,_|_|  |_|\__|\__, |
                                                               |___/
    Linux Security Auditor v1.0.0  —  Open Source Security Checks
"""
    print(_colored(banner, CYAN))


def print_result(result: dict[str, Any], verbose: bool = False) -> None:
    status = result["status"]
    color, icon = STATUS_STYLE.get(status, ("", "?"))
    label = _colored(f"[{icon} {status:<4}]", color)
    name  = _colored(result["name"], BOLD)
    print(f"  {label}  {name}")
    print(f"         {_colored(result['message'], DIM)}")
    if verbose or status in ("FAIL", "WARN"):
        rec = result["recommendation"]
        print(f"         {_colored('→ ' + rec, YELLOW)}")
    print()


def print_summary(results: list[dict[str, Any]]) -> None:
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    warned = sum(1 for r in results if r["status"] == "WARN")
    infos  = sum(1 for r in results if r["status"] == "INFO")

    print(_colored("─" * 60, DIM))
    print(_colored(f"  SUMMARY  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", BOLD))
    print(_colored("─" * 60, DIM))
    print(f"  Total checks : {total}")
    print(f"  {_colored(f'Passed  : {passed}', GREEN)}")
    print(f"  {_colored(f'Warnings: {warned}', YELLOW)}")
    print(f"  {_colored(f'Failed  : {failed}', RED)}")
    print(f"  {_colored(f'Info    : {infos}', CYAN)}")
    print()

    if failed == 0 and warned == 0:
        print(_colored("  🎉 System passes all security checks!", GREEN))
    elif failed > 0:
        print(_colored(f"  ⚠  Address {failed} critical issue(s) above.", RED))
    else:
        print(_colored(f"  ⚠  Review {warned} warning(s) above.", YELLOW))
    print()


def save_json_report(results: list[dict[str, Any]], path: str) -> None:
    report = {
        "generated_at": datetime.now().isoformat(),
        "tool": "linux-security-auditor",
        "version": "1.0.0",
        "total": len(results),
        "passed": sum(1 for r in results if r["status"] == "PASS"),
        "failed": sum(1 for r in results if r["status"] == "FAIL"),
        "warnings": sum(1 for r in results if r["status"] == "WARN"),
        "results": results,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(_colored(f"  📄 Report saved to: {path}", CYAN))
