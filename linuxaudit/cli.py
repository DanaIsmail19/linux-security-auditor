#!/usr/bin/env python3
"""
Linux Security Auditor — CLI entry point.

Usage:
    linuxaudit                        Run all security checks
    linuxaudit --verbose              Show recommendations for every check
    linuxaudit --json report.json     Save report as JSON
    linuxaudit --check ssh_config     Run only the SSH check
    linuxaudit --list                 List all available checks

    linuxaudit --apparmor nginx                      Generate AppArmor profile
    linuxaudit --apparmor /usr/bin/python3           Generate by full path
    linuxaudit --apparmor sshd --output /tmp/sshd    Save to specific file
    linuxaudit --apparmor curl --print               Print profile to stdout
"""

import argparse
import sys

from linuxaudit.checks import ALL_CHECKS
from linuxaudit.report import (
    print_banner, print_result, print_summary, save_json_report,
    _colored, CYAN, GREEN, YELLOW, RED, BOLD, DIM,
)


def list_checks() -> None:
    print("\n  Available checks:\n")
    for fn in ALL_CHECKS:
        short = fn.__name__.replace("check_", "")
        doc   = (fn.__doc__ or "").strip().split("\n")[0]
        print(f"    {short:<30} {doc}")
    print()


def run_apparmor(args: argparse.Namespace) -> int:
    from linuxaudit.apparmor_gen import build_apparmor_profile

    target = args.apparmor
    output = getattr(args, "output", None)

    print_banner()
    print(f"  {_colored('AppArmor Profile Generator', BOLD)}\n")
    print(f"  Target  : {_colored(target, CYAN)}")

    result = build_apparmor_profile(target, output_path=output)

    if result["status"] == "FAIL":
        print(f"  {_colored('ERROR', RED)}: {result['message']}\n")
        return 2

    binary   = result["binary"]
    category = result["category"]
    libs     = result["linked_libs"]
    running  = result["is_running"]
    out_path = result["output_path"]

    print(f"  Binary  : {_colored(binary, GREEN)}")
    print(f"  Category: {_colored(category, CYAN)}")
    print(f"  Libs    : {len(libs)} linked libraries detected")
    print(f"  Running : {'yes — live process found' if running else 'no'}")
    print(f"  Output  : {_colored(out_path, YELLOW)}")
    print()

    profile_name = binary.lstrip("/").replace("/", ".")
    print(_colored("  Next steps:", BOLD))
    print(f"    1. Review the profile:         cat {out_path}")
    print(f"    2. Test in complain mode first: sudo aa-complain {binary}")
    print(f"    3. Copy to apparmor.d:          sudo cp {out_path} /etc/apparmor.d/{profile_name}")
    print(f"    4. Load the profile:            sudo apparmor_parser -r /etc/apparmor.d/{profile_name}")
    print(f"    5. Check status:                sudo aa-status | grep {profile_name[:20]}")
    print()

    if getattr(args, "print_profile", False):
        print(_colored("  ── Profile ─────────────────────────────────────────", DIM))
        print()
        for line in result["profile"].splitlines():
            if line.startswith("#"):
                print(_colored("  " + line, DIM))
            elif "deny" in line:
                print(_colored("  " + line, YELLOW))
            elif line.strip().endswith("{") or line.strip() == "}":
                print(_colored("  " + line, CYAN))
            else:
                print("  " + line)
        print()
        print(_colored("  ────────────────────────────────────────────────────", DIM))
        print()

    print(_colored(f"  Profile written to: {out_path}", GREEN))
    print()
    return 0


def run(args: argparse.Namespace) -> int:
    print_banner()

    if args.check:
        requested = {c.lower() for c in args.check}
        checks = [
            fn for fn in ALL_CHECKS
            if fn.__name__.replace("check_", "").lower() in requested
        ]
        if not checks:
            print(f"  No check matched: {args.check}. Use --list to see options.\n")
            return 1
    else:
        checks = ALL_CHECKS

    print(f"  Running {len(checks)} check(s)...\n")

    results = []
    for fn in checks:
        try:
            result = fn()
        except Exception as exc:
            result = {
                "name": fn.__name__,
                "status": "INFO",
                "severity": "low",
                "message": f"Check raised an exception: {exc}",
                "recommendation": "Report this as a bug on GitHub.",
            }
        results.append(result)
        print_result(result, verbose=args.verbose)

    print_summary(results)

    if args.json:
        save_json_report(results, args.json)

    failed = any(r["status"] == "FAIL" for r in results)
    warned = any(r["status"] == "WARN" for r in results)
    return 2 if failed else (1 if warned else 0)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="linuxaudit",
        description="Linux Security Auditor — open source CLI security checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--verbose", "-v", action="store_true",
        help="Show recommendations for every check, not just failures.")
    parser.add_argument("--json", metavar="FILE",
        help="Save the full audit report as JSON to FILE.")
    parser.add_argument("--check", "-c", nargs="+", metavar="NAME",
        help="Run only the named check(s). Use --list to see names.")
    parser.add_argument("--list", "-l", action="store_true",
        help="List all available checks and exit.")
    parser.add_argument("--apparmor", "-a", metavar="BINARY",
        help="Generate an AppArmor profile for BINARY (name or full path).")
    parser.add_argument("--output", "-o", metavar="FILE",
        help="Write the AppArmor profile to FILE (used with --apparmor).")
    parser.add_argument("--print", dest="print_profile", action="store_true",
        help="Print the generated AppArmor profile to stdout (used with --apparmor).")

    args = parser.parse_args()

    if args.list:
        list_checks()
        sys.exit(0)

    if args.apparmor:
        sys.exit(run_apparmor(args))

    sys.exit(run(args))


if __name__ == "__main__":
    main()
