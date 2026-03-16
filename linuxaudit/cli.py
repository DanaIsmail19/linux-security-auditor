#!/usr/bin/env python3
"""
Linux Security Auditor — CLI entry point.

Usage:
    linuxaudit                  Run all checks
    linuxaudit --verbose        Show recommendations for all checks
    linuxaudit --json report.json   Save report as JSON
    linuxaudit --check ssh      Run only the SSH check
    linuxaudit --list           List all available checks
"""

import argparse
import sys

from linuxaudit.checks import ALL_CHECKS
from linuxaudit.report import print_banner, print_result, print_summary, save_json_report


def list_checks() -> None:
    print("\n  Available checks:\n")
    for fn in ALL_CHECKS:
        # Derive a short name from the function name: check_ssh_config -> ssh_config
        short = fn.__name__.replace("check_", "")
        doc   = (fn.__doc__ or "").strip().split("\n")[0]
        print(f"    {short:<30} {doc}")
    print()


def run(args: argparse.Namespace) -> int:
    print_banner()

    # Filter checks if --check flag was used
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

    print(f"  Running {len(checks)} check(s)…\n")

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

    # Exit code: 2 = failures, 1 = warnings only, 0 = all pass
    failed  = any(r["status"] == "FAIL" for r in results)
    warned  = any(r["status"] == "WARN" for r in results)
    return 2 if failed else (1 if warned else 0)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="linuxaudit",
        description="Linux Security Auditor — open source CLI security checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show recommendations for every check, not just failures.",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save the full report as JSON to FILE.",
    )
    parser.add_argument(
        "--check", "-c",
        nargs="+",
        metavar="NAME",
        help="Run only the named check(s). Use --list to see names.",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List all available checks and exit.",
    )

    args = parser.parse_args()

    if args.list:
        list_checks()
        sys.exit(0)

    sys.exit(run(args))


if __name__ == "__main__":
    main()
