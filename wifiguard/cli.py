"""
WiFiGuard command-line interface.
"""

from __future__ import annotations

import argparse

from .reports import save_csv, save_json
from .risk import assess
from .scanner import ScannerError, WiFiScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifiguard",
        description=(
            "Passive Wi-Fi security intelligence and "
            "rogue-access-point awareness."
        ),
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Wireless interface to scan.",
    )

    parser.add_argument(
        "--json",
        help="Save results as JSON.",
    )

    parser.add_argument(
        "--csv",
        help="Save results as CSV.",
    )

    return parser


def print_results(access_points) -> None:
    print()
    print("WiFiGuard v0.1.0")
    print("=" * 78)

    print(
        f"{'SSID':25} "
        f"{'BSSID':18} "
        f"{'CH':>4} "
        f"{'SIGNAL':>7} "
        f"{'SECURITY':12} "
        f"{'RISK':9}"
    )

    print("-" * 78)

    for ap in access_points:
        risk = assess(ap)

        print(
            f"{ap.ssid[:25]:25} "
            f"{ap.bssid:18} "
            f"{str(ap.channel or '-'):>4} "
            f"{str(ap.signal or '-'):>7} "
            f"{ap.security[:12]:12} "
            f"{risk.level:9}"
        )

    print("-" * 78)

    total = len(access_points)
    open_count = sum(
        ap.security.upper() == "OPEN"
        for ap in access_points
    )

    print(f"Networks detected : {total}")
    print(f"Open networks     : {open_count}")
    print()


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    scanner = WiFiScanner(args.interface)

    try:
        access_points = scanner.scan()
    except ScannerError as exc:
        parser.error(str(exc))
        return 1

    if not access_points:
        print("No wireless networks detected.")
        return 0

    print_results(access_points)

    if args.json:
        save_json(access_points, args.json)
        print(f"JSON report saved to: {args.json}")

    if args.csv:
        save_csv(access_points, args.csv)
        print(f"CSV report saved to: {args.csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
