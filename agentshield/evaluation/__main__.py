"""Run with python3 -m agentshield.evaluation [--output PATH]."""

import argparse
from pathlib import Path

from .runner import format_summary, run_evaluation, write_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate the local intentionally insecure baseline")
    parser.add_argument("--output", type=Path, help="Write a local JSON report")
    args = parser.parse_args()
    report = run_evaluation()
    print(format_summary(report))
    if args.output:
        write_report(report, args.output)
        print(f"JSON report: {args.output}")
    return 1 if report["totals"]["evaluation_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
