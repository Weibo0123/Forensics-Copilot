# cli.py

from __future__ import annotations
import argparse
import sys
import json
from forensics_copilot.analyzer import analyze
from forensics_copilot.report import render_text_report

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="forensics-copilot",
        description="Automated analysis and suggestion tool for CTF forensics challenges"
    )
    parser.add_argument("input_path", help="Path to the file or directory to analyze")
    parser.add_argument(
        "--json",
        metavar="OUT_FILE",
        default=None,
        help="Save the full report as a JSON file"
    )
    args = parser.parse_args()

    try:
        report, _temp_dirs = analyze(args.input_path)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(render_text_report(report))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, ensure_ascii=False, indent=2, default=str)
        print(f"\nFull report saved to {args.json}.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
