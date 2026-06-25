# cli.py

from __future__ import annotations
import argparse
import sys
import json
from forensics_copilot.model import SuggestionStatus
from forensics_copilot.execute import execute_suggestion, is_tool_wired
from forensics_copilot.analyzer import analyze, cleanup_temp_dirs
from forensics_copilot.report import render_text_report

def _prompt_and_execute(report, input_fn=input) -> None:
    runnable = [
        s for s in report.suggestions
        if is_tool_wired(s.tool_hint) and s.status == SuggestionStatus.PENDING
    ]

    if not runnable:
        return

    print(f"\n{len(runnable)} suggestion(s) have a tool available to run automatically.")
    print("For each one: [y] run it   [n] skip it   [q] stop asking (leave the rest as-is)\n")

    for s in runnable:
        try:
            answer = input_fn(f"Run '{s.tool_hint}' on {s.target_file}? [y/n/q]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nStopping... remaining suggestions left untouched.")
            break
        if answer == "q":
            print("Stooping... remaining suggestions left untouched. ")
            break
        if answer != "y":
            s.status = SuggestionStatus.REJECTED
            print(f"Skipping '{s.tool_hint}' on {s.target_file}.")
            continue

        execute_suggestion(report, s.id)
        print(f"  -> {s.status.value}")
        if s.result.error:
            print(f"  -> {s.result.error}")
        elif s.result.stdout.strip():
            for line in s.result.stdout.strip().splitlines()[:5]:
                print(f"     {line}")
            if s.result.stdout_truncated:
                print(f"     ... full output saved to {s.result.stdout_file}")
        print()

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
    parser.add_argument(
        "--flag-pattern",
        metavar="[NAME=]REGEX",
        action="append",
        default=None,
        help=(
            "Add a custom flag-format regex to scan for, in addition to the "
            "built-in flag{}/ctf{}/picoCTF{} patterns. Matched against raw "
            "bytes, case-insensitive. Repeatable. Optionally prefix with a "
            "name, e.g. --flag-pattern 'mybadctf=MBCTF\\{[^}]{1,300}\\}'."
        ),
    )
    parser.add_argument(
        "interactive",
        action="store_true",
        help=("After printing the report, ask once per suggestion whether to "
            "run its tool (y/n/q). Nothing runs without explicit per-suggestion confirmation."
        ),
    )

    args = parser.parse_args()

    custom_patterns: list[tuple[str, str]] = []
    for i, raw in enumerate(args.flag_pattern or [], start=1):
        name, _, pattern = raw.partition("=")
        if not pattern:
            name, pattern = f"custom{i}", raw
        custom_patterns.append((name, pattern))

    try:
        report, temp_dirs = analyze(args.input_path, custom_flag_patterns=custom_patterns or None)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(render_text_report(report))

    if args.interactive:
        _prompt_and_execute(report)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, ensure_ascii=False, indent=2, default=str)
        print(f"\nFull report saved to {args.json}.")

    cleanup_temp_dirs(temp_dirs)
    return 0

if __name__ == "__main__":
    sys.exit(main())
