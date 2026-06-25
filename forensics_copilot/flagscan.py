# flagscan.py

from __future__ import annotations
import re
from forensics_copilot.model import FlagMatch

_DEFAULT_PATTERNS: list[tuple[str, bytes]] = [
    ("flag{}", rb"flag\{[^}]{1,300}\}"),
    ("ctf{}", rb"ctf\{[^}]{1,300}\}"),
]


MAX_SCAN_BYTES = 50 * 1024 * 1024
MAX_MATCHES_PER_PATTERN = 20

def _compile_patterns(custom_patterns: list[tuple[str, str]] | None) -> list[tuple[str, re.Pattern]]:
    compiled: list[tuple[str, re.Pattern]] = []

    for name, pattern in _DEFAULT_PATTERNS:
        compiled.append((name, re.compile(pattern, re.IGNORECASE)))

    for name, pattern in (custom_patterns or []):
        try:
            compiled.append((name, re.compile(pattern.encode("utf-8", "ignore"), re.IGNORECASE)))
        except re.error:
            continue
    return compiled

def scan_for_flags(abs_path: str, custom_patterns: list[tuple[str, str]] | None = None,) -> list[FlagMatch]:
    try:
        with open(abs_path, "rb") as f:
            data = f.read(MAX_SCAN_BYTES)
    except OSError:
        return []

    matches: list[FlagMatch] = []
    seen: set[tuple[int, bytes]] = set()
    for name, regex in _compile_patterns(custom_patterns):
        count = 0
        for m in regex.finditer(data):
            if count >= MAX_MATCHES_PER_PATTERN:
                break
            key = (m.start(), m.group(0))
            if key in seen:
                continue
            seen.add(key)
            matches.append(FlagMatch(
                pattern_name=name,
                matched_text=m.group(0).decode("utf-8", "replace"),
                offset=m.start(),
            ))
            count += 1
    matches.sort(key=lambda m: m.offset)
    return matches