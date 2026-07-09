# suggest.py

from __future__ import annotations
from typing import Callable, Union
from forensics_copilot.model import Suggestion, DetectedFile

TextOrFn = Union[str, Callable[[DetectedFile], str]]

def _resolve(value: TextOrFn, f: DetectedFile) -> str:
    return value(f) if callable(value) else value

_RULES: list[tuple[Callable[[DetectedFile], bool], TextOrFn, TextOrFn, str | None, int]] = [
    (
        lambda f: f.extension_mismatch,
        lambda f: f"File extension '{f.declared_ext}' does not match the detected MIME type '{f.detected_mime}'",
        "The file extension mismatches, it's a common spoofing technique.",
        "file",
        1,
    ),
    (
        lambda f: f.extension_mismatch or bool(f.anomalies) or f.category == "unknown",
        "View a raw hex dump of the file (check magic bytes / header structure)",
        "File type or structure looks suspicious — worth inspecting the raw bytes directly.",
        "xxd",
        2,
    ),
    (
        lambda f: bool(f.anomalies) or f.category in ("unknown", "archive"),
        "Compute byte-level entropy (high entropy may indicate encrypted/compressed/hidden data)",
        "Random-looking byte distributions are a common signature of encrypted or hidden payloads.",
        "ent",
        2,
    ),
    (
        lambda f: f.category == "archive" and f.detected_mime == "application/zip",
        "List archive contents without extracting (filenames, sizes, CRCs)",
        "ZIP archive detected — useful for spotting hidden or duplicate filenames before extracting anything.",
        "zipinfo",
        2,
    ),
    (
        lambda f: f.category == "image" and f.detected_mime == "image/png",
        "Validate PNG structure chunk-by-chunk",
        "PNG file detected — pngcheck catches malformed or extra chunks that a simple trailing-data check can miss.",
        "pngcheck",
        2,
    ),

    (lambda f: f.category == "image", "Check image metadata (EXIF / hidden fields)", "Image file detected", "exiftool", 2),
    (lambda f: f.category == "image", "Check for image steganography (LSB / appended data)", "Image file detected", "binwalk + zsteg/stegsolve", 2),
    (lambda f: f.category == "image", "Scan for readable strings with strings", "Image file detected", "strings", 3),

    (lambda f: f.category == "pdf", "Check PDF metadata (author / creation time / producer)", "PDF file detected", "exiftool / pdfinfo", 2),
    (lambda f: f.category == "pdf", "Check whether the PDF embeds attachments or JavaScript", "PDF file detected", "pdf-parser / peepdf", 2),

    (lambda f: f.category == "pcap", "Inspect plaintext protocol traffic (HTTP/FTP, etc.) with tshark", "Network capture file detected", "tshark", 1),
    (lambda f: f.category == "pcap", "Try reconstructing the session with Wireshark's Follow Stream", "Network capture file detected", "wireshark", 2),
    (lambda f: f.category == "pcap", "Check for transferred files that can be exported (File > Export Objects)", "Network capture file detected", "tshark --export-objects", 2),

    (lambda f: f.category == "archive", "Check whether the archive is password-protected", "Archive file detected", None, 1),
    (lambda f: f.category == "archive", "Check filenames for anomalies / hidden files", "Archive file detected", None, 2),

    (lambda f: f.category == "text", "Check text content for encoded strings (Base64/Hex, etc.)", "Text file detected", None, 2),

    (lambda f: f.category == "executable", "Check the executable's strings and import table", "Executable file detected", "strings / file / objdump", 2),

    (lambda f: f.category == "audio", "Run automated audio steganography detection (Morse code and more)", "Audio file detected — audio_analyzer automatically scans for Morse code patterns and other hidden audio signals.", "audio_analyzer", 1),
    (lambda f: f.category == "audio", "Manually inspect the spectrogram for visual patterns (e.g. images encoded in frequency)", "Audio file detected — some CTF challenges encode data visually in the spectrogram, which automated tools may not catch.", "Sonic Visualiser / Audacity", 2),
    (lambda f: f.category == "audio", "Check audio metadata", "Audio file detected", "exiftool", 3),

    (lambda f: f.category == "unknown", "File type not recognized — inspect structure with file/binwalk first", "Could not identify file type; may be a custom or obfuscated format", "binwalk", 1),
]

def gengerate_suggestions(detected_files: list[DetectedFile], start_id: int = 1) -> list[Suggestion]:
    suggestions: list[Suggestion] = []
    next_id = start_id

    for f in detected_files:
        if f.flag_matches:
            preview = ", ".join(fm.matched_text for fm in f.flag_matches[:3])
            if len(f.flag_matches) > 3:
                preview += f", ... (+{len(f.flag_matches) - 3} more)"
            suggestions.append(Suggestion(
                id=next_id,
                target_file=f.path,
                target_abs_path=f.abs_path,
                action=f"Candidate flag found: {preview}",
                reason="Matched a flag-format pattern against the file's raw bytes.",
                tool_hint=None,
                priority=0,
            ))
            next_id += 1

        for anomaly in f.anomalies:
            suggestions.append(Suggestion(
                id=next_id,
                target_file=f.path,
                target_abs_path=f.abs_path,
                action=f"Investigate anomaly: {anomaly.description}",
                reason="Suspicious file content detected.",
                tool_hint="binwalk" if ("trailing data" in anomaly.description or "additional data" in anomaly.description) else None,
                priority=1 if anomaly.severity in ("suspicious", "high") else 2,
            ))
            next_id += 1

        for predicate, action, reason, tool_hint, priority in _RULES:
            if not predicate(f):
                continue
            suggestions.append(Suggestion(
                id=next_id,
                target_file=f.path,
                target_abs_path=f.abs_path,
                action=_resolve(action, f),
                reason=_resolve(reason, f),
                tool_hint=tool_hint,
                priority=priority,
            ))
            next_id += 1

    suggestions.sort(key=lambda s: (s.priority, s.id))
    return suggestions