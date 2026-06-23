# suggest.py

from __future__ import annotations
from forensics_copilot.model import Suggestion, DetectedFile

_CATEGORY_SUGGESTIONS: dict[str, list[tuple[str, str, str | None, int]]] = {
    "image": [
        ("Check image metadata (EXIF / hidden fields)", "Image file detected", "exiftool", 2),
        ("Check for image steganography (LSB / appended data)", "Image file detected", "binwalk + zsteg/stegsolve", 2),
        ("Scan for readable strings with strings", "Image file detected", "strings", 3),
    ],
    "pdf": [
        ("Check PDF metadata (author / creation time / producer)", "PDF file detected", "exiftool / pdfinfo", 2),
        ("Check whether the PDF embeds attachments or JavaScript", "PDF file detected", "pdf-parser / peepdf", 2),
    ],
    "pcap": [
        ("Inspect plaintext protocol traffic (HTTP/FTP, etc.) with tshark", "Network capture file detected", "tshark", 1),
        ("Try reconstructing the session with Wireshark's Follow Stream", "Network capture file detected", "wireshark", 2),
        ("Check for transferred files that can be exported (File > Export Objects)", "Network capture file detected", "tshark --export-objects", 2),
    ],
    "archive": [
        ("Check whether the archive is password-protected", "Archive file detected", None, 1),
        ("Check filenames for anomalies / hidden files", "Archive file detected", None, 2),
    ],
    "text": [
        ("Check text content for encoded strings (Base64/Hex, etc.)", "Text file detected", None, 2),
    ],
    "executable": [
        ("Check the executable's strings and import table", "Executable file detected", "strings / file / objdump", 2),
    ],
    "audio": [
        ("Check the audio file's spectrogram (may hide a pattern/Morse code)", "Audio file detected", "Sonic Visualiser / Audacity", 2),
        ("Check audio metadata", "Audio file detected", "exiftool", 3),
    ],
    "unknown": [
        ("File type not recognized — inspect structure with file/binwalk first", "Could not identify file type; may be a custom or obfuscated format", "binwalk", 1),
    ],
}

def gengerate_suggestions(detected_files: list[DetectedFile], start_id: int = 1) -> list[Suggestion]:
    suggestions: list[Suggestion] = []
    next_id = start_id

    for f in detected_files:
        if f.extension_mismatch:
            suggestions.append(Suggestion(
                id=next_id,
                target_file=f.path,
                action=f"File extension '{f.declared_ext}' does not match the detected MIME type '{f.detected_mime}'",
                reason="The file extension mismatches, it's a common spoofing technique.",
                tool_hint="file.",
                priority=1,
            ))
            next_id += 1

        for anomaly in f.anomalies:
            suggestions.append(Suggestion(
                id=next_id,
                target_file=f.path,
                action=f"Investigate anomaly: {anomaly.description}",
                reason="Suspicious file content detected.",
                tool_hint="binwalk" if "extra data" in anomaly.description else None,
                priority=1 if anomaly.severity in ("suspicious", "high") else 2,
            ))
            next_id += 1

        for action, reason, tool_hint, priority in _CATEGORY_SUGGESTIONS.get(f.category, []):
            suggestions.append(Suggestion(
                id=next_id,
                target_file=f.path,
                action=action,
                reason=reason,
                tool_hint=tool_hint,
                priority=priority,
            ))
            next_id += 1

    suggestions.sort(key=lambda s: (s.priority, s.id))
    return suggestions
