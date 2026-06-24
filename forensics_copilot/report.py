# report.py

from __future__ import annotations
from forensics_copilot.model import AnalysisReport

_CATEGORY= {
    "pcap": "pcap capture file",
    "image": "image file",
    "pdf": "PDF file",
    "archive": "archive file",
    "text": "text file",
    "executable": "executable file",
    "audio": "audio file",
    "video": "video file",
    "unknown": "unknown-type file",
}

_PRIORITY_LABELS = {1: "[High]", 2: "[Medium]", 3: "[Low]"}

def render_text_report(report: AnalysisReport) -> str:
    lines: list[str] = []
    lines.append(f"Analysis target: {report.input_path}")
    lines.append("")

    lines.append("Findings: ")
    if not report.detected_files:
        lines.append("No files were detected.")
    else:
        counts: dict[str, int] = {}
        for f in report.detected_files:
            counts[f.category] = counts.get(f.category, 0) + 1
        for category, count in counts.items():
            label = _CATEGORY.get(category, category)
            lines.append(f" - {count} {label}(s)")

        lines.append("")
        lines.append("File list: ")
        for f in report.detected_files:
            flag = ""
            if f.extension_mismatch:
                flag = " [Extension does not match actual type!]"
            origin = f" (extracted from {f.extracted_from})" if f.extracted_from else ""
            lines.append(f" - {f.path} [{f.detected_mime}] {f.size_bytes} bytes{flag}{origin}")
            for a in f.anomalies:
                marker = "🚩" if a.severity in ("suspicious", "high") else "·"
                lines.append(f"      {marker} {a.description}")

    lines.append("")
    lines.append("Suggestions: ")
    if not report.suggestions:
        lines.append("No suggestions were generated.")
    else:
        for idx, s in enumerate(report.suggestions, start=1):
            priority_label = _PRIORITY_LABELS.get(s.priority, "")
            tool = f" (tool: {s.tool_hint})" if s.tool_hint else ""
            lines.append(f" {idx}. {priority_label} [{s.target_file}] {s.action}{tool}")
            lines.append(f" Reason: {s.reason}")

    return "\n".join(lines)
