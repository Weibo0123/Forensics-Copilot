# analyzer.py

from __future__ import annotations
import os
import tempfile
import shutil
from forensics_copilot.identify import identify_file
from forensics_copilot.anomalies import run_anomaly_checks
from forensics_copilot.model import DetectedFile, Suggestion, AnalysisReport, Anomaly
from forensics_copilot.suggest import gengerate_suggestions
from forensics_copilot.extract import extract_file, MAX_RECURSION_DEPTH

def _analyze_single_file(
        abs_path: str,
        rel_path: str,
        extracted_from:str | None,
        depth: int,
        out_files: list[DetectedFile],
        temp_dirs: list[str],
) -> None:
    info = identify_file(abs_path, rel_path)
    detected = DetectedFile(extracted_from=extracted_from, **info)

    anomalies = run_anomaly_checks(abs_path, detected.category)
    detected.anomalies.extend(anomalies)
    out_files.append(detected)

    if detected.category == "archive":
        if depth < MAX_RECURSION_DEPTH:
            extract_desk = tempfile.mkdtemp(prefix="forensics_extract_")
            temp_dirs.append(extract_desk)
            result = extract_file(abs_path, extract_desk, detected.detected_mime)

            if result.success and result.extracted_to:
                for root, _dirs, files in os.walk(result.extracted_to):
                    for fname in files:
                        nested_abs = os.path.join(root, fname)
                        nested_rel = os.path.relpath(nested_abs, result.extracted_to)
                        nested_display = f"{rel_path}/{nested_rel}"
                        _analyze_single_file(nested_abs, nested_display, rel_path, depth + 1, out_files, temp_dirs)
            elif result.note:
                detected.anomalies.append(_extracted_note_to_anomaly(result.note))
        else:
            detected.anomalies.append(Anomaly(description=f"Reached maximum recursion depth ({MAX_RECURSION_DEPTH} levels); did not continue extracting this archive — its contents may not have been fully analyzed", severity="warning"))

def _extracted_note_to_anomaly(note: str) -> Anomaly:
    return Anomaly(description=note, severity="info")

def analyze(input_path: str) -> tuple[AnalysisReport, list[str]]:
    input_path = os.path.abspath(input_path)
    out_files: list[DetectedFile] = []
    temp_dirs: list[str] = []

    try:
        if os.path.isfile(input_path):
            rel_path = os.path.basename(input_path)
            _analyze_single_file(input_path, rel_path, None, 0, out_files, temp_dirs)
        elif os.path.isdir(input_path):
            for root, _dirs, files in os.walk(input_path):
                for fname in files:
                    abs_path = os.path.join(root, fname)
                    rel_path = os.path.relpath(abs_path, input_path)
                    _analyze_single_file(abs_path, rel_path, None, 0, out_files, temp_dirs)
        else:
            raise FileNotFoundError(f"The input path '{input_path}' does not exist or is not a file or directory.")

        suggestions = gengerate_suggestions(out_files)
        report = AnalysisReport(input_path=input_path, detected_files=out_files, suggestions=suggestions)
        return report, temp_dirs
    except Exception:
        for d in temp_dirs:
            _safe_rmtree(d)
        raise

def _safe_rmtree(path: str) -> None:
    try:
        shutil.rmtree(path)
    except OSError:
        pass
