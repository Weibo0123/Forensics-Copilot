# execute.py

from __future__ import annotations
import importlib.util
import json
import subprocess
import tempfile
import os
import shutil
from forensics_copilot.model import AnalysisReport, Finding, Suggestion, SuggestionStatus, ExecutionResult

_TOOL_COMMANDS: dict[str, list[str]] = {
    "file": ["file", "--brief", "{target}"],
    "strings": ["strings", "-n", "6", "{target}"],
    "exiftool": ["exiftool", "{target}"],
    "xxd": ["xxd", "{target}"],
    "zipinfo": ["zipinfo", "-v", "{target}"],
    "pngcheck": ["pngcheck", "-v", "{target}"],
    "ent": ["ent", "{target}"],
    "audio_analyzer": ["python3", "-m", "audio_analyzer.cli", "{target}", "--json"],
    "zsteg": ["zsteg", "{target}"],
    "stegseek": ["stegseek", "--crack", "{target}"],
}

_INSTALL_HINTS: dict[str, str] = {
    "file": "install it via your OS package manager, e.g. 'apt install file' or 'brew install file'.",
    "strings": "it ships with binutils — install via 'apt install binutils' or 'brew install binutils'.",
    "exiftool": "install via 'apt install libimage-exiftool-perl' or 'brew install exiftool'.",
    "xxd": "ships by default on macOS; on Linux install via 'apt install xxd' (it's also bundled with vim).",
    "zipinfo": "ships alongside unzip — install via 'apt install unzip' or 'brew install unzip'.",
    "pngcheck": "install via 'apt install pngcheck' or 'brew install pngcheck'.",
    "ent": "install via 'apt install ent' or 'brew install ent'.",
    "zsteg":    "install via 'gem install zsteg' (requires Ruby).",
    "stegseek": "install via 'apt install stegseek' or download from https://github.com/RickdeJager/stegseek/releases.",
    "audio_analyzer": "install via 'pip install audio-analyzer' (or 'pip install -e path/to/audio_analyzer' for local dev).",
}

_PYTHON_MODULE_TOOLS: dict[str, str] = {
    "audio_analyzer": "audio_analyzer",
}

TIMEOUT_SECONDS = 15
MAX_INLINE_OUTPUT_BYTES = 4096
MAX_CAPTURED_OUTPUT_BYTES = 5 * 1024 * 1024

def _parse_plugin_findings(result: ExecutionResult, suggestion: Suggestion, module: str) -> None:
    try:
        payload = json.loads(result.stdout)
        for raw in payload.get("findings", []):
            result.findings.append(Finding(
                module=module,
                kind=raw.get("kind", "unknown"),
                confidence=float(raw.get("confidence", 0.0)),
                summary=raw.get("summary", ""),
                detail=raw.get("detail", {}),
                concluded_value=raw.get("concluded_value"),
                target_file=suggestion.target_file,
                target_abs_path=suggestion.target_abs_path,
            ))
    except Exception:
        pass

def _spill_to_disk(content: bytes, label: str) -> str:
    fd, path = tempfile.mkstemp(prefix=f"forensics_copilot_{label}_", suffix=".txt")
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return path

def _fail(suggestion: Suggestion, tool: str, command: list[str], error: str, timed_out: bool = False) -> Suggestion:
    suggestion.status = SuggestionStatus.FAILED
    suggestion.result = ExecutionResult(tool=tool, command=command, error=error, timed_out=timed_out)
    return suggestion

def _skip(suggestion: Suggestion, tool: str, error: str) -> Suggestion:
    suggestion.status = SuggestionStatus.SKIPPED
    suggestion.result = ExecutionResult(tool=tool, command=[], error=error)
    return suggestion

def _execute(suggestion: Suggestion) -> Suggestion:
    if not suggestion.tool_hint:
        return _skip(suggestion, "(none)", "This suggestion has no tool_hint — nothing to execute.")

    tool = suggestion.tool_hint
    template = _TOOL_COMMANDS.get(tool)
    if template is None:
        return _skip(suggestion, tool, f"'{tool}' is not wired up to the executor yet.")

    if tool in _PYTHON_MODULE_TOOLS:
        module_name = _PYTHON_MODULE_TOOLS[tool]
        if importlib.util.find_spec(module_name) is None:
            hint = _INSTALL_HINTS.get(tool, f"install the '{module_name}' Python package.")
            return _fail(suggestion, tool, [], f"Python package '{module_name}' is not installed — {hint}")
    else:
        binary = template[0]
        if shutil.which(binary) is None:
            hint = _INSTALL_HINTS.get(binary, f"'{binary}' was not found on PATH.")
            return _fail(suggestion, tool, [], f"'{binary}' is not installed or not on PATH — {hint}")

    target = suggestion.target_abs_path
    if not os.path.exists(target):
        return _fail(
            suggestion, tool, [],
            f"Target file no longer exists: {target} "
            "(if this came from inside an archive, the temp extraction dir it lived in may already be cleaned up)."
        )

    command = [arg.replace("{target}", target) for arg in template]

    try:
        proc = subprocess.run(command, capture_output=True, timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return _fail(suggestion, tool, command, f"Timed out after {TIMEOUT_SECONDS}s.", timed_out=True)
    except OSError as e:
        return _fail(suggestion, tool, command, f"Failed to launch '{command[0]}': {e}")

    raw_stdout = proc.stdout[:MAX_CAPTURED_OUTPUT_BYTES]
    raw_stderr = proc.stderr[:MAX_CAPTURED_OUTPUT_BYTES]

    result = ExecutionResult(tool=tool, command=command, returncode=proc.returncode)

    if len(raw_stdout) > MAX_INLINE_OUTPUT_BYTES:
        result.stdout_file = _spill_to_disk(raw_stdout, "stdout")
        result.stdout = raw_stdout[:MAX_INLINE_OUTPUT_BYTES].decode("utf-8", "replace")
        result.stdout_truncated = True
    else:
        result.stdout = raw_stdout.decode("utf-8", "replace")

    if len(raw_stderr) > MAX_INLINE_OUTPUT_BYTES:
        result.stderr_file = _spill_to_disk(raw_stderr, "stderr")
        result.stderr = raw_stderr[:MAX_INLINE_OUTPUT_BYTES].decode("utf-8", "replace")
        result.stderr_truncated = True
    else:
        result.stderr = raw_stderr.decode("utf-8", "replace")

    suggestion.result = result
    suggestion.status = SuggestionStatus.DONE if proc.returncode == 0 else SuggestionStatus.FAILED

    if tool in _PYTHON_MODULE_TOOLS and proc.returncode == 0:
        _parse_plugin_findings(result, suggestion, tool)

    return suggestion

def is_tool_wired(tool_hint: str | None) -> bool:
    return bool(tool_hint) and tool_hint in _TOOL_COMMANDS

def execute_suggestion(report: AnalysisReport, suggestion_id: int) -> Suggestion:
    suggestion = next((s for s in report.suggestions if s.id == suggestion_id), None)
    if suggestion is None:
        raise ValueError(f"No suggestion with id={suggestion_id} in this report.")
    return _execute(suggestion)
