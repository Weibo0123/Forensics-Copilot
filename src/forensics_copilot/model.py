# model.py

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any,Optional
import enum

class SuggestionStatus(str, enum.Enum):
    PENDING  = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    DONE     = "done"
    FAILED   = "failed"
    SKIPPED  = "skipped"

@dataclass()
class Anomaly:
    description: str                   # For human
    severity: str = "info"             # For machine / programming
    details: Optional[dict] = None     # Additional details like offset

@dataclass()
class DetectedFile:
    path:    str                       # For human
    abs_path: str                      # For machine / programming
    size_bytes: int
    declared_ext: str                  # File name extension, such as ".jpg" (not trustworthy)
    detected_mime: str                 # The MIME type given by python-magic
    detected_type_label: str           # The human-readable description provided by python-magic
    category: str
    extension_mismatch: bool = False
    anomalies: list[Anomaly] = field(default_factory=list)
    flag_matches: list[FlagMatch] = field(default_factory=list)
    sha256: Optional[str] = None
    extracted_from: Optional[str] = None

@dataclass()
class Suggestion:
    id: int                            # For AI to know which suggestion the user wants
    target_file: str
    target_abs_path: str
    action: str
    reason: str
    tool_hint: Optional[str] = None
    priority: int = 2                  # 1 = high, 2 = medium, 3 = low
    status: SuggestionStatus = SuggestionStatus.PENDING
    result: Optional[ExecutionResult] = None

@dataclass()
class AnalysisReport:
    """
    The Final Report of the Analysis
    """
    input_path: str
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    detected_files: list[DetectedFile] = field(default_factory=list)
    suggestions: list[Suggestion] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["generated_at"] = self.generated_at.isoformat()
        return d

@dataclass()
class FlagMatch:
    pattern_name: str
    matched_text: str
    offset: int


@dataclass()
class Finding:
    module: str
    kind: str
    confidence: float
    summary: str
    detail: dict = field(default_factory=dict)
    concluded_value: Optional[str] = None
    target_file: str = ""
    target_abs_path: str = ""

@dataclass()
class ExecutionResult:
    tool: str
    command: list[str]
    returncode: int = None
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    stdout_file: Optional[str] = None
    stderr_file: Optional[str] = None
    timed_out: bool = False
    error: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)