from __future__ import annotations
from abc import ABC, abstractmethod
from forensics_copilot.model import DetectedFile

class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, file: DetectedFile) -> None:
        pass