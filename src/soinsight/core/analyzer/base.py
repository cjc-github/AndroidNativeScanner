"""Analyzer extension contract."""

from abc import ABC, abstractmethod
from typing import Optional

from ..models import AnalysisResult, AnalysisTarget
from .context import AnalysisContext
from .metadata import AnalyzerMetadata


class Analyzer(ABC):
    metadata: AnalyzerMetadata

    @abstractmethod
    def analyze(
        self,
        target: AnalysisTarget,
        context: AnalysisContext,
    ) -> AnalysisResult:
        """Analyze a target and return a normalized result."""

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format the analysis result as text.

        Override this method to provide custom text formatting.
        Returns None to use default formatting.
        """
        return None
