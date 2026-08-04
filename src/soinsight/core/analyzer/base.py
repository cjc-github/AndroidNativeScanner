"""Analyzer extension contract."""

from abc import ABC, abstractmethod

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
