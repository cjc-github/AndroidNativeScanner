"""Top-level analysis runtime."""

from time import perf_counter
from uuid import uuid4

from ..analyzer import AnalysisContext, AnalyzerRegistry, CancellationToken
from ..models import AnalysisStatus, AnalysisTarget, ScanResult
from ..rules import RuleEngine
from .aggregator import ResultAggregator
from .cache import RuntimeCache
from .planner import DependencyPlanner
from .progress import (
    KIND_ANALYZER_FINISH,
    KIND_RUN_FINISH,
    KIND_RUN_START,
    ProgressEvent,
    ProgressObserver,
    emit,
)
from .scheduler import DAGScheduler


class AnalysisRuntime:
    def __init__(
        self,
        registry: AnalyzerRegistry,
        planner: DependencyPlanner | None = None,
        scheduler: DAGScheduler | None = None,
        aggregator: ResultAggregator | None = None,
        rule_engine: RuleEngine | None = None,
    ) -> None:
        self.registry = registry
        self.planner = planner or DependencyPlanner()
        self.scheduler = scheduler or DAGScheduler()
        self.aggregator = aggregator or ResultAggregator()
        self.rule_engine = rule_engine or RuleEngine()

    def execute(
        self,
        target: AnalysisTarget,
        analyzer_ids: tuple[str, ...] | list[str],
        config: object,
        profile: str | None = None,
        observer: ProgressObserver | None = None,
        cancellation: CancellationToken | None = None,
    ) -> ScanResult:
        plan = self.planner.build(analyzer_ids, self.registry)
        context = AnalysisContext(
            run_id=str(uuid4()),
            target=target,
            config=config,
            cancellation=cancellation or CancellationToken(),
        )
        started = perf_counter()
        emit(
            observer,
            ProgressEvent(
                kind=KIND_RUN_START,
                total_analyzers=len(plan.resolved),
                completed_analyzers=0,
            ),
        )
        cache = RuntimeCache(config) if getattr(config, "cache_enabled", False) else None
        if cache:
            for analyzer_id in plan.resolved:
                analyzer = self.registry.get(analyzer_id)
                if not analyzer.metadata.cacheable:
                    # The result depends on host or configuration state the key
                    # does not cover, so it must never be replayed.
                    continue
                cached = cache.get(
                    target,
                    analyzer_id,
                    analyzer.metadata.version,
                    _dependency_signature(analyzer, plan.resolved),
                )
                if cached is not None:
                    context.add_result(cached)
                    # A cache hit skips the scheduler, so report it here or the
                    # run would look silent for the analyzers it reused.
                    emit(
                        observer,
                        ProgressEvent(
                            kind=KIND_ANALYZER_FINISH,
                            analyzer_id=analyzer_id,
                            total_analyzers=len(plan.resolved),
                            completed_analyzers=len(context.results),
                            status=cached.status.value,
                            duration_ms=cached.duration_ms,
                            message="cache hit",
                        ),
                    )
        self.scheduler.run(
            plan,
            self.registry,
            context,
            getattr(config, "jobs", 1),
            observer,
            getattr(config, "timeout_seconds", None),
        )
        self._attach_text_outputs(context)
        if cache:
            for result in context.results.values():
                if (
                    result.status == AnalysisStatus.SUCCESS
                    and not result.cache_hit
                    and self.registry.get(result.analyzer_id).metadata.cacheable
                ):
                    cache.put(
                        target,
                        result,
                        _dependency_signature(
                            self.registry.get(result.analyzer_id), plan.resolved
                        ),
                    )
        self.rule_engine.evaluate(context)
        duration_ms = int((perf_counter() - started) * 1000)
        emit(
            observer,
            ProgressEvent(
                kind=KIND_RUN_FINISH,
                total_analyzers=len(plan.resolved),
                completed_analyzers=len(context.results),
                duration_ms=duration_ms,
            ),
        )
        return self.aggregator.aggregate(context, plan, duration_ms, profile)

    def _attach_text_outputs(self, context: AnalysisContext) -> None:
        """Populate each result's ``text`` via the owning analyzer's ``format_text``.

        ``text`` is a human-readable summary of one analyzer's own output. It is
        carried into the JSON payload so web clients (and any other consumer of
        the scan document) can render it without re-implementing the layout; the
        CLI's own ``--format text`` report is produced separately by
        :mod:`soinsight.renderers.text_renderer` and does not read this field.

        Best-effort by design: an analyzer without ``format_text``, or a failure
        while formatting, leaves the field empty instead of failing the analysis.
        """
        for analyzer_id, result in context.results.items():
            if result.text:
                continue
            analyzer = self.registry.get(analyzer_id)
            if analyzer is None:
                continue
            formatter = getattr(analyzer, "format_text", None)
            if not callable(formatter):
                continue
            try:
                rendered = formatter(result)
            except Exception:  # pragma: no cover - 环境相关的兜底
                continue
            if rendered:
                result.text = rendered


def _dependency_signature(analyzer, planned: tuple[str, ...]) -> str:
    """Cache-key component naming the optional dependencies that took part."""
    optional = getattr(analyzer.metadata, "optional_requires", ())
    participants = tuple(sorted(dep for dep in optional if dep in planned))
    return ",".join(participants)
