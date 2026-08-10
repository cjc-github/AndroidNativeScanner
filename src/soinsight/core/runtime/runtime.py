"""Top-level analysis runtime."""

from time import perf_counter
from uuid import uuid4

from ..analyzer import AnalysisContext, AnalyzerRegistry
from ..models import AnalysisStatus, AnalysisTarget, ScanResult
from ..rules import RuleEngine
from .aggregator import ResultAggregator
from .cache import RuntimeCache
from .planner import DependencyPlanner
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
    ) -> ScanResult:
        plan = self.planner.build(analyzer_ids, self.registry)
        context = AnalysisContext(
            run_id=str(uuid4()),
            target=target,
            config=config,
        )
        started = perf_counter()
        cache = RuntimeCache(config) if getattr(config, "cache_enabled", False) else None
        if cache:
            for analyzer_id in plan.resolved:
                analyzer = self.registry.get(analyzer_id)
                cached = cache.get(target, analyzer_id, analyzer.metadata.version)
                if cached is not None:
                    context.add_result(cached)
        self.scheduler.run(plan, self.registry, context, getattr(config, "jobs", 1))
        if cache:
            for result in context.results.values():
                if result.status == AnalysisStatus.SUCCESS and not result.cache_hit:
                    cache.put(target, result)
        self.rule_engine.evaluate(context)
        duration_ms = int((perf_counter() - started) * 1000)
        return self.aggregator.aggregate(context, plan, duration_ms, profile)
