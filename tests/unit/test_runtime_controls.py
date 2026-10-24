"""Unit tests for analyzer timeout, cancellation and progress reporting."""

import time

import pytest

from soinsight.core.analyzer import AnalysisContext, Analyzer, AnalyzerMetadata
from soinsight.core.analyzer import AnalyzerRegistry
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.core.runtime import (
    AnalysisRuntime,
    DAGScheduler,
    ProgressEvent,
    ProgressObserver,
)
from soinsight.core.runtime.planner import DependencyPlanner
from soinsight.core.runtime.progress import emit
from soinsight.infrastructure.config import RuntimeConfig


class _RecordingAnalyzer(Analyzer):
    def __init__(self, analyzer_id: str, delay: float = 0.0) -> None:
        self.metadata = AnalyzerMetadata(
            id=analyzer_id, name=analyzer_id, version="1.0.0",
            timeout_seconds=60,
        )
        self._delay = delay

    def analyze(self, target, context):
        if self._delay:
            time.sleep(self._delay)
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={"delay": self._delay},
        )


class _HangingAnalyzer(Analyzer):
    def __init__(self) -> None:
        self.metadata = AnalyzerMetadata(
            id="basic.hang", name="Hang", version="1.0.0", timeout_seconds=1
        )

    def analyze(self, target, context):
        time.sleep(30)
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
        )


class _ExplodingAnalyzer(Analyzer):
    def __init__(self) -> None:
        self.metadata = AnalyzerMetadata(
            id="basic.explode", name="Explode", version="1.0.0"
        )

    def analyze(self, target, context):
        raise RuntimeError("boom")


def _target() -> AnalysisTarget:
    return AnalysisTarget(
        path=None, real_path=None, name="lib.so", size=0, sha256="test"
    )


def _registry(*analyzers: Analyzer) -> AnalyzerRegistry:
    registry = AnalyzerRegistry()
    registry.register_many(analyzers)
    return registry


# --- timeout -----------------------------------------------------------------


def test_scheduler_marks_slow_analyzer_as_timeout():
    registry = _registry(_HangingAnalyzer())
    context = AnalysisContext("run", _target(), RuntimeConfig())

    DAGScheduler().run(
        DependencyPlanner().build(("basic.hang",), registry),
        registry,
        context,
        jobs=1,
        timeout_seconds=1,
    )

    result = context.results["basic.hang"]
    assert result.status is AnalysisStatus.TIMEOUT
    assert result.diagnostics[0].code == "ANALYZER_TIMEOUT"
    assert result.diagnostics[0].details["timeout_seconds"] == 1
    assert result.duration_ms >= 900


def test_scheduler_uses_the_tighter_of_the_two_budgets():
    """A per-analyzer budget tighter than the run budget must win."""
    registry = _registry(_HangingAnalyzer())
    context = AnalysisContext("run", _target(), RuntimeConfig())

    DAGScheduler().run(
        DependencyPlanner().build(("basic.hang",), registry),
        registry,
        context,
        jobs=1,
        timeout_seconds=600,
    )

    result = context.results["basic.hang"]
    assert result.status is AnalysisStatus.TIMEOUT
    assert result.diagnostics[0].details["timeout_seconds"] == 1


def test_scheduler_completes_fast_analyzer_within_budget():
    registry = _registry(_RecordingAnalyzer("basic.file", delay=0.05))
    context = AnalysisContext("run", _target(), RuntimeConfig())

    DAGScheduler().run(
        DependencyPlanner().build(("basic.file",), registry),
        registry,
        context,
        jobs=1,
        timeout_seconds=30,
    )

    assert context.results["basic.file"].status is AnalysisStatus.SUCCESS


def test_scheduler_timeout_does_not_block_the_process():
    """The abandoned worker must be a daemon so the interpreter can exit."""
    import threading

    registry = _registry(_HangingAnalyzer())
    context = AnalysisContext("run", _target(), RuntimeConfig())
    before = threading.active_count()

    DAGScheduler().run(
        DependencyPlanner().build(("basic.hang",), registry),
        registry,
        context,
        jobs=1,
        timeout_seconds=1,
    )

    # The watchdog thread is still alive but is a daemon, so it cannot keep
    # the process from exiting.
    alive = [t for t in threading.enumerate() if t.name.startswith("soinsight-")]
    assert alive and all(thread.daemon for thread in alive)


def test_analyzer_exception_still_reported_as_failed():
    registry = _registry(_ExplodingAnalyzer())
    context = AnalysisContext("run", _target(), RuntimeConfig())

    DAGScheduler().run(
        DependencyPlanner().build(("basic.explode",), registry),
        registry,
        context,
        jobs=1,
        timeout_seconds=30,
    )

    result = context.results["basic.explode"]
    assert result.status is AnalysisStatus.FAILED
    assert result.diagnostics[0].code == "ANALYZER_EXCEPTION"


def test_runtime_honours_configured_timeout():
    registry = _registry(_HangingAnalyzer())
    runtime = AnalysisRuntime(registry)

    result = runtime.execute(
        target=_target(),
        analyzer_ids=("basic.hang",),
        config=RuntimeConfig(timeout_seconds=1),
    )

    assert result.results["basic.hang"].status is AnalysisStatus.TIMEOUT


# --- cancellation ------------------------------------------------------------


def test_cancelled_run_marks_remaining_analyzers():
    from soinsight.core.analyzer import CancellationToken

    registry = _registry(
        _RecordingAnalyzer("a.first"), _RecordingAnalyzer("z.second")
    )
    # Force two stages: the second analyzer depends on the first.
    dependent = _RecordingAnalyzer("z.second")
    dependent.metadata = AnalyzerMetadata(
        id="z.second", name="second", version="1.0.0", requires=("a.first",)
    )
    registry = _registry(_RecordingAnalyzer("a.first"), dependent)
    context = AnalysisContext(
        "run", _target(), RuntimeConfig(), cancellation=CancellationToken()
    )
    context.cancellation.cancel()

    DAGScheduler().run(
        DependencyPlanner().build(("z.second",), registry),
        registry,
        context,
        jobs=1,
        timeout_seconds=30,
    )

    assert context.results["a.first"].status is AnalysisStatus.CANCELLED
    assert context.results["z.second"].status is AnalysisStatus.CANCELLED


def test_runtime_accepts_an_external_cancellation_token():
    from soinsight.core.analyzer import CancellationToken

    registry = _registry(_RecordingAnalyzer("basic.file"))
    token = CancellationToken()
    token.cancel()

    result = AnalysisRuntime(registry).execute(
        target=_target(),
        analyzer_ids=("basic.file",),
        config=RuntimeConfig(),
        cancellation=token,
    )

    assert result.results["basic.file"].status is AnalysisStatus.CANCELLED


# --- progress ----------------------------------------------------------------


class _CollectingObserver(ProgressObserver):
    def __init__(self) -> None:
        self.events: list[ProgressEvent] = []

    def on_run_start(self, event: ProgressEvent) -> None:
        self.events.append(event)

    def on_stage_start(self, event: ProgressEvent) -> None:
        self.events.append(event)

    def on_analyzer_start(self, event: ProgressEvent) -> None:
        self.events.append(event)

    def on_analyzer_finish(self, event: ProgressEvent) -> None:
        self.events.append(event)

    def on_run_finish(self, event: ProgressEvent) -> None:
        self.events.append(event)


def test_runtime_emits_progress_events_in_order():
    registry = _registry(_RecordingAnalyzer("basic.file"))
    observer = _CollectingObserver()

    AnalysisRuntime(registry).execute(
        target=_target(),
        analyzer_ids=("basic.file",),
        config=RuntimeConfig(),
        observer=observer,
    )

    kinds = [event.kind for event in observer.events]
    assert kinds == [
        "run_start",
        "stage_start",
        "analyzer_start",
        "analyzer_finish",
        "run_finish",
    ]
    assert observer.events[0].total_analyzers == 1
    assert observer.events[3].status == "success"


def test_runtime_emits_progress_for_every_analyzer():
    registry = _registry(
        _RecordingAnalyzer("a.first"), _RecordingAnalyzer("b.second")
    )
    observer = _CollectingObserver()

    AnalysisRuntime(registry).execute(
        target=_target(),
        analyzer_ids=("a.first", "b.second"),
        config=RuntimeConfig(),
        observer=observer,
    )

    started = [e.analyzer_id for e in observer.events if e.kind == "analyzer_start"]
    finished = [e.analyzer_id for e in observer.events if e.kind == "analyzer_finish"]
    assert sorted(started) == ["a.first", "b.second"]
    assert sorted(finished) == ["a.first", "b.second"]


def test_progress_events_carry_stage_information():
    registry = _registry(
        _RecordingAnalyzer("a.first"), _RecordingAnalyzer("z.second")
    )
    dependent = _RecordingAnalyzer("z.second")
    dependent.metadata = AnalyzerMetadata(
        id="z.second", name="second", version="1.0.0", requires=("a.first",)
    )
    registry = _registry(_RecordingAnalyzer("a.first"), dependent)
    observer = _CollectingObserver()

    AnalysisRuntime(registry).execute(
        target=_target(),
        analyzer_ids=("z.second",),
        config=RuntimeConfig(),
        observer=observer,
    )

    stages = [e for e in observer.events if e.kind == "stage_start"]
    assert [stage.stage_index for stage in stages] == [0, 1]


def test_observer_defaults_are_noop():
    """An observer may implement only the hooks it renders."""
    class _Partial(ProgressObserver):
        def __init__(self) -> None:
            self.seen: list[str] = []

        def on_analyzer_finish(self, event: ProgressEvent) -> None:
            self.seen.append(event.analyzer_id)

    observer = _Partial()
    registry = _registry(_RecordingAnalyzer("basic.file"))

    AnalysisRuntime(registry).execute(
        target=_target(),
        analyzer_ids=("basic.file",),
        config=RuntimeConfig(),
        observer=observer,
    )

    assert observer.seen == ["basic.file"]


def test_broken_observer_never_breaks_the_run():
    class _Broken(ProgressObserver):
        def on_analyzer_start(self, event: ProgressEvent) -> None:
            raise RuntimeError("observer is broken")

    registry = _registry(_RecordingAnalyzer("basic.file"))

    result = AnalysisRuntime(registry).execute(
        target=_target(),
        analyzer_ids=("basic.file",),
        config=RuntimeConfig(),
        observer=_Broken(),
    )

    assert result.status is AnalysisStatus.SUCCESS


def test_emit_ignores_unknown_event_kinds():
    observer = _CollectingObserver()

    emit(observer, ProgressEvent(kind="not_a_real_kind"))

    assert observer.events == []


def test_emit_accepts_no_observer():
    emit(None, ProgressEvent(kind="run_start"))  # must not raise
