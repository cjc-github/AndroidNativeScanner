"""Progress reporting for analysis runs.

The runtime executes analyzers synchronously, so anything that wants to show
what is happening — a terminal progress line, a web UI log stream, a CI
heartbeat — needs a hook. ``ProgressObserver`` is that hook: the runtime calls
it at run, stage and analyzer boundaries.

Every method defaults to doing nothing, so an observer implements only what it
renders. Observers must be cheap and must not raise: an exception escaping into
the scheduler would abort the run, so the runtime wraps calls defensively.
"""

from abc import ABC
from dataclasses import dataclass

from ..models import AnalysisResult

KIND_RUN_START = "run_start"
KIND_STAGE_START = "stage_start"
KIND_ANALYZER_START = "analyzer_start"
KIND_ANALYZER_FINISH = "analyzer_finish"
KIND_RUN_FINISH = "run_finish"


@dataclass(frozen=True)
class ProgressEvent:
    """A single progress notification.

    ``stage_index`` is ``-1`` for run-level events. ``total_analyzers`` counts
    the analyzers in the plan; ``completed_analyzers`` counts finished ones.
    """

    kind: str
    analyzer_id: str = ""
    stage_index: int = -1
    stage_size: int = 0
    total_analyzers: int = 0
    completed_analyzers: int = 0
    status: str = ""
    duration_ms: int = 0
    message: str = ""


class ProgressObserver(ABC):
    """Receives progress events. All hooks are optional."""

    def on_run_start(self, event: ProgressEvent) -> None:
        """Called once before the first stage."""

    def on_stage_start(self, event: ProgressEvent) -> None:
        """Called before each execution stage."""

    def on_analyzer_start(self, event: ProgressEvent) -> None:
        """Called before an analyzer runs."""

    def on_analyzer_finish(self, event: ProgressEvent) -> None:
        """Called after an analyzer produced a result, including failures."""

    def on_run_finish(self, event: ProgressEvent) -> None:
        """Called once after the last stage, before results are aggregated."""


def emit(observer: ProgressObserver | None, event: ProgressEvent) -> None:
    """Deliver ``event`` to ``observer``, swallowing observer failures.

    A broken observer must never take down an analysis run: progress is
    diagnostic output, not part of the result.
    """
    if observer is None:
        return
    handler = {
        KIND_RUN_START: observer.on_run_start,
        KIND_STAGE_START: observer.on_stage_start,
        KIND_ANALYZER_START: observer.on_analyzer_start,
        KIND_ANALYZER_FINISH: observer.on_analyzer_finish,
        KIND_RUN_FINISH: observer.on_run_finish,
    }.get(event.kind)
    if handler is None:
        return
    try:
        handler(event)
    except Exception:  # noqa: BLE001 - progress must never break a run.
        pass
