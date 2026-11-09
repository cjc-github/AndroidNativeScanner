"""``dynamic.arguments``: plan a runtime argument capture.

The collector would record the arguments a chosen entry point receives and
the value it returns. The static side of the capability is the list of
candidate entry points and the sampling points worth watching, both derived
from the recovered symbol table.
"""

from ..core.analyzer import AnalyzerMetadata
from .dynamic_collectors import DynamicCollectorAnalyzer

ANALYZER_ID = "dynamic.arguments"

#: How many candidate entry points are reported.
_MAX_ENTRY_POINTS = 50


class DynamicArgumentsAnalyzer(DynamicCollectorAnalyzer):
    """Plan a sandboxed argument capture."""

    collector_kind = "arguments"

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Runtime Argument Capture",
        version="1.0.0",
        description="Plan a sandboxed capture of the arguments an entry point receives.",
        requires=(),
        optional_requires=("basic.symbols",),
        default_enabled=True,
        cacheable=False,
    )

    def collect_facts(self, context) -> dict:
        entry_points: list[dict] = []
        symbols = context.optional("basic.symbols")
        if symbols is not None:
            for record in (symbols.data or {}).get("functions") or ():
                entry_points.append(
                    {
                        "name": record.get("name"),
                        "signature": record.get("signature"),
                        "language": record.get("language"),
                        "address": record.get("address"),
                        "parameters": len(record.get("parameters") or ()),
                    }
                )
                if len(entry_points) >= _MAX_ENTRY_POINTS:
                    break

        sampling_points = []
        for item in entry_points:
            if item.get("parameters"):
                sampling_points.append(
                    {
                        "entrypoint": item.get("name"),
                        "points": [f"arg{index}" for index in range(item["parameters"])],
                    }
                )
        return {
            "entry_points": entry_points,
            "entry_point_count": len(entry_points),
            "sampling_points": sampling_points,
        }

    def _default_entrypoint(self, context) -> str:
        symbols = context.optional("basic.symbols")
        if symbols is None:
            return ""
        for record in (symbols.data or {}).get("functions") or ():
            name = record.get("name")
            if name:
                return str(name)
        return ""

    def harness_arguments(self, context) -> tuple[str, ...]:
        symbols = context.optional("basic.symbols")
        if symbols is None:
            return ()
        for record in (symbols.data or {}).get("functions") or ():
            signature = str(record.get("signature") or "")
            if "(" in signature and signature.endswith(")"):
                return (signature,)
        return ()

    def fact_lines(self, data: dict) -> list[tuple[str, object]]:
        return [
            ("候选入口", f"{data.get('entry_point_count', 0)} 个"),
            ("采样点", f"{len(data.get('sampling_points') or ())} 处"),
        ]
