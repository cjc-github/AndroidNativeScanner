"""``dynamic.memory``: plan a runtime memory observation.

The collector would watch the memory the library touches: its own mapped
ranges, the heap and the stack. The static side of the capability is the
observation whitelist, derived from the recovered dynamic linking facts --
the libraries the image depends on and the search paths it uses.
"""

from ..core.analyzer import AnalyzerMetadata
from .dynamic_collectors import DynamicCollectorAnalyzer

ANALYZER_ID = "dynamic.memory"


class DynamicMemoryAnalyzer(DynamicCollectorAnalyzer):
    """Plan a sandboxed memory observation."""

    collector_kind = "memory"

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Runtime Memory Observation",
        version="1.0.0",
        description="Plan a sandboxed observation of the memory the library touches.",
        requires=(),
        optional_requires=("basic.dynamic",),
        default_enabled=True,
        cacheable=False,
    )

    def collect_facts(self, context) -> dict:
        observation_points: list[dict] = []
        dynamic = context.optional("basic.dynamic")
        if dynamic is not None:
            data = dynamic.data or {}
            for name in data.get("needed") or data.get("dependencies") or ():
                observation_points.append(
                    {
                        "kind": "dependency",
                        "name": str(name),
                        "detail": "依赖库映射，观察其加载地址与读写",
                    }
                )
            for path in data.get("rpath") or data.get("runpath") or ():
                observation_points.append(
                    {
                        "kind": "search-path",
                        "name": str(path),
                        "detail": "库搜索路径，决定会被加载的映射",
                    }
                )
        observation_points.extend(
            [
                {
                    "kind": "region",
                    "name": "/proc/<pid>/maps",
                    "detail": "进程映射表：所有可写映射的来源",
                },
                {
                    "kind": "region",
                    "name": "heap",
                    "detail": "堆：库自行分配的内存",
                },
                {
                    "kind": "region",
                    "name": "stack",
                    "detail": "栈：函数参数与返回地址",
                },
            ]
        )
        return {
            "observation_points": observation_points,
            "observation_count": len(observation_points),
        }

    def fact_lines(self, data: dict) -> list[tuple[str, object]]:
        return [("观测点", f"{data.get('observation_count', 0)} 处")]
