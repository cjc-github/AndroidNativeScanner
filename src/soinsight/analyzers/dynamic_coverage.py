"""``dynamic.coverage``: plan a runtime coverage collection.

Coverage is only useful when it can be lined up with the code the static
analysis recovered, so the collector's plan is anchored on the basic blocks
``basic.cfg`` found: each block start is a coverage id, and the edges
between them are the transitions a run may take.
"""

from ..core.analyzer import AnalyzerMetadata
from .dynamic_collectors import DynamicCollectorAnalyzer

ANALYZER_ID = "dynamic.coverage"

#: How many blocks are listed in the plan.
_MAX_BLOCKS = 500


class DynamicCoverageAnalyzer(DynamicCollectorAnalyzer):
    """Plan a sandboxed coverage collection."""

    collector_kind = "coverage"

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Runtime Coverage Collection",
        version="1.0.0",
        description="Plan a sandboxed coverage collection aligned with the recovered CFG.",
        requires=(),
        optional_requires=("basic.cfg",),
        default_enabled=True,
        cacheable=False,
    )

    def collect_facts(self, context) -> dict:
        cfg = context.optional("basic.cfg")
        coverage_map: list[dict] = []
        block_count = 0
        edge_count = 0
        if cfg is not None:
            for function in (cfg.data or {}).get("functions") or ():
                blocks = function.get("blocks") or ()
                block_count += len(blocks)
                edges = function.get("edges") or ()
                edge_count += len(edges)
                for block in blocks:
                    if len(coverage_map) >= _MAX_BLOCKS:
                        break
                    coverage_map.append(
                        {
                            "id": block.get("start"),
                            "function": function.get("name"),
                            "terminator": block.get("terminator"),
                            "successors": list(block.get("successors") or ()),
                        }
                    )
        return {
            "coverage_map": coverage_map,
            "block_count": block_count,
            "edge_count": edge_count,
            "aligned": bool(coverage_map),
        }

    def fact_lines(self, data: dict) -> list[tuple[str, object]]:
        return [
            ("基本块", f"{data.get('block_count', 0):,} 个"),
            ("边", f"{data.get('edge_count', 0):,} 条"),
            ("已对齐 CFG", "是" if data.get("aligned") else "否"),
        ]
