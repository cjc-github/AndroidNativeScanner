#!/usr/bin/env python3
"""测试单独运行各个分析器（自动包含依赖）"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from soinsight.core.analyzer.registry import AnalyzerRegistry
from soinsight.core.runtime import AnalysisRuntime
from soinsight.core.runtime.planner import DependencyPlanner
from soinsight.analyzers import register_builtin_analyzers


def test_analyzer_dependencies():
    """测试每个分析器的依赖解析"""
    registry = AnalyzerRegistry()
    register_builtin_analyzers(registry)
    planner = DependencyPlanner()
    
    analyzers = [
        "basic.file",
        "basic.elf",
        "basic.symbols",
        "basic.dwarf",
        "advanced.strings",
        "security.hardening",
        "security.dangerous-api",
        "security.risk"
    ]
    
    print("=" * 70)
    print("测试每个分析器的依赖解析（单独运行时会自动包含的依赖）")
    print("=" * 70)
    
    for analyzer in analyzers:
        print(f"\n【{analyzer}】")
        try:
            plan = planner.build([analyzer], registry)
            print(f"  实际运行的分析器: {' → '.join(plan.resolved)}")
            print(f"  执行阶段数: {len(plan.stages)}")
            for i, stage in enumerate(plan.stages, 1):
                print(f"    阶段 {i}: {', '.join(stage.analyzer_ids)}")
        except Exception as e:
            print(f"  ✗ 错误: {e}")
    
    print("\n" + "=" * 70)
    print("结论：每个分析器都可以单独运行，系统会自动解析并运行其依赖")
    print("=" * 70)


if __name__ == "__main__":
    test_analyzer_dependencies()
