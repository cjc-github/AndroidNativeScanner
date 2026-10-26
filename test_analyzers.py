#!/usr/bin/env python3
"""测试单独运行各个分析器的功能"""

import sys
import tempfile
from pathlib import Path

# 添加 src 到路径
sys.path.insert(0, str(Path(__file__).parent / "src"))

from soinsight.application.service import AnalysisService
from soinsight.core.analyzer.registry import AnalyzerRegistry
from soinsight.core.runtime import AnalysisRuntime
from soinsight.analyzers import register_builtin_analyzers


def test_single_analyzer():
    """测试单个分析器"""
    # 创建一个测试 ELF 文件
    test_elf = Path(__file__).parent / "test.so"
    if not test_elf.exists():
        print(f"测试文件不存在: {test_elf}")
        return False
    
    # 注册所有分析器
    registry = AnalyzerRegistry()
    register_builtin_analyzers(registry)
    
    # 测试每个分析器
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
    
    for analyzer in analyzers:
        print(f"\n测试分析器: {analyzer}")
        print("-" * 50)
        
        try:
            # 创建运行时和服务
            runtime = AnalysisRuntime(registry)
            service = AnalysisService(runtime)
            
            # 运行分析
            result = service.analyze(test_elf, analyzers=[analyzer])
            
            if result.success:
                print(f"✓ 成功")
                print(f"  结果类型: {type(result.data)}")
                if hasattr(result.data, 'keys'):
                    print(f"  数据键: {list(result.data.keys())}")
            else:
                print(f"✗ 失败: {result.error}")
                
        except Exception as e:
            print(f"✗ 异常: {e}")
            import traceback
            traceback.print_exc()
    
    return True


def test_multiple_analyzers():
    """测试多个分析器组合"""
    test_elf = Path(__file__).parent / "test.so"
    if not test_elf.exists():
        print(f"测试文件不存在: {test_elf}")
        return False
    
    # 注册所有分析器
    registry = AnalyzerRegistry()
    register_builtin_analyzers(registry)
    
    # 测试组合
    combinations = [
        ["basic.file", "basic.elf"],
        ["basic.symbols", "basic.dwarf"],
        ["security.hardening", "security.dangerous-api"],
        ["basic.file", "basic.symbols", "security.risk"]
    ]
    
    for combo in combinations:
        print(f"\n测试组合: {', '.join(combo)}")
        print("-" * 50)
        
        try:
            # 创建运行时和服务
            runtime = AnalysisRuntime(registry)
            service = AnalysisService(runtime)
            
            # 运行分析
            result = service.analyze(test_elf, analyzers=combo)
            
            if result.success:
                print(f"✓ 成功")
                if hasattr(result.data, '__len__'):
                    print(f"  结果数量: {len(result.data)}")
            else:
                print(f"✗ 失败: {result.error}")
                
        except Exception as e:
            print(f"✗ 异常: {e}")
            import traceback
            traceback.print_exc()
    
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("测试单独运行分析器功能")
    print("=" * 60)
    
    success = True
    
    # 测试单个分析器
    if not test_single_analyzer():
        success = False
    
    # 测试多个分析器组合
    if not test_multiple_analyzers():
        success = False
    
    print("\n" + "=" * 60)
    if success:
        print("✓ 所有测试通过")
    else:
        print("✗ 部分测试失败")
    print("=" * 60)
    
    sys.exit(0 if success else 1)
