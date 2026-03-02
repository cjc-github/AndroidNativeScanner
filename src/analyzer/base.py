"""
分析器抽象基类模块
定义所有分析器的统一接口
"""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseAnalyzer(ABC):
    """所有 .so 文件分析器的抽象基类"""

    name: str = ""
    key: str = ""
    summary_key: str = ""

    @abstractmethod
    def analyze(self, so_file: str, **context) -> Any:
        """
        对 .so 文件执行分析

        Args:
            so_file: .so 文件路径
            **context: 可选的共享上下文，如 strings=<预提取的字符串列表>

        Returns:
            分析结果（格式由子类定义）
        """

    @abstractmethod
    def summarize(self, results: Any) -> Dict[str, Any]:
        """
        根据分析结果生成摘要

        Args:
            results: analyze() 的返回值

        Returns:
            包含 risk_score 的摘要字典
        """
