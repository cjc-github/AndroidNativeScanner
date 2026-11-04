"""``basic.jni``: the JNI registration table, static and dynamic.

The static half comes from ``basic.symbols``: every ``Java_*`` export is already
decoded there (package, class, method, parameter types). The dynamic half is
recovered here from the ``JNINativeMethod`` arrays that ``RegisterNatives``
consumes -- the name and signature strings and the function pointer of each
entry, with the relocation slots as evidence.

Both halves answer the same user question -- *which Java method reaches which
native code* -- so they are reported side by side. What the analyzer cannot see
it also says: a dynamic entry without a symbol name stays a bare address, and a
method name that is not fully qualified cannot reveal its Java class (the class
arrives through ``FindClass`` at run time).
"""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.elf import ElfFormatError, parse_elf
from ..infrastructure.jni_dynamic import find_dynamic_registrations

ANALYZER_ID = "basic.jni"

_DEFAULT_OPTIONS = {
    "max_registrations": 200,
}


class BasicJniAnalyzer(Analyzer):
    """Report the static and dynamic JNI registrations of an image."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="JNI Registration Analyzer",
        version="1.0.0",
        description="Recover the JNI registration table, static and dynamic.",
        requires=("basic.symbols",),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        diagnostics: list[Diagnostic] = []

        try:
            with open(target.real_path, "rb") as stream:
                blob = stream.read()
            elf = parse_elf(target.real_path)
        except (ElfFormatError, OSError) as exc:
            return AnalysisResult(
                analyzer_id=ANALYZER_ID,
                analyzer_version=self.metadata.version,
                status=AnalysisStatus.FAILED,
                diagnostics=[
                    Diagnostic(
                        code="JNI_INVALID_ELF",
                        level=DiagnosticLevel.ERROR,
                        message=str(exc),
                        analyzer_id=ANALYZER_ID,
                    )
                ],
            )

        report = find_dynamic_registrations(elf, blob)
        registrations = report.registrations

        if report.blocked_reason is not None:
            diagnostics.append(
                Diagnostic(
                    code="JNI_NO_DYNAMIC_REGISTRATION",
                    level=DiagnosticLevel.INFO,
                    message=report.blocked_reason,
                    analyzer_id=ANALYZER_ID,
                )
            )
        if report.unnamed_function_count:
            diagnostics.append(
                Diagnostic(
                    code="JNI_STRIPPED_FUNCTIONS",
                    level=DiagnosticLevel.WARNING,
                    message=(
                        f"{report.unnamed_function_count} 个被注册的函数没有符号名"
                        "（strip 过的镜像只能给出地址）。"
                    ),
                    analyzer_id=ANALYZER_ID,
                )
            )

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "static_count": _static_count(context),
                "dynamic_count": len(registrations),
                "dynamic_array_count": report.array_count,
                "on_load_present": report.on_load_present,
                "register_natives_imported": report.register_natives_imported,
                "dynamic_registrations": [
                    item.as_dict() for item in registrations
                ],
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """Format the JNI registration table as text."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== JNI 注册 ===",
            f"静态注册（Java_* 导出）: {data.get('static_count', 0)} 个",
            f"动态注册（RegisterNatives）: {data.get('dynamic_count', 0)} 个"
            f"（{data.get('dynamic_array_count', 0)} 个数组）",
        ]
        registrations = data.get("dynamic_registrations") or []
        if registrations:
            lines.append("")
            lines.append("动态注册表:")
            for item in registrations:
                name = item["method_name"]
                target = (
                    f"{item['function_symbol']}"
                    if item.get("function_named")
                    else f"{item['function_address']}（无符号名）"
                )
                lines.append(f"  {name}")
                lines.append(f"    签名: {item['signature']}")
                lines.append(f"    函数: {target}")
                if not item.get("qualified"):
                    lines.append("    （方法名为简名，所属 Java 类需 FindClass 才知道）")
        elif data.get("on_load_present") or data.get("register_natives_imported"):
            lines.append("（检测到 JNI_OnLoad/RegisterNatives，但未找到形似 JNINativeMethod 的数组）")
        return "\n".join(lines)


def _static_count(context) -> int:
    """Count the ``Java_*`` exports ``basic.symbols`` already decoded."""
    try:
        symbols = context.require("basic.symbols")
    except KeyError:
        return 0
    if symbols.status != AnalysisStatus.SUCCESS:
        return 0
    return int(symbols.data.get("jni_count", 0) or 0)
