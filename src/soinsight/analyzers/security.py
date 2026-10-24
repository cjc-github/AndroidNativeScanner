"""Built-in Security domain analyzers."""

from ..core.analyzer import Analyzer, AnalyzerKind, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Confidence,
    Diagnostic,
    DiagnosticLevel,
    Finding,
    Severity,
)


class SecurityHardeningAnalyzer(Analyzer):
    metadata = AnalyzerMetadata(
        id="security.hardening",
        name="Hardening Analyzer",
        version="1.0.0",
        description="Evaluate basic ELF hardening facts.",
        requires=("basic.elf",),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        del target
        elf_result = context.require("basic.elf")
        elf_data = elf_result.data
        findings: list[Finding] = []
        if elf_data.get("type") == "EXEC":
            findings.append(
                Finding(
                    rule_id="security.hardening.executable-elf",
                    rule_version="1.0.0",
                    title="Executable ELF lacks shared-object hardening baseline",
                    category="hardening",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    message="ELF type is EXEC rather than DYN; PIE hardening may be absent.",
                )
            )
        if elf_data.get("executable_stack") is True:
            findings.append(
                Finding(
                    rule_id="security.hardening.executable-stack",
                    rule_version="1.0.0",
                    title="Executable stack is enabled",
                    category="hardening",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    message="PT_GNU_STACK is executable; NX may be disabled.",
                )
            )
        if elf_data.get("has_gnu_relro") is False:
            findings.append(
                Finding(
                    rule_id="security.hardening.missing-relro",
                    rule_version="1.0.0",
                    title="GNU RELRO is not present",
                    category="hardening",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    message="No PT_GNU_RELRO segment found; relocation hardening may be absent.",
                )
            )
        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={"hardening_summary": {"finding_count": len(findings)}},
            findings=findings,
        )


# --- dangerous API rule table ------------------------------------------------
#
# The judgment is data, not code: each entry maps a symbol name to its
# category, severity and remediation. Matching is exact on the symbol name
# after normalising FORTIFY ("__strcpy_chk") and leading-underscore variants,
# so a substring can never produce a false hit.
#
# Deliberately excluded: ubiquitous primitives such as memcpy, memmove, memset,
# malloc, free and printf. They appear in every shared object, so reporting
# them would bury the findings that matter.

DANGEROUS_APIS: dict[str, tuple[str, Severity, str]] = {
    # 命令执行
    "system": ("命令执行", Severity.CRITICAL,
               "避免把不可信输入传给 system()；改用 execve 并显式传参数组。"),
    "popen": ("命令执行", Severity.CRITICAL,
              "popen 会经过 shell 解释；改用 posix_spawn 或 pipe+fork+exec。"),
    "execl": ("命令执行", Severity.HIGH, "确认参数来自可信来源，优先使用 execv 数组形式。"),
    "execlp": ("命令执行", Severity.HIGH, "确认参数来自可信来源，优先使用 execv 数组形式。"),
    "execle": ("命令执行", Severity.HIGH, "确认参数来自可信来源，优先使用 execv 数组形式。"),
    "execv": ("命令执行", Severity.HIGH, "确认参数来自可信来源且不做 shell 解释。"),
    "execvp": ("命令执行", Severity.HIGH, "确认参数来自可信来源且不做 shell 解释。"),
    "execvpe": ("命令执行", Severity.HIGH, "确认参数来自可信来源且不做 shell 解释。"),
    "execve": ("命令执行", Severity.HIGH, "确认参数来自可信来源且不做 shell 解释。"),
    "posix_spawn": ("命令执行", Severity.HIGH, "确认要执行的程序路径来自可信来源。"),
    "posix_spawnp": ("命令执行", Severity.HIGH, "确认要执行的程序路径来自可信来源。"),
    # 动态加载
    "dlopen": ("动态加载", Severity.HIGH,
               "dlopen 的路径必须来自可信来源；校验库的真实路径与签名。"),
    "dlsym": ("动态加载", Severity.HIGH,
              "通过 dlsym 获取的函数指针应做存在性与完整性校验。"),
    "dladdr": ("动态加载", Severity.LOW, "仅用于符号查询，确认不用于绕过校验。"),
    # 内存破坏
    "strcpy": ("内存破坏", Severity.HIGH,
               "改用 strncpy/strlcpy 并保证终止符；或启用 FORTIFY。"),
    "strcat": ("内存破坏", Severity.HIGH,
               "改用 strncat/strlcat 并保证终止符；或启用 FORTIFY。"),
    "sprintf": ("内存破坏", Severity.HIGH, "改用 snprintf 并传入缓冲区大小。"),
    "vsprintf": ("内存破坏", Severity.HIGH, "改用 vsnprintf 并传入缓冲区大小。"),
    "gets": ("内存破坏", Severity.CRITICAL, "gets 无法限制长度，必须替换为 fgets。"),
    "scanf": ("内存破坏", Severity.MEDIUM, "为 %s/%[ 指定字段宽度，或改用 fgets+解析。"),
    "sscanf": ("内存破坏", Severity.MEDIUM, "为 %s/%[ 指定字段宽度，或改用 fgets+解析。"),
    "alloca": ("内存破坏", Severity.MEDIUM, "alloca 分配不可校验，改用固定缓冲区或堆。"),
    # 权限操作
    "setuid": ("权限操作", Severity.HIGH, "确认提权路径不可被外部输入影响。"),
    "setgid": ("权限操作", Severity.HIGH, "确认提权路径不可被外部输入影响。"),
    "seteuid": ("权限操作", Severity.HIGH, "确认提权路径不可被外部输入影响。"),
    "setegid": ("权限操作", Severity.HIGH, "确认提权路径不可被外部输入影响。"),
    "setreuid": ("权限操作", Severity.HIGH, "确认提权路径不可被外部输入影响。"),
    "chmod": ("权限操作", Severity.MEDIUM, "确认目标路径与权限位来自可信来源。"),
    "chown": ("权限操作", Severity.MEDIUM, "确认目标路径与属主来自可信来源。"),
    "umask": ("权限操作", Severity.LOW, "确认不会放宽新建文件的默认权限。"),
    # 注入与反调试
    "ptrace": ("注入/反调试", Severity.HIGH,
               "ptrace 可用于注入或反调试；确认其用途符合产品预期。"),
    "process_vm_readv": ("注入/反调试", Severity.HIGH, "可读取其他进程内存，确认用途合法。"),
    "process_vm_writev": ("注入/反调试", Severity.HIGH, "可写入其他进程内存，确认用途合法。"),
    "mprotect": ("内存保护修改", Severity.HIGH,
                 "把内存改为可执行会削弱 NX；确认不是为了自修改代码。"),
    "mmap": ("内存映射", Severity.LOW, "确认未映射可执行段。"),
    # 进程与持久化
    "fork": ("进程创建", Severity.MEDIUM, "确认子进程不会继承不可信的执行上下文。"),
    "vfork": ("进程创建", Severity.MEDIUM, "vfork 语义危险，优先使用 fork 或 posix_spawn。"),
    "daemon": ("进程创建", Severity.LOW, "确认后台化行为符合产品预期。"),
    # 网络外联
    "socket": ("网络通信", Severity.LOW, "确认外联目标与传输内容符合隐私政策。"),
    "connect": ("网络通信", Severity.LOW, "确认外联目标与传输内容符合隐私政策。"),
    # 文件与痕迹
    "unlink": ("文件操作", Severity.LOW, "确认删除路径不可被外部输入控制。"),
    "remove": ("文件操作", Severity.LOW, "确认删除路径不可被外部输入控制。"),
    "rename": ("文件操作", Severity.LOW, "确认重命名路径不可被外部输入控制。"),
}

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_DEFAULT_OPTIONS = {
    "include_imports": True,
    "include_exports": True,
    "min_severity": "info",
}


class SecurityDangerousApiAnalyzer(Analyzer):
    """Detect dangerous APIs in a shared object's symbol table.

    Consumes the ``basic.symbols`` result: an imported dangerous API means the
    library can reach that behaviour, an exported one means it offers it to
    its callers. Both are facts about linkage rather than about a call site —
    the analyzer does not disassemble, so a match reports a capability, not a
    proof of use, and the confidence field says so.
    """

    metadata = AnalyzerMetadata(
        id="security.dangerous-api",
        name="Dangerous API Detection",
        version="1.0.0",
        description="Detect dangerous imported and exported APIs.",
        kind=AnalyzerKind.DETECTOR,
        requires=("basic.symbols",),
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        del target
        options = _resolve_options(context)
        symbols = context.require("basic.symbols")
        findings: list[Finding] = []
        matched: set[str] = set()

        if options["include_imports"]:
            for record in symbols.data.get("imports", []):
                matched |= self._inspect(record, options, findings, usage="import")
        if options["include_exports"]:
            for record in symbols.data.get("functions", []):
                matched |= self._inspect(record, options, findings, usage="export")

        return AnalysisResult(
            analyzer_id=self.metadata.id,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "matched_apis": sorted(matched),
                "finding_count": len(findings),
                "counts_by_severity": _count_by_severity(findings),
            },
            findings=findings,
            diagnostics=_stripped_diagnostic(self.metadata.id, symbols),
        )

    def _inspect(
        self,
        record: dict,
        options: dict,
        findings: list[Finding],
        *,
        usage: str,
    ) -> set[str]:
        name = record.get("name", "")
        if not name:
            return set()
        canonical = _canonical_symbol(name)
        rule = DANGEROUS_APIS.get(canonical)
        if rule is None:
            return set()
        category, severity, remediation = rule
        if _SEVERITY_ORDER[severity] < _SEVERITY_ORDER[options["min_severity"]]:
            return set()
        findings.append(
            Finding(
                rule_id=f"security.dangerous-api.{canonical}",
                rule_version=self.metadata.version,
                title=f"Dangerous API {usage}ed: {name}",
                category="dangerous-api",
                severity=severity,
                confidence=Confidence.HIGH,
                message=(
                    f"The library {usage}s '{name}' ({category}); "
                    f"the capability is reachable through this symbol."
                ),
                fingerprint=f"{canonical}:{usage}:{name}",
                evidence=(
                    {
                        "symbol": name,
                        "canonical_symbol": canonical,
                        "usage": usage,
                        "source": record.get("source", ".dynsym"),
                        "api_category": category,
                    },
                ),
                remediation=remediation,
            )
        )
        return {canonical}


def _canonical_symbol(name: str) -> str:
    """Normalise FORTIFY and leading-underscore variants for exact matching."""
    canonical = name
    if canonical.startswith("__") and not canonical.startswith("___"):
        canonical = canonical[2:]
    if canonical.endswith("_chk") and len(canonical) > 4:
        canonical = canonical[:-4]
    return canonical


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return counts


def _resolve_options(context) -> dict:
    """Read capability options with defaults, types and range enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(
        "security.dangerous-api", {}
    )
    resolved = dict(_DEFAULT_OPTIONS)
    for key in ("include_imports", "include_exports"):
        if key in declared:
            resolved[key] = bool(declared[key])
    if "min_severity" in declared:
        candidate = str(declared["min_severity"]).lower()
        if candidate in _SEVERITY_ORDER:
            resolved["min_severity"] = candidate
    return resolved


def _stripped_diagnostic(analyzer_id: str, symbols) -> list[Diagnostic]:
    """Note when the regular symbol table was unavailable."""
    if symbols.data.get("stripped"):
        return [
            Diagnostic(
                code="SYMBOLS_STRIPPED",
                level=DiagnosticLevel.INFO,
                message=(
                    "The regular symbol table is absent; dangerous APIs are "
                    "detected from the dynamic symbol table only."
                ),
                analyzer_id=analyzer_id,
            )
        ]
    return []
