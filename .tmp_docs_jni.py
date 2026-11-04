"""Document basic.jni (corrected anchors)."""

import pathlib


def patch(relpath, edits):
    p = pathlib.Path(relpath)
    s = p.read_text(encoding="utf-8")
    for old, new in edits:
        assert s.count(old) == 1, f"{relpath}: anchor not unique -> {old[:70]!r}"
        s = s.replace(old, new)
    p.write_text(s, encoding="utf-8")
    print(f"patched {relpath}")


patch(
    "docs/module-system.md",
    [
        (
            "| `basic xref` | `basic.xref` | 交叉引用 | 已实现 |",
            "| `basic xref` | `basic.xref` | 交叉引用 | 已实现 |\n"
            "| `basic jni` | `basic.jni` | JNI 注册表 | 已实现（静态+动态） |",
        ),
        (
            "`basic.symbols` 采集 `.dynsym`/`.symtab` 符号事实",
            "`basic.jni` 把 JNI 注册表统一到一个视图里：静态侧是 `basic.symbols` 已经解码的 `Java_*` "
            "导出（包名/类名/方法名/参数类型）；动态侧从 `RegisterNatives` 消费的 `JNINativeMethod` 数组"
            "还原——数组在 `.data.rel.ro`，每个指针槽带一条 `R_*_RELATIVE` 重定位（加载器必需，strip 也"
            "不会剥掉），据此把 name 字符串、Java 方法描述符和函数地址一一对应；函数地址能回查符号表就"
            "给函数名，strip 后只给地址并明确告警。方法名是简名时，所属 Java 类由运行时的 `FindClass` "
            "决定，静态不可知，输出中如实标注。纯静态，不执行目标。\n\n"
            "`basic.symbols` 采集 `.dynsym`/`.symtab` 符号事实",
        ),
    ],
)

patch(
    "docs/pending-capabilities.md",
    [
        ("已实现的 29/45 项能力见 `feature-status.md` §一",
         "已实现的 30/46 项能力见 `feature-status.md` §一"),
        ("共 **16/45** 项外壳能力", "共 **16/46** 项外壳能力"),
    ],
)

patch(
    "docs/feature-status.md",
    [
        ("### 3. V2 已实现的真正 Analyzer 与 Rule（29/45 能力）",
         "### 3. V2 已实现的真正 Analyzer 与 Rule（30/46 能力）"),
        ("| `automation.binary-diff` | 双输入符号级 Diff：",
         "| `basic.jni` | JNI 注册表统一还原：静态 `Java_*` 导出（来自 basic.symbols）+ 动态 "
         "`RegisterNatives` 表（从 `.data.rel.ro` 的 RELATIVE 重定位还原 name/签名/函数地址，"
         "strip 后只给地址并告警） | `analyzers/jni.py` + `infrastructure/jni_dynamic.py` |\n"
         "| `automation.binary-diff` | 双输入符号级 Diff："),
        ("以下 16/45 项能力**只有目录和命令外壳，没有真实 Analyzer**：",
         "以下 16/46 项能力**只有目录和命令外壳，没有真实 Analyzer**："),
        ("| `basic`（12/12） |", "| `basic`（13/13） |"),
    ],
)

patch(
    "docs/project-status.md",
    [
        ("- [x] `automation.binary-diff`（符号级）：",
         "- [x] `basic.jni`（JNI 注册表）：静态 `Java_*` 导出 + 动态 `RegisterNatives` 表还原"
         "（`.data.rel.ro` + RELATIVE 重定位驱动，strip 后仍可还原并降级为地址）；\n"
         "- [x] `automation.binary-diff`（符号级）："),
        ("为 `811 passed, 9 skipped`；`cpp_demangle` 未装时", "为 `843 passed, 9 skipped`；`cpp_demangle` 未装时"),
        ("为 `695 passed, 1 skipped`。", "为 `727 passed, 1 skipped`。"),
    ],
)

patch(
    "docs/quickstart.md",
    [
        ("`security.risk`、`security.dynamic-loading`、`automation.fuzz-target`、`automation.harness`；",
         "`security.risk`、`security.dynamic-loading`、`basic.jni`、`automation.fuzz-target`、"
         "`automation.harness`；"),
    ],
)
