# 开发标准与迭代流程

本文档记录 SOInsight 的开发标准：每一条都来自本项目真实踩过的坑，并且尽量落成
**可执行的检查**，而不是文字约定。文中引用的测试与脚本都在仓库里，可以直接运行。

文档本身分两部分：

- **§1–§6 是标准**：写代码、改代码时必须满足的条件。
- **§7 是迭代流程**：一个改动从想法到提交的完整闭环，以及每一步该跑什么。

---

## 0. 三条底线

这三条是所有其它标准的前提，违反其中任何一条都说明改动没有真正完成。

1. **在真实样本上验证。** 合成夹具会让"测试通过但功能是死的"。
   本项目有过一次真实教训：控制流平坦化检测的单测喂的是手工构造的字典，
   而真实 CFG 的块出度最多 2，判据"出度 ≥ 4"永远不成立——测试绿了，功能从未生效。
   现在端到端检查一律跑 `in/libtest_demo.so`。
2. **声明与实现一致。** 能力清单里勾了就是实现了；文档里的数字、名称、
   能力状态必须与代码一致。这条由 §5 的守卫强制。
3. **每个提交独立可用。** 一个提交只依赖它之前的提交，不能依赖后面的。
   bisect、revert、cherry-pick 都要求这一点。验证方法见 §7.3。

---

## 1. 静态检查：未定义名是硬性阻断，未使用导入是待清理

**标准**，分两级：

| 级别 | 规则 | 检查方式 |
|---|---|---|
| **阻断** | 不得有 `undefined name` | 全项目必须为 0 |
| **待清理** | 改动过的文件不得新增 `imported but unused` | 增量检查 |

```bash
# 阻断项：全项目必须是 0
python -m pyflakes src/soinsight/ tests/ | grep "undefined name"

# 增量项：只看你改动的文件
python -m pyflakes <改动的文件>
```

**为什么分级**：项目当前有六十余条 pyflakes 报告，其中四十余条是历史遗留的
未使用导入（无害），**0 条未定义名**。若要求全量为 0，这项标准从第一天就没人能过；
而未定义名是真 bug。所以前者阻断、后者增量。

**为什么是标准**：本项目的 `cli/main.py` 漏导入 `AnalyzerNotFoundError`，
`diff` 命令走到"analyzer 未注册"分支时会抛 `NameError` 而不是友好报错。
这个分支在正常路径下永远走不到，所以测试没有发现它——只有静态检查能发现。

**执行方式**：阻断项已纳入 `tests/unit/test_change_audit.py` 第 8 项
（CLI 无未定义名）；增量项由同一脚本第 7 项检查本次新增文件。

**待办**：把历史遗留的未使用导入清掉，届时本节可以升级为"全量为 0"。
（数字会随改动变化，所以这里不写具体条数——用上面的命令现场看。）

---

## 2. 安全边界：不执行被分析目标

**标准**：分析不可信输入的能力，默认不得执行它。任何执行路径必须同时满足
两个条件：配置显式授权 **且** 执行器构造时显式 opt-in。

```python
# src/soinsight/infrastructure/execution.py
class SubprocessSandboxExecutor:
    def __init__(self, sandbox, *, allow_execution: bool = False):
        ...
```

**执行方式**：`tests/unit/test_change_audit.py` 第 2 项扫描全部动态族源码，
断言其中不出现 `subprocess.` / `os.system` / `os.popen` / `Popen`。
这条守卫是自动化的，不要靠人肉检查。

---

## 3. 边界要说清楚：降级而不是静默

**标准**：能力遇到无法处理的目标时，行为必须是三者之一，且三者都可从结果里看出：

| 情况 | 行为 | 例子 |
|---|---|---|
| 与目标无关 | 正常工作 | `advanced.strings` 对任意文件都可用 |
| 目标相关但无法解析 | 明确失败并给出原因 | `basic.elf` 对非 ELF 返回 `INVALID_ELF` |
| 依赖缺失 | 跳过并说明依赖 | `basic.dwarf` 对无调试信息返回 `DEPENDENCY_FAILED` |

**不要**：静默返回空结果。读者无法区分"分析过了，没有发现"和"根本没分析"。

**声明的边界要落在代码里**：能力声称"支持 X"时，X 的边界也要能被验证。
例如 `basic.dataflow` 声明 `scope: intra-procedural`，那它的结果里就要带着
这个声明，而不是让人从实现里猜。

---

## 4. 报告事实，不下判决

**标准**：分析器报告证据，不给"有/没有漏洞"这种结论。判断留给规则层。

- 事实：`call_site_count: 2`、`evidence_level: "call-site"`、`severity: "high"`
- 结论（属于规则/裁决）：`"存在命令注入风险"`

**置信度只反映证据强度，不反映危害**。本项目里 `security.vulnerability`
即使有污点路径证据也保持 `MEDIUM`——因为"调用方可控"和"攻击者可控"是两件事，
把后者说成前者是越界。

**同一件事要标明覆盖范围**。污点分析追的是"数据从哪来"，不是"能否被利用"；
规则说"调用方可控"，不说"攻击者可控"。写进消息文本里。

---

## 5. 文档与代码的一致性（自动化）

**标准**：以下四项由守卫测试强制，任何一项失败即视为改动未完成。

| 守卫 | 文件 | 检查什么 |
|---|---|---|
| 能力清单 | `tests/unit/test_readme_capability_list.py` | README 里 46 项能力的勾选状态与注册表**双向**一致；汇总表合计正确 |
| 文档数字 | `tests/unit/test_document_consistency.py` | 文档里的能力数与代码实时重算的结果一致；README 逐项对照 |
| 文档形状 | `tests/unit/test_documentation_status.py` | 文档里不出现"具体 Analyzer 迁移尚未开始"这类过期表述 |
| 变更审计 | `tests/unit/test_change_audit.py` | 新能力可达、动态族零执行、单一 Web 实现、报告合并两侧发现项、污点链路闭环、无死代码、CLI 无未定义名 |

### 5.1 不要写死会变的数字

**标准**：文档与断言里不得出现随每次提交变化的数字。

本项目的教训：文档曾写"992 passed"，那数字每次加测试都会变，导致文档在
除最后一个提交外的**每一个**提交上都是错的。现在文档写"900+ passed"这个
**下限**——它随测试增长保持为真，且保留了文档守卫查找的形状。

同理，Web 测试曾硬编码"36 个 analyzer"，结果在注册提交之前的每一个提交上
都失败。现在断言的是性质（列表来自注册表、包含 `basic.file`），不是数字。

**推论**：任何断言如果"加个功能就要改它"，就应该改成断言性质。

### 5.2 文档命名跟着代码走

代码路径变了，文档里的路径也要改。本项目把控制台移进包内后，
`web/index.html` → `src/soinsight/web/index.html`，文档同步更新。

---

## 6. 结构：一份实现，多个入口

**标准**：同一个功能只有一个实现。多个入口（脚本、CLI 子命令、平台启动器）
必须走到同一份代码。

本项目曾有两套 Web 控制台（包内 10KB 的简易页 + 仓库根 41KB 的完整页），
`soinsight web` 指向旧的那套。现在完整实现在 `src/soinsight/web/console.py`，
仓库根的 `web/server.py` 是薄包装，四个启动脚本都调用它。

**资源不要留重复副本**：控制台页面只保留包内一份，打包时随包带走。

**执行方式**：`tests/unit/test_change_audit.py` 第 4 项检查包内没有第二个
`server.py`、没有重复的模板目录、仓库根没有重复的页面副本。

---

## 7. 迭代流程

### 7.1 一个改动的闭环

```text
想清楚要证明什么
  ↓
写实现
  ↓
写测试（先想清楚测试怎么证明这件事）
  ↓
在真实样本上跑一遍，看输出对不对
  ↓
跑守卫（§5）
  ↓
提交（一个功能一个提交）
  ↓
逐提交验证（§7.3）
```

**关键顺序**：测试不是实现之后的补品。写下测试的时候如果发现"这句话怎么证明"，
说明这个需求还没想清楚——这正是本项目几个真实缺陷的成因。

### 7.2 提交粒度：一个功能一个提交

**标准**：一个提交只做一件事，提交信息说清"为什么"而不只是"做了什么"。

本项目使用的格式（Conventional Commits）：

```
feat(advanced): detect control-flow flattening from the recovered CFG

A flattened function dispatches through a table, so its states end in
jumps whose destination is not in the instruction text. The CFG builder
now reports those blocks as indirect_jump, and the obfuscation analyzer
uses the share of them to judge flattening.

The criterion is deliberately narrow: an earlier version looked for a
high in-degree join point, which fired on 19 of the 124 functions of a
real, un-obfuscated library -- a return point or a switch is such a join
point too. Requiring the indirect jumps keeps the false-positive rate at
zero while still catching the classic shape.
```

约定：

- 主题用 `feat` / `fix` / `docs` / `test` / `chore`，范围用模块名；
- 正文写"为什么"，尤其是"为什么不用另一种做法"——后来的人会问；
- 涉及取舍时，把被否掉的方案和它的缺陷写下来（例如上面的误报数据）。

### 7.3 逐提交验证：每个提交都要独立可用

**标准**：本次改动范围内的**每一个**提交，checkout 出来后完整测试套件必须通过。

```bash
# 逐个提交跑测试
git rev-list --reverse <base>..HEAD | while read sha; do
  git checkout -q "$sha"
  python -m pytest tests -q || echo "FAIL: $sha"
done
git checkout -q main
```

**为什么是标准**：本项目在整理提交历史时，发现 11 个提交里有 7 个**单独
checkout 会失败**——测试依赖了后面才有的注册、或 patch 了还没迁移的模块名。
这些提交单独看都是"合理"的，但组合起来的历史是坏的：任何人 bisect 到中途
都会拿到一个不能用的树。

**迭代点**：这个检查应当在提交**之前**跑，而不是整理历史时才补。
新增依赖（注册、共享底座、测试夹具）时，先确认前面的提交仍然自洽。

### 7.4 依赖声明要与代码一致

**标准**：依赖的下限版本必须覆盖代码实际用到的 API。

本项目的 `capstone>=4.0` 与代码用的 `CS_ARCH_SH` / `CS_MODE_RISCV*` 不匹配——
这些常量只在 Capstone 5 存在。项目自己的 venv 里是 5.0.9，所以本机测试全绿，
而任何按声明下限安装的环境会在那两个架构上 `AttributeError`，解码器还会
**静默**返回空 profile。

**检查方式**：改动架构表、协议表或任何依赖特定符号的东西时，
grep 一次依赖包的版本历史，确认下限对得上。

---

## 8. 提交前自查清单

```bash
# 1. 全量测试
python -m pytest tests -q

# 2. 静态检查（未定义名必须为 0；未使用导入只看改动的文件）
python -m pyflakes src/soinsight/ tests/ | grep "undefined name"   # 应无输出
python -m pyflakes <改动的文件>                                    # 不应新增告警

# 3. 守卫（文档/清单/审计）
python -m pytest tests/unit/test_change_audit.py \
                 tests/unit/test_document_consistency.py \
                 tests/unit/test_readme_capability_list.py \
                 tests/unit/test_documentation_status.py -q

# 4. 真实样本上的行为
python -m soinsight scan in/libtest_demo.so \
    --module-available basic,advanced,security,dynamic --format json

# 5. 打包后的东西仍然可用
python -m build --wheel --outdir /tmp/dist
python -m venv /tmp/check && /tmp/check/bin/pip install /tmp/dist/*.whl
/tmp/check/bin/soinsight modules list
```

> 第 4 步的 `--no-cache` 不是必须的：缓存键含代码指纹，改代码会自动失效。
> 但在同一进程内连续验证时指纹只算一次，加 `--no-cache` 更稳妥。

---

## 9. 可以持续迭代的部分

这些是当前标准里**尚未自动化**的部分，按优先级排列：

| 事项 | 现状 | 迭代方向 |
|---|---|---|
| 逐提交验证 | 手工脚本 | 接入 CI，作为 PR 必过项 |
| CI | 无 | 建立 `.github/workflows`：测试 + 守卫 + 打包检查 |
| 依赖下限核对 | 手工 grep | 写一个检查：代码用到的符号在声明下限下是否存在 |
| 静态检查 | pyflakes 手工跑 | 接入 CI；扩展到类型检查（mypy） |
| 真实样本回归 | 手工对比输出 | 建立"黄金样本"：固定样本的输出快照，防止能力回退 |
| 能力实现度 | `modules list` 报状态 | 区分"已实现"与"计划版"，避免名不副实 |
| 审计脚本 | `test_change_audit.py` 是脚本形式 | 改成 pytest 用例，或为每轮改动增加对应的检查项 |

---

## 10. 相关文档

- [扩展开发指南](extension-development.md)：怎么写一个 Analyzer / Rule / Profile / Renderer
- [模块体系](module-system.md)：六大能力域与 46 项能力的定义
- [项目状态与路线图](project-status.md)：已完成、未实现与验收标准
- [功能实现状态清单](feature-status.md)：逐项能力的现状
