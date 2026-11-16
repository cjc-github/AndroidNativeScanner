"use strict";

/* ================= 工具 ================= */

var SEV_LABEL = { critical: "严重", high: "高", medium: "中", low: "低", info: "提示" };
var STATUS_LABEL = {
  success: ["成功", "ok"], partial: ["部分完成", "warn"], failed: ["失败", "fail"],
  skipped: ["跳过", "info"], cancelled: ["已取消", "warn"], timeout: ["超时", "fail"],
  cached: ["缓存", "info"], pending: ["等待", "info"], running: ["进行中", "info"]
};

function esc(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

function fmtBytes(n) {
  if (typeof n !== "number" || !isFinite(n)) return "—";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KiB";
  return (n / 1024 / 1024).toFixed(2) + " MiB";
}

function fmtMs(n) {
  if (typeof n !== "number" || !isFinite(n)) return "—";
  return n < 1000 ? n + " ms" : (n / 1000).toFixed(2) + " s";
}

/* ISO-8601（服务端 utc_now_iso 输出）-> 本地 "YYYY-MM-DD HH:MM:SS" */
function fmtTime(iso) {
  if (!iso) return "—";
  var d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  var pad = function (n) { return (n < 10 ? "0" : "") + n; };
  return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
    " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
}

/* 由开始时刻与耗时推出结束时刻；startedAt 缺失时返回 "—" */
function endTimeFrom(startIso, durationMs) {
  if (!startIso) return "—";
  var start = new Date(startIso);
  if (isNaN(start.getTime()) || typeof durationMs !== "number") return "—";
  return fmtTime(new Date(start.getTime() + durationMs).toISOString());
}

/* 超过这个长度的值只渲染摘要 + 折叠全文。
   basic.disasm / cfg / dataflow 这类分析器的函数体数据被 JSON.stringify 后
   可达 40 万字符，整行铺开会把页面撑到 20 万像素高，滚动和切 tab 都会卡。 */
var KV_INLINE_LIMIT = 400;
var KV_FOLD_THRESHOLD = 4000;
/* 折叠区最多内联多少字符。超长的值仍走服务端落盘那份完整 JSON：
   在 <pre> 里塞几十万字符对浏览器毫无收益，展开时也会把页面重新撑高。 */
var KV_FOLD_INLINE_LIMIT = 20000;
/* 格式化后的 JSON / 多行文本默认最多显示多少行，超出改为区块内滚动 */
var KV_MAX_ROWS = 10;

/* 尝试把值解析成 JSON 并缩进格式化；不是 JSON 就原样返回 null。
   数组/对象格式化后可读性远高于 JSON.stringify 的单行。 */
function tryPrettyJson(text) {
  var trimmed = text.trim();
  if (!trimmed || (trimmed[0] !== "{" && trimmed[0] !== "[")) return null;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch (e) {
    return null;
  }
}

/* rows: [key, value, mono?, small?, rawKey?]
   rawKey 仅在 key 被中文化时提供，用于 title 悬浮显示原始字段名。 */
function kv(rows) {
  return '<div class="kv">' + rows.map(function (r) {
    var raw = r[1] == null ? "—" : r[1];
    // 对象/数组先序列化成紧凑 JSON，交由 tryPrettyJson 重新缩进
    var text = raw !== null && typeof raw === "object" ? JSON.stringify(raw) : String(raw);
    var cls = (r[2] ? " mono" : "") + (r[3] ? " small" : "");
    var rawKey = r[4];
    var keyTitle = rawKey && rawKey !== r[0] ? ' title="原始字段：' + esc(rawKey) + '"' : "";
    var valueHtml;
    if (text.length > KV_FOLD_THRESHOLD) {
      // 长值：可见区只放摘要，全文进 <details>，需要时才展开
      var foldBody = esc(text.length > KV_FOLD_INLINE_LIMIT
        ? text.slice(0, KV_FOLD_INLINE_LIMIT) +
          "\n\n…（仅内联前 " + fmtCount(KV_FOLD_INLINE_LIMIT) + " 字符，完整内容见「结果 JSON」Tab 的服务端文件）"
        : text);
      valueHtml =
        '<span class="v-foldsum">' + esc(text.slice(0, KV_INLINE_LIMIT)) +
        ' <span class="v-foldmeta">… 共 ' + esc(fmtCount(text.length)) + ' 字符</span></span>' +
        '<details class="v-fold"><summary>展开全文</summary>' +
        '<pre class="v-foldpre">' + foldBody + "</pre></details>";
    } else {
      // 能解析成 JSON 就给缩进格式；行数超过上限改为内部滚动，不把表格撑高
      var pretty = tryPrettyJson(text);
      if (pretty) {
        var lineCount = pretty.split("\n").length;
        if (lineCount > KV_MAX_ROWS) {
          valueHtml =
            '<pre class="v-json is-clipped" data-rows="' + lineCount + '"' +
            ' title="共 ' + lineCount + ' 行，此处显示前 ' + KV_MAX_ROWS + ' 行，滚动查看其余内容">' +
            esc(pretty) + "</pre>";
        } else {
          valueHtml = '<pre class="v-json">' + esc(pretty) + "</pre>";
        }
      } else {
        valueHtml = esc(text);
      }
    }
    return '<div><div class="k"' + keyTitle + ">" + esc(r[0]) + '</div><div class="v' + cls + '">' +
      valueHtml + "</div></div>";
  }).join("") + "</div>";
}

/* 大数字加千分位，便于快速判断数量级 */
function fmtCount(n) {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function statusChip(status) {
  var entry = STATUS_LABEL[status] || [status, "info"];
  return '<span class="chip ' + entry[1] + '">' + esc(entry[0]) + "</span>";
}

function sevRank(s) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s] || 0;
}

function copyText(text, btn) {
  function fallback() {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* ignore */ }
    ta.remove();
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(fallback);
  } else {
    fallback();
  }
  if (btn) {
    var old = btn.textContent;
    btn.textContent = "已复制";
    setTimeout(function () { btn.textContent = old; }, 1200);
  }
}

/* ================= 网络请求 ================= */

var API_TIMEOUT_MS = 20000;   // 普通接口（health / 列表 / CRUD）的默认超时

/* 统一请求入口：每个请求都带超时，并可被外部 AbortSignal 中止。
   浏览器原生的 fetch 没有超时，服务端卡住时 Promise 永远不会 settle，
   调用方只能一直等；这里用 AbortController 兜住这种情况。 */
function apiFetch(url, options) {
  options = options || {};
  var controller = new AbortController();
  var timeoutMs = options.timeout || API_TIMEOUT_MS;
  var timer = setTimeout(function () {
    controller.abort();
  }, timeoutMs);
  /* 外部 signal（如「停止分析」按钮）与内部超时各自都能中止请求：
     fetch 只认一个 signal，所以把外部中止转发进内部 controller，
     直接用外部 signal 的话内部超时就形同虚设。
     externalAbort 区分两种中止来源，超时才能报「请求超时」而不是「已取消」。 */
  var externalAbort = false;
  if (options.signal) {
    if (options.signal.aborted) { externalAbort = true; controller.abort(); }
    else options.signal.addEventListener("abort", function () {
      externalAbort = true;
      controller.abort();
    });
  }
  var init = {
    method: options.method || "GET",
    headers: options.headers || {},
    signal: controller.signal
  };
  if (options.body !== undefined && options.body !== null) init.body = options.body;
  if (options.cache) init.cache = options.cache;
  return fetch(url, init).then(
    function (resp) {
      clearTimeout(timer);
      return resp;
    },
    function (err) {
      clearTimeout(timer);
      if (err && err.name === "AbortError") {
        if (externalAbort) throw new Error("已取消本次请求");
        throw new Error("请求超时（" + Math.round(timeoutMs / 1000) + " 秒），请检查本地服务是否仍在运行");
      }
      throw err;
    }
  );
}

/* 读取 JSON 响应；响应体不是 JSON 时抛出一条带状态码的可读错误 */
function readJson(resp) {
  return resp.json().catch(function () {
    throw new Error("服务返回无法解析的响应（HTTP " + resp.status + "）");
  });
}

/* ================= 状态 ================= */

var state = {
  health: null,
  healthChecked: false,    // /api/health 是否已经返回过，避免首屏闪一下"未连接"
  samples: [],
  target: null,
  include: "",            // 批量扫描时的包含/排除过滤（与 CLI 的 --include/--exclude 同义）
  exclude: "",
  mode: "multi",          // "multi"（多选能力）或 "scan"（组合扫描全部）
  capabilities: [],       // 多选的能力 id
  presets: [],            // 服务端保存的预置分析脚本（.soinsight/presets/*.json）
  projects: [],            // 数据库中的项目列表
  currentProjectId: null,  // 当前选中的项目
  currentProject: null,    // 当前打开详情的项目对象
  projectPage: 1,          // 项目管理列表当前页
  projectQuery: "",        // 项目搜索关键词（小写）
  taskPage: 1,             // 项目详情任务列表当前页
  tasks: [],               // 数据库中的任务列表
  overview: null,          // /api/overview 聚合结果（趋势 / 严重级别 / 失败原因 / 作业状态）
  overviewLoading: false,
  resultHiddenGroups: [],  // 结果页按大类折叠时被隐藏的结果组
  resultHiddenCaps: [],    // 结果页中单独被隐藏的小类结果
  activeTab: "summary",
  running: false,
  cancelling: false,
  timeout: 180,           // 服务端单次分析超时上限（/api/health 返回，秒）
  response: null,
  timer: null,
  abort: null,            // 正在运行的 /api/analyze 对应的 AbortController
  healthTimer: null,      // 健康检查轮询句柄
  view: "overview",       // 当前所在视图：overview / config / project / results / history / settings
  sym: { q: "", lang: "all", shown: 200 }
};

/* 静态展示元数据：服务端只提供 analyzer id，中文名与说明必须由页面维护。
   新增 analyzer 时在这里补一条即可；没补也能正常显示（回退成 id）。
   desc 讲清楚「这个分析做什么、能拿到什么」，结果面板顶部展示。 */
var CAP_META = {
  "basic.file":          { name: "文件属性", brief: "大小 / 哈希 / 格式判定",
    desc: "读取目标文件本身的基础属性。产出文件名、字节大小、SHA-256 摘要、Magic 头与格式判定，用于确认样本身份并供后续比对。" },
  "basic.elf":           { name: "ELF 头",   brief: "架构 / 段表 / 入口点",
    desc: "解析 ELF 头与段表、节表。产出位数、端序、文件类型、机器架构、入口点、段与节数量，以及 GNU RELRO、NX、栈 Canary、CFI、PAC 等加固位。" },
  "basic.symbols":       { name: "符号表",   brief: "导出导入 / demangle / JNI",
    desc: "枚举动态符号表并恢复函数签名。产出导入与导出函数、导出数据、C++ demangle 后的可读名字、JNI 方法名及语言分类，支持搜索与导出 CSV。" },
  "basic.dwarf":         { name: "DWARF",    brief: "调试信息函数签名",
    desc: "解析调试信息中的编译单元与函数条目。产出函数签名、参数名与参数类型、返回值、声明文件与行号；stripped 构建会明确报告调试信息缺失。" },
  "basic.types":         { name: "类型恢复", brief: "结构体 / 枚举 / 全局变量",
    desc: "从 DWARF 恢复类型系统。产出函数签名清单、全局与局部变量、结构体 / 联合体 / 枚举等复合类型的定义。" },
  "basic.cpp":           { name: "C++ 恢复", brief: "RTTI / vtable / 继承",
    desc: "从 RTTI 与 vtable 还原 C++ 类结构。产出类名、虚函数表、继承关系、构造与析构函数、thunk 和 construction vtable，可判断是否 C++ 编写。" },
  "basic.disasm":        { name: "反汇编",   brief: "指令解码 / 函数体",
    desc: "反汇编可执行段并定位函数边界。产出代码区域清单、函数列表与逐条指令，是控制流图、数据流和交叉引用的基础。" },
  "basic.cfg":           { name: "控制流图", brief: "基本块 / 跳转关系",
    desc: "在反汇编结果上恢复过程内控制流。产出每个函数的基本块、跳转边与循环，用于判断分支复杂度和代码结构。" },
  "basic.callgraph":     { name: "调用图",   brief: "函数调用关系",
    desc: "解析直接调用、PLT 导入调用和间接调用点。产出 caller / callee 关系，用于判断哪些函数被谁调用、哪些入口可达。" },
  "basic.dataflow":      { name: "数据流",   brief: "寄存器 / 变量追踪",
    desc: "过程内 Use-Def 与可达定义分析。产出每个基本块的定义点、使用点与数据依赖，用于追踪参数在函数内部如何流动。" },
  "basic.dynamic":       { name: "动态链接", brief: "PLT / GOT / 重定位",
    desc: "解析动态段与重定位信息。产出依赖库（NEEDED）、SONAME、RPATH / RUNPATH、init/fini 构造函数入口和符号版本要求。" },
  "basic.jni":           { name: "JNI 注册表", brief: "静态 / 动态注册",
    desc: "还原 JNI 注册表。静态侧是 Java_* 导出（包名 / 类名 / 方法名 / 参数类型），动态侧从 RegisterNatives 消费的 JNINativeMethod 数组还原方法名、Java 方法描述符与 native 函数地址；strip 后函数只剩地址并如实标注，方法名为简名时所属 Java 类需运行时 FindClass 才知道。" },
  "basic.xref":          { name: "交叉引用", brief: "符号 / 地址引用",
    desc: "把指令操作数还原为其指向的字符串字面量。产出「代码地址 → 字符串」的引用关系，用于定位报错文案、协议字段名等线索出处。" },
  "advanced.strings":    { name: "字符串",   brief: "提取 / 分类 / 敏感信息",
    desc: "提取、定位并分类可打印字符串。产出分类统计（URL、密钥、路径、配置项等）与完整字符串清单及所在偏移，是找线索最快的入口。" },
  "advanced.constants":  { name: "常量分析", brief: "整数 / 魔法值",
    desc: "扫描二进制中已知算法的常量表特征。产出命中的魔法值、所属算法族、出现偏移与所在节，是算法识别的底层证据。" },
  "advanced.algorithm":  { name: "算法识别", brief: "加密 / 哈希特征",
    desc: "交叉印证常量、符号名和字符串三路证据后给出判定。产出加密 / 哈希 / 密钥派生 / 压缩 / 编码等算法、证据强度（单一或已多源印证）与命中依据。" },
  "advanced.file-format":{ name: "文件格式", brief: "容器 / 压缩识别",
    desc: "按签名识别外层与内嵌文件格式。产出格式清单、类别统计（压缩包、镜像、证书等）以及是否已通过结构校验。" },
  "advanced.library":    { name: "库识别",   brief: "第三方组件指纹",
    desc: "用依赖名、符号和字符串指纹匹配第三方库。产出库名、版本线索、证据来源与置信强度，用于判断集成了哪些开源组件。" },
  "advanced.compiler":   { name: "编译器",   brief: "工具链 / 优化级别",
    desc: "从注释段、符号和特征识别构建工具链。产出编译器家族与版本、Build ID、Android 版本标识等线索，可反推 NDK 版本。" },
  "advanced.protocol":   { name: "协议分析", brief: "消息结构 / 状态机",
    desc: "识别网络协议与私有协议特征。产出协议族、消息结构线索（魔术头、长度字段、状态常量）与证据强度。" },
  "advanced.obfuscation":{ name: "混淆检测", brief: "反调试 / 字符串加密",
    desc: "汇总混淆与加壳证据。产出混淆信号列表（控制流扁平化、字符串加密、符号剥离、反调试等）、类别统计与印证强度。" },
  "dynamic.trace":       { name: "动态追踪", brief: "运行时调用记录",
    desc: "在显式授权且探测到隔离环境时，产出沙箱执行计划（超时、内存上限、执行方式）。默认拒绝执行目标，因此通常只给计划不给运行数据。" },
  "dynamic.arguments":   { name: "参数采集", brief: "入口参数取值",
    desc: "列出可观测的入口参数与采样点，产出候选入口签名与建议采样位置。默认只给沙箱执行计划，不实际运行目标，因此目前不返回真实参数取值。" },
  "dynamic.memory":      { name: "内存观测", brief: "映射 / 堆栈白名单",
    desc: "给出运行期可观测的内存范围白名单（按依赖库与链接信息推导）。默认只给沙箱执行计划，不实际读取进程内存。" },
  "dynamic.syscalls":    { name: "系统调用", brief: "seccomp 拦截策略",
    desc: "生成默认拒绝的系统调用过滤策略，并标出需要重点观察的危险 API。默认只给沙箱执行计划，不实际拦截调用。" },
  "dynamic.coverage":    { name: "覆盖率",   brief: "基本块覆盖对齐",
    desc: "把覆盖率采集点对齐到已恢复的控制流基本块，产出块号索引与基本块数量。默认只给沙箱执行计划，不实际采集覆盖率。" },
  "security.hardening":  { name: "加固检查", brief: "PIE / NX / RELRO / Canary",
    desc: "评估 ELF 安全加固位。结论汇总在「概览」Tab 的发现项中，覆盖 PIE、NX、RELRO、栈 Canary、CFI 与 PAC。" },
  "security.dynamic-loading": { name: "动态加载", brief: "dlopen / JNI 加载",
    desc: "评估库搜索路径与符号抢占带来的动态加载风险。产出 RPATH/RUNPATH 中的相对路径、可写路径、TEXTREL、符号抢占与 bind-now 情况。" },
  "security.dangerous-api": { name: "危险 API", brief: "高危函数调用",
    desc: "检测导入与导出的高危函数。产出命中的危险 API、按严重度的数量分布，以及调用点处的上下文证据。" },
  "security.risk":       { name: "风险汇总", brief: "严重度 / 加权评分",
    desc: "对所有 Finding 去重、聚合并加权评分。产出风险总分与等级、按严重度和置信度的分布、类别分布，以及最需要关注的 Top 发现项。" },
  "security.vulnerability": { name: "漏洞模式", brief: "危险 API 映射 CWE",
    desc: "由危险链接与加固事实推断漏洞类别。产出 CWE 编号映射、漏洞模式计数、加固类发现项与字符串指标。" },
  "automation.fuzz-target": { name: "Fuzz 目标", brief: "入口函数识别",
    desc: "从导出函数中挑选适合做模糊测试的入口。产出候选目标及其评分，以及解析器特征、缓冲区长度配对等启发式依据。" },
  "automation.harness":  { name: "Harness",  brief: "测试桩生成",
    desc: "为选定入口生成可编译的 Fuzz 测试桩骨架。产出 harness 源码；需要先运行 Fuzz 目标识别出可用入口。" },
  "automation.binary-diff": { name: "二进制对比", brief: "两版本符号差异",
    desc: "对比两个 ELF 的符号集合。产出新增、移除、移动和大小发生变化的函数清单，适合做版本回归与补丁影响面评估。" },
  "automation.seed":      { name: "种子语料", brief: "格式 / 协议种子生成",
    desc: "依据已识别的文件格式、协议特征和算法常量生成种子语料。产出种子清单、大小与哈希，以及每条种子的来源依据；无上游事实时退化为通用字节种子。" },
  "automation.report":    { name: "报告归档", brief: "多格式报告 / 归档",
    desc: "把本次分析结果汇总为多格式报告（Text / JSON / Markdown / HTML / SARIF）。产出各格式正文、失败格式记录与可选的报告归档路径。" }
};
/* 离线兜底顺序（health 拿不到清单时用） */
var CAP_META_ORDER = Object.keys(CAP_META);

/* /api/modules 返回的登记信息：{ "<capability id>": { name, desc } }。
   服务端的名称与说明是权威来源，CAP_META 只在服务端没登记时兜底。 */
var CATALOG_META = {};

/* 运行时能力清单：由 /api/health 的 registered_analyzers 决定，见 buildPresets() */
var PRESETS = [];

var SCAN_PRESET = { id: "scan", name: "组合扫描", brief: "basic + advanced + security 全部已实现分析器" };

/* ================= DOM ================= */

function $(id) { return document.getElementById(id); }
var dropzone = $("dropzone");
var fileInput = $("file-input");
var sampleSelect = $("sample-select");
var pathInput = $("path-input");
var targetChip = $("target-chip");
var chipName = $("chip-name");
var chipMeta = $("chip-meta");
var capGrid = $("capability-groups");
var presetSelect = $("preset-select");            // 预置分析脚本下拉
var presetName = $("preset-name");                // 保存预置时的名称输入
var presetApplyBtn = $("preset-apply");
var presetSaveBtn = $("preset-save");
var presetDeleteBtn = $("preset-delete");
var projectListEl = $("project-list");            // 项目管理列表容器
var projectDetailEl = $("project-detail");        // 项目详情容器
var projectSearch = $("project-search");          // 项目搜索框
var toastBox = $("toast-box");                    // 全局轻提示容器
var projectModal = $("project-modal");
var projectModalName = $("project-modal-name");
var projectModalDesc = $("project-modal-desc");
var projectModalClose = $("project-modal-close");
var projectModalCancel = $("project-modal-cancel");
var projectModalCreate = $("project-modal-create");
var taskDescInput = $("task-description");        // 创建任务弹窗里的任务描述（若存在）
var taskModal = $("task-modal");
var taskClose = $("task-close");
var taskCancel = $("task-cancel");
var taskPrev = $("task-prev");
var taskNext = $("task-next");
var taskNameInput = $("task-name");
var targetNameInput = $("target-name");
var runBtn = $("run-btn");
var runSpinner = $("run-spinner");
var runLabel = $("run-label");
var runStatus = $("run-status");
var cancelBtn = $("cancel-btn");
var elapsedEl = $("elapsed");
var emptyState = $("empty-state");
var resultBody = $("result-body");
var resultMeta = $("result-meta");
var resultTabs = $("result-tabs");
var resultPanels = $("result-panels");
var resultLayout = document.querySelector(".result-layout");
var batchBody = $("batch-body");
var rawPanel = $("panel-raw");
var summaryStatus = $("summary-status");
var findingsSection = $("findings-section");
var diagnosticsSection = $("diagnostics-section");
var rawInfo = $("raw-info");
var sidenav = $("sidenav");
var navResults = $("nav-results");
var resultsBadge = $("results-badge");
var historyBadge = $("history-badge");
var historyList = $("history-list");
var settingsPrefs = $("settings-prefs");
var settingsEnv = $("settings-env");
var settingsClear = $("settings-clear");
var progressCard = $("progress-card");
var pcTitle = $("pc-title");
var pcTarget = $("pc-target");
var pcElapsed = $("pc-elapsed");
var pcStage = $("pc-stage");
var pcCancel = $("pc-cancel");
var overviewMetrics = $("overview-metrics");
var overviewRecent = $("overview-recent");
var overviewOffline = $("overview-offline");
var overviewSeverity = $("overview-severity");
var overviewTrend = $("overview-trend");
var overviewTrendSummary = $("overview-trend-summary");
var overviewFailures = $("overview-failures");
var overviewProjects = $("overview-projects");

/* ================= 项目与任务 ================= */

var PAGE_SIZE = 10;   // 项目列表与任务列表每页条数

/* 编辑按钮统一用铅笔图标 */
var PENCIL_SVG =
  '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor"' +
  ' stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>';

/* 方案 A：项目详情侧栏 / 空态图标（与 PENCIL_SVG 同款描边风格） */
var PLUS_SVG =
  '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"' +
  ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M12 5v14"/><path d="M5 12h14"/></svg>';

var CHART_SVG =
  '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"' +
  ' stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M4 20V10"/><path d="M10 20V4"/><path d="M16 20v-7"/><path d="M22 20H2"/></svg>';

var DOC_SVG =
  '<svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor"' +
  ' stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>' +
  '<path d="M14 2v6h6"/><path d="M9 13h6"/><path d="M9 17h6"/></svg>';

function loadProjects() {
  return apiFetch("/api/projects", { cache: "no-store" })
    .then(readJson)
    .then(function (data) {
      state.projects = (data && data.projects) || [];
      syncCurrentProject();
      renderProjectList();
      if (state.view === "project") renderProjectDetail();
      if (state.view === "overview") renderOverview();
      return loadTasks();
    })
    .catch(function () { renderProjectList(); });
}

/* currentProjectId 失效（项目被删）时清空，否则同步详情页用的项目对象 */
function syncCurrentProject() {
  if (!state.currentProjectId) { state.currentProject = null; return; }
  var still = state.projects.filter(function (p) { return p.id === state.currentProjectId; })[0];
  if (!still) {
    state.currentProjectId = null;
    state.currentProject = null;
    if (state.view === "project") switchView("config");
  } else {
    state.currentProject = still;
  }
}

/* ---------- 分页 ---------- */

function pageCount(total) {
  return Math.max(1, Math.ceil(total / PAGE_SIZE));
}

function clampPage(page, total) {
  return Math.min(Math.max(1, page), pageCount(total));
}

/* 页码按钮：页数多时折叠成 1 … 4 5 6 … 20，避免几十个按钮铺满整行 */
function pageButtonsHtml(page, pages) {
  var out = [];
  function push(n) {
    out.push('<button type="button" data-pg="' + n + '"' +
      (n === page ? ' class="current"' : "") + ">" + n + "</button>");
  }
  if (pages <= 7) {
    for (var i = 1; i <= pages; i++) push(i);
    return out.join("");
  }
  var start = Math.max(2, page - 1);
  var end = Math.min(pages - 1, page + 1);
  push(1);
  if (start > 2) out.push('<span class="pg-gap">…</span>');
  for (var j = start; j <= end; j++) push(j);
  if (end < pages - 1) out.push('<span class="pg-gap">…</span>');
  push(pages);
  return out.join("");
}

/* 分页条 HTML：按钮带 data-pg，由列表容器的事件委托统一处理。
   即使只有一页也完整渲染（页码 + 上一/下一页置灰），保证分页组件始终可见。 */
function pagerHtml(page, total, label) {
  var pages = pageCount(total);
  return '<div class="pager"><span class="pg-info">共 ' + esc(total) + " " + esc(label || "条") +
    " · 第 " + page + " / " + pages + " 页</span><span class=\"pg-pages\">" +
    '<button type="button" data-pg="prev"' + (page <= 1 ? " disabled" : "") + ">‹ 上一页</button>" +
    pageButtonsHtml(page, pages) +
    '<button type="button" data-pg="next"' + (page >= pages ? " disabled" : "") + ">下一页 ›</button>" +
    "</span></div>";
}

/* pagerHtml 的 data-pg 点击 → 返回新的页码；不在分页条上时返回 null */
function pagerClick(e, page, total) {
  var btn = e.target.closest ? e.target.closest("[data-pg]") : null;
  if (!btn || btn.disabled) return null;
  var v = btn.getAttribute("data-pg");
  if (v === "prev") return clampPage(page - 1, total);
  if (v === "next") return clampPage(page + 1, total);
  var n = Number(v);
  return n >= 1 ? clampPage(n, total) : null;
}

/* ---------- 项目管理列表（config 视图） ---------- */

/* 搜索过滤后的项目列表（名称 / 描述子串，大小写不敏感）；渲染与分页共用 */
function visibleProjects() {
  var q = state.projectQuery || "";
  if (!q) return state.projects;
  return state.projects.filter(function (p) {
    return (p.name || "").toLowerCase().indexOf(q) >= 0 ||
      (p.description || "").toLowerCase().indexOf(q) >= 0;
  });
}

function renderProjectList() {
  if (!projectListEl) return;
  var all = visibleProjects();
  if (!state.projects.length) {
    projectListEl.innerHTML =
      '<div class="empty-block">' +
        '<div class="eb-title">还没有项目</div>' +
        '<div class="eb-hint">项目用于把一批分析任务归到一起，创建后可在详情页里建任务。</div>' +
        '<div class="eb-actions"><button type="button" class="primary" data-empty-new-project>＋ 新建项目</button></div>' +
      "</div>";
    return;
  }
  if (!all.length) {
    projectListEl.innerHTML =
      '<div class="empty-block">' +
        '<div class="eb-title">没有匹配「' + esc(state.projectQuery) + '」的项目</div>' +
        '<div class="eb-hint">换个关键词试试，或清空搜索框查看全部项目。</div>' +
      "</div>";
    return;
  }
  state.projectPage = clampPage(state.projectPage, all.length);
  var page = state.projectPage;
  var start = (page - 1) * PAGE_SIZE;
  var rows = all.slice(start, start + PAGE_SIZE);
  var body = rows.map(function (p) {
    return "<tr>" +
      '<td><button type="button" class="name-link clamp-2" data-open-project="' + esc(p.id) + '" title="' + esc(p.name) + '">' + esc(p.name) + "</button>" +
        '<div class="cell-sub">' + esc(p.task_count) + " 个任务</div></td>" +
      '<td class="c-desc"><div class="cell-desc clamp-2" title="' + esc(p.description) + '">' + (p.description ? esc(p.description) : '<span class="cell-sub">（无描述）</span>') + "</div></td>" +
      '<td class="c-time">' + esc(fmtTime(new Date(p.created_at * 1000).toISOString())) + "</td>" +
      '<td class="c-actions"><div class="row-actions">' +
        '<button type="button" class="icon-btn" data-edit-project="' + esc(p.id) + '" title="编辑" aria-label="编辑">' +
          PENCIL_SVG + "</button>" +
        '<span class="menu-wrap">' +
          '<button type="button" class="menu-dots" aria-label="更多操作" title="更多操作">⋮</button>' +
          '<div class="menu-pop">' +
            '<button type="button" data-del-project="' + esc(p.id) + '">删除项目…</button>' +
          "</div>" +
        "</span>" +
      "</div></td>" +
    "</tr>";
  }).join("");
  projectListEl.innerHTML =
    '<div class="p-table-wrap"><table class="p-table"><thead><tr>' +
      '<th>项目名称</th><th class="c-desc">描述</th><th>创建时间</th><th style="text-align:right">操作</th>' +
    "</tr></thead><tbody>" + body + "</tbody></table></div>" +
    pagerHtml(page, all.length, "个项目");
}

function onProjectListClick(e) {
  if (e.target.closest && e.target.closest("[data-empty-new-project]")) { openProjectModal(); return; }
  var open = e.target.closest ? e.target.closest("[data-open-project]") : null;
  if (open) { openProjectDetail(Number(open.getAttribute("data-open-project"))); return; }
  var edit = e.target.closest ? e.target.closest("[data-edit-project]") : null;
  if (edit) {
    var pid = Number(edit.getAttribute("data-edit-project"));
    var p = state.projects.filter(function (x) { return x.id === pid; })[0];
    if (p) openEditModal("project", p);
    return;
  }
  var del = e.target.closest ? e.target.closest("[data-del-project]") : null;
  if (del) {
    var did = Number(del.getAttribute("data-del-project"));
    var dp = state.projects.filter(function (x) { return x.id === did; })[0];
    if (dp) requestDeleteProject(dp);
    return;
  }
  var dots = e.target.closest ? e.target.closest(".menu-dots") : null;
  if (dots) { toggleMenu(dots); return; }
  var nextPage = pagerClick(e, state.projectPage, visibleProjects().length);
  if (nextPage !== null) { state.projectPage = nextPage; renderProjectList(); }
}

/* 展开/收起三点菜单。菜单是绝对定位，而表格容器为了横向滚动设了 overflow，
   纵向也会被裁剪——下方放不下时改成向上弹，否则最后一行菜单点不到。 */
function toggleMenu(dots) {
  var pop = dots.parentElement.querySelector(".menu-pop");
  if (!pop) return;
  var wasOpen = pop.classList.contains("open");
  closeAllMenus();
  if (wasOpen) return;
  pop.classList.remove("up");
  pop.classList.add("open");
  var rect = pop.getBoundingClientRect();
  var wrap = pop.closest(".p-table-wrap");
  var limitedBy = wrap ? wrap.getBoundingClientRect() : { top: 0, bottom: window.innerHeight };
  if (rect.bottom > limitedBy.bottom + 1 && rect.top > rect.height + 8) {
    pop.classList.add("up");
  }
}

function closeAllMenus() {
  Array.prototype.forEach.call(document.querySelectorAll(".menu-pop.open"), function (m) {
    m.classList.remove("open");
  });
}

/* ---------- 项目详情（project 视图） ---------- */

function openProjectDetail(projectId) {
  var p = state.projects.filter(function (x) { return x.id === projectId; })[0];
  if (!p) { showError("项目不存在或已被删除"); return; }
  state.currentProjectId = projectId;
  state.currentProject = p;
  state.taskPage = 1;
  savePrefs();
  renderProjectDetail();
  switchView("project");
}

function renderProjectDetail() {
  if (!projectDetailEl) return;
  var p = state.currentProject;
  if (!p) { switchView("config"); return; }
  var tasks = projectTasks(p.id);
  state.taskPage = clampPage(state.taskPage, tasks.length);
  var page = state.taskPage;
  var start = (page - 1) * PAGE_SIZE;
  var rows = tasks.slice(start, start + PAGE_SIZE);

  var successCount = tasks.filter(function (t) { return t.status === "success"; }).length;
  var failureCount = tasks.length - successCount;
  var findingCount = tasks.reduce(function (sum, t) {
    return sum + (Number(t.finding_count) || 0);
  }, 0);
  var lastScan = tasks.reduce(function (latest, t) {
    return Math.max(latest, Number(t.created_at) || 0);
  }, 0);

  var head =
    '<div class="proj-topbar">' +
      '<button type="button" class="back-btn" data-back-projects>← 返回项目管理</button>' +
    "</div>" +
    '<div class="proj-banner">' +
      '<div class="pb-avatar">' + esc((p.name || "?").trim().charAt(0).toUpperCase() || "?") + "</div>" +
      '<div class="pb-info">' +
        '<div class="pb-name">' + esc(p.name) +
          '<span class="chip">' + esc(p.task_count) + " 个任务</span>" +
        "</div>" +
        '<div class="pb-meta">' + (p.description ? esc(p.description) : "（暂无描述）") +
          "　·　创建于 " + esc(fmtTime(new Date(p.created_at * 1000).toISOString())) + "</div>" +
      "</div>" +
      '<div class="pb-actions">' +
        '<button type="button" class="primary" data-new-task>＋ 新建任务</button>' +
        '<button type="button" class="ghost" data-edit-project="' + esc(p.id) + '">编辑项目</button>' +
      "</div>" +
    "</div>";

  var side =
    '<aside class="proj-side">' +
      '<div class="panel">' +
        "<h3>" + PLUS_SVG + "增加任务</h3>" +
        '<p class="hint">选择目标文件与分析能力，运行后结果会自动归档到当前项目。</p>' +
        '<button type="button" class="ps-cta" data-new-task>＋ 新建任务</button>' +
        '<button type="button" class="ps-cta-ghost" data-edit-project="' + esc(p.id) + '">' +
          PENCIL_SVG + "<span>编辑项目</span></button>" +
      "</div>" +
      '<div class="panel">' +
        "<h3>" + CHART_SVG + "项目概览</h3>" +
        '<ul class="side-stat-list">' +
          '<li><span class="ssk">任务</span><span class="ssv">' + esc(tasks.length) + "</span></li>" +
          '<li><span class="ssk">成功 / 失败</span><span class="ssv">' + esc(successCount) + " / " + esc(failureCount) + "</span></li>" +
          '<li><span class="ssk">发现项</span><span class="ssv">' + esc(findingCount) + "</span></li>" +
          '<li><span class="ssk">最近扫描</span><span class="ssv">' +
            (lastScan ? esc(fmtTime(new Date(lastScan * 1000).toISOString())) : "尚未扫描") + "</span></li>" +
        "</ul>" +
      "</div>" +
    "</aside>";

  var table;
  if (!tasks.length) {
    table =
      '<div class="task-empty">' +
        '<div class="te-icon">' + DOC_SVG + "</div>" +
        '<div class="te-title">该项目还没有任务</div>' +
        '<div class="te-desc">点击下方「＋ 新建任务」按钮<br>选择目标文件与分析能力，开始第一次扫描。</div>' +
        '<button type="button" class="te-cta" data-new-task>＋ 新建任务</button>' +
      "</div>";
  } else {
    var body = rows.map(function (t) {
      var caps = (t.capabilities || []).join(", ") || t.modules || "全量";
      var nameCell = t.status === "success"
        ? '<button type="button" class="name-link clamp-2" data-open-task="' + esc(t.id) + '" title="' + esc(t.name) + '">' + esc(t.name) + "</button>"
        : '<span class="clamp-2" title="' + esc(t.name) + '">' + esc(t.name) + "</span>";
      return "<tr>" +
        "<td>" + nameCell + '<div class="cell-sub">' + esc(t.target_name || "—") + " · " + esc(caps) + "</div></td>" +
        '<td class="c-desc"><div class="cell-desc clamp-2" title="' + esc(t.description) + '">' + (t.description ? esc(t.description) : '<span class="cell-sub">（无描述）</span>') + "</div></td>" +
        '<td class="c-status">' + statusChip(t.status) + "</td>" +
        '<td class="c-time">' + esc(fmtTime(new Date(t.created_at * 1000).toISOString())) + "</td>" +
        '<td class="c-actions"><div class="row-actions">' +
          '<button type="button" class="icon-btn" data-edit-task="' + esc(t.id) + '" title="编辑" aria-label="编辑">' +
            PENCIL_SVG + "</button>" +
          '<button type="button" class="small danger-btn" data-del-task="' + esc(t.id) + '">删除</button>' +
        "</div></td>" +
      "</tr>";
    }).join("");
    table =
      '<div class="p-table-wrap"><table class="p-table"><thead><tr>' +
        '<th>任务名称</th><th class="c-desc">描述</th><th>状态</th><th>创建时间</th><th style="text-align:right">操作</th>' +
      "</tr></thead><tbody>" + body + "</tbody></table></div>" +
      pagerHtml(page, tasks.length, "个任务");
  }
  projectDetailEl.innerHTML = head +
    '<div class="proj-layout">' +
      '<div class="proj-main"><div class="panel proj-list-panel">' +
        '<div class="list-head"><div class="lh-main"><h2>任务列表</h2>' +
          '<div class="lh-sub">共 ' + esc(tasks.length) + " 个任务 · 第 " + esc(page) +
            " / " + esc(pageCount(tasks.length)) + " 页</div></div></div>" +
        table +
      "</div></div>" +
      side +
    "</div>";
}

/* 某项目的全部任务（客户端过滤，列表量级小） */
function projectTasks(projectId) {
  return state.tasks.filter(function (t) { return t.project_id === projectId; });
}

function onProjectDetailClick(e) {
  if (e.target.closest && e.target.closest("[data-back-projects]")) { switchView("config"); return; }
  if (e.target.closest && e.target.closest("[data-new-task]")) { openTaskModal(); return; }
  var open = e.target.closest ? e.target.closest("[data-open-task]") : null;
  if (open) { openTask(Number(open.getAttribute("data-open-task"))); return; }
  var editP = e.target.closest ? e.target.closest("[data-edit-project]") : null;
  if (editP) {
    var p = state.currentProject;
    if (p) openEditModal("project", p);
    return;
  }
  var editT = e.target.closest ? e.target.closest("[data-edit-task]") : null;
  if (editT) {
    var tid = Number(editT.getAttribute("data-edit-task"));
    var t = state.tasks.filter(function (x) { return x.id === tid; })[0];
    if (t) openEditModal("task", t);
    return;
  }
  var delT = e.target.closest ? e.target.closest("[data-del-task]") : null;
  if (delT) {
    var did = Number(delT.getAttribute("data-del-task"));
    var dt = state.tasks.filter(function (x) { return x.id === did; })[0];
    if (dt) requestDeleteTask(dt);
    return;
  }
  var tasks = state.currentProject ? projectTasks(state.currentProject.id) : [];
  var nextPage = pagerClick(e, state.taskPage, tasks.length);
  if (nextPage !== null) { state.taskPage = nextPage; renderProjectDetail(); }
}

/* ---------- 新建 / 编辑项目 ---------- */

/* 弹窗焦点管理：打开时记住触发元素，关闭时把焦点还回去；
   打开期间 Tab 只在弹窗内循环，避免键盘用户跑到背后的页面上。
   回归目标存在元素自身上，确认框叠在向导之上时也不会互相覆盖。 */
var FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]),' +
  ' select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function openDialog(el) {
  if (!el) return;
  el._returnFocus = document.activeElement;
  el.hidden = false;
}

function closeDialog(el) {
  if (!el) return;
  el.hidden = true;
  var back = el._returnFocus;
  el._returnFocus = null;
  if (back && back.focus) {
    try { back.focus(); } catch (e) { /* 元素已从 DOM 移除 */ }
  }
}

/* 顶层未隐藏的弹窗（确认框优先级最高，因为它可能叠在向导之上） */
function topDialog() {
  var list = [confirmModal, editModal, projectModal, taskModal];
  for (var i = 0; i < list.length; i++) {
    if (list[i] && !list[i].hidden) return list[i];
  }
  return null;
}

function trapTab(e, dialog) {
  var items = Array.prototype.filter.call(
    dialog.querySelectorAll(FOCUSABLE),
    function (el) { return el.offsetParent !== null; }
  );
  if (!items.length) return;
  var first = items[0];
  var last = items[items.length - 1];
  if (!dialog.contains(document.activeElement)) {
    // 焦点还在弹窗外面（例如刚打开却还没聚焦）：先拉进弹窗，否则 Tab 会继续在背后走
    e.preventDefault();
    first.focus();
    return;
  }
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}

function openProjectModal() {
  if (!projectModal) return;
  openDialog(projectModal);
  projectModalName.value = "";
  projectModalDesc.value = "";
  setTimeout(function () { projectModalName.focus(); }, 30);
}

function closeProjectModal() {
  closeDialog(projectModal);
}

function createProject() {
  var name = projectModalName.value.trim();
  if (!name) { showError("请输入项目名称"); return; }
  apiFetch(
    "/api/projects?name=" + encodeURIComponent(name) +
      "&description=" + encodeURIComponent(projectModalDesc.value.trim()),
    { method: "POST" }
  )
    .then(readJson)
    .then(function (data) {
      if (!data || !data.ok) throw new Error((data && data.error) || "创建项目失败");
      projectModalName.value = "";
      projectModalDesc.value = "";
      closeProjectModal();
      showSuccess("项目「" + data.project.name + "」已创建");
      state.currentProjectId = data.project.id;
      return loadProjects();
    })
    .catch(function (err) { showError(err && err.message ? err.message : String(err)); });
}

/* ---------- 通用编辑弹窗（项目 / 任务） ---------- */

var editModal = $("edit-modal");
var editModalTitle = $("edit-modal-title");
var editModalName = $("edit-modal-name");
var editModalDesc = $("edit-modal-desc");
var editModalSave = $("edit-modal-save");
var editTarget = null;   // { kind: "project"|"task", id }

function openEditModal(kind, obj) {
  if (!editModal || !obj) return;
  editTarget = { kind: kind, id: obj.id };
  var isProject = kind === "project";
  editModalTitle.textContent = isProject ? "编辑项目" : "编辑任务";
  $("edit-modal-name-label").innerHTML = (isProject ? "项目名称" : "任务名称") + ' <span class="req">*</span>';
  $("edit-modal-desc-label").textContent = isProject ? "项目描述" : "任务描述";
  editModalName.value = obj.name || "";
  editModalDesc.value = obj.description || "";
  openDialog(editModal);
  setTimeout(function () { editModalName.focus(); }, 30);
}

function closeEditModal() {
  closeDialog(editModal);
  editTarget = null;
}

function saveEdit() {
  if (!editTarget) return;
  var name = editModalName.value.trim();
  if (!name) { showError("名称不能为空"); return; }
  var desc = editModalDesc.value.trim();
  var base = editTarget.kind === "project" ? "/api/projects/" : "/api/tasks/";
  apiFetch(
    base + editTarget.id + "?name=" + encodeURIComponent(name) +
      "&description=" + encodeURIComponent(desc),
    { method: "PATCH" }
  )
    .then(readJson)
    .then(function (data) {
      if (!data || !data.ok) throw new Error((data && data.error) || "保存失败");
      var wasProject = editTarget && editTarget.kind === "project";
      closeEditModal();
      showSuccess(wasProject ? "项目已保存" : "任务已保存");
      return loadProjects();   // 同时刷新项目与任务列表，详情页也会随之重渲染
    })
    .catch(function (err) { showError(err && err.message ? err.message : String(err)); });
}

/* ---------- 确认对话框 ---------- */

var confirmModal = $("confirm-modal");
var confirmTitleEl = $("confirm-title");
var confirmMessageEl = $("confirm-message");
var confirmOkBtn = $("confirm-ok");
var confirmAction = null;

function openConfirm(title, message, action, okText) {
  if (!confirmModal) { if (window.confirm(message)) action(); return; }
  confirmTitleEl.textContent = title;
  confirmMessageEl.textContent = message;
  confirmOkBtn.textContent = okText || "确认删除";
  confirmAction = action;
  openDialog(confirmModal);
}

function closeConfirm() {
  closeDialog(confirmModal);
  confirmAction = null;
}

/* 删除项目：走确认对话框（对应用户描述的"三个点→弹出对话框确认删除"） */
function requestDeleteProject(p) {
  if (!p) return;
  openConfirm("删除项目", "确定删除项目「" + p.name + "」吗？其下全部 " + p.task_count + " 个任务及分析结果会一并删除，此操作不可撤销。", function () {
    apiFetch("/api/projects/" + p.id, { method: "DELETE" })
      .then(readJson)
      .then(function (data) {
        if (!data || !data.ok) throw new Error((data && data.error) || "删除项目失败");
        showSuccess("项目「" + p.name + "」已删除");
        if (state.projectPage > 1) state.projectPage--;
        return loadProjects();
      })
      .catch(function (err) { showError(err && err.message ? err.message : String(err)); });
  });
}

/* 删除任务：同样走确认对话框 */
function requestDeleteTask(t) {
  if (!t) return;
  openConfirm("删除任务", "确定删除任务「" + t.name + "」吗？其分析结果会一并删除，此操作不可撤销。", function () {
    apiFetch("/api/tasks/" + t.id, { method: "DELETE" })
      .then(readJson)
      .then(function (data) {
        if (!data || !data.ok) throw new Error((data && data.error) || "删除任务失败");
        showSuccess("任务「" + t.name + "」已删除");
        if (state.taskPage > 1) state.taskPage--;
        return loadTasks();
      })
      .catch(function (err) { showError(err && err.message ? err.message : String(err)); });
  });
}

/* ---------- 创建任务向导 ---------- */

function openTaskModal() {
  if (!state.currentProjectId) {
    showError("请先进入某个项目的详情页，再创建任务");
    return;
  }
  if (!taskModal) return;
  openDialog(taskModal);
  setTaskWizardStep(1);
  updateRunButton();
  loadPresets();   // 打开向导时刷新预置清单，别用上次的旧列表
}

function closeTaskModal() {
  closeDialog(taskModal);
}

function setTaskWizardStep(step) {
  if (!taskModal) return;
  var steps = taskModal.querySelectorAll(".w-step");
  Array.prototype.forEach.call(steps, function (el) {
    el.classList.toggle("active", Number(el.getAttribute("data-wstep")) === step);
  });
  var panels = taskModal.querySelectorAll(".w-panel");
  Array.prototype.forEach.call(panels, function (el) {
    el.classList.toggle("active", Number(el.getAttribute("data-wpanel")) === step);
  });
  if (taskPrev) taskPrev.disabled = step === 1;
  if (taskNext) taskNext.hidden = step === 2;
  if (runBtn) runBtn.hidden = step === 1;
  updateRunButton();
}

function loadTasks() {
  return apiFetch("/api/tasks", { cache: "no-store" })
    .then(readJson)
    .then(function (data) {
      state.tasks = (data && data.tasks) || [];
      renderHistory();
      refreshNavState();
      if (state.view === "project") renderProjectDetail();
      if (state.view === "overview") { renderOverview(); loadOverview(); }
    })
    .catch(function () { renderHistory(); });
}

function openTask(taskId) {
  apiFetch("/api/tasks/" + taskId, { cache: "no-store" })
    .then(readJson)
    .then(function (data) {
      var task = data && data.task;
      if (!task || !task.result) throw new Error((data && data.error) || "任务结果不存在");
      state.response = task.result;
      renderResults(task.result);
      switchView("results");
      refreshNavState();
    })
    .catch(function (err) { showError(err && err.message ? err.message : String(err)); });
}

/* ================= 结果视图空态 ================= */
/* 没有结果时 result-body（含空 tab 侧栏）必须真正退出布局，否则它会和
   空态同时占位。统一走这里渲染，避免各处手拼字符串后样式漂移。 */
var EMPTY_STATES = {
  idle: {
    cls: "",
    title: "还没有分析结果",
    hint: "进入「项目管理」的项目详情，创建任务（选择目标文件和分析能力）并运行。"
  },
  running: {
    cls: "",
    title: "正在分析，请稍候…",
    hint: "分析在本机 Python 实算，结果出来后按分析器分 Tab 展示。"
  },
  error: {
    cls: "es-error",
    title: "分析未完成",
    hint: ""
  },
  notice: {
    cls: "es-notice",
    title: "已停止本次分析",
    hint: "服务端子进程已终止，可重新选择能力后再次运行。"
  }
};

function showEmptyState(kind, message) {
  var cfg = EMPTY_STATES[kind] || EMPTY_STATES.idle;
  emptyState.className = cfg.cls;
  emptyState.hidden = false;
  emptyState.innerHTML =
    '<div class="es-title">' + esc(cfg.title) + "</div>" +
    '<div class="es-hint">' +
      (message ? esc(message) : esc(cfg.hint)) +
      (message && cfg.hint ? "<br>" + esc(cfg.hint) : "") +
    "</div>" +
    '<div class="es-back">' +
      '<button class="small" type="button" data-back-config>返回项目管理</button>' +
    "</div>";
  var back = emptyState.querySelector("[data-back-config]");
  if (back) back.addEventListener("click", function () { switchView("config"); });
}

/* showEmptyState 会重建 innerHTML 并自带绑定；首屏那份静态 HTML 只需要一次 */
function bindEmptyStateBack() {
  var back = emptyState.querySelector("[data-back-config]");
  if (back) back.addEventListener("click", function () { switchView("config"); });
}

/* ================= 偏好持久化 ================= */

/* 只记住"选择"（模式 / 勾选的能力 / 服务器路径），不存分析结果。
   上传的 File 对象无法序列化，所以拖拽选择的文件刷新后需要重选。 */
var PREFS_KEY = "soinsight.console.prefs.v1";
/* 清除偏好后置位：避免下一次切视图又把默认偏好写回 localStorage。 */
var prefsCleared = false;

function loadPrefs() {
  try {
    var raw = window.localStorage.getItem(PREFS_KEY);
    if (!raw) return null;
    var data = JSON.parse(raw);
    return data && typeof data === "object" ? data : null;
  } catch (e) {
    return null;   // 隐私模式 / JSON 脏数据：静默回退到默认值
  }
}

function savePrefs() {
  // 用户主动清空过偏好后不再自动写回，直到他重新做出一次选择。
  if (prefsCleared) return;
  try {
    window.localStorage.setItem(PREFS_KEY, JSON.stringify({
      mode: state.mode,
      capabilities: state.capabilities,
      currentProjectId: state.currentProjectId,
      path: pathInput ? pathInput.value : ""
    }));
  } catch (e) { /* 配额满或被禁用：持久化失败不影响分析 */ }
}

function restorePrefs() {
  var prefs = loadPrefs();
  if (!prefs) return;
  if (prefs.mode === "scan") state.mode = "scan";
  if (prefs.currentProjectId) state.currentProjectId = prefs.currentProjectId;
  if (Object.prototype.toString.call(prefs.capabilities) === "[object Array]") {
    state.capabilities = prefs.capabilities.filter(function (id) {
      return typeof id === "string" && id;
    });
  }
  if (prefs.path) {
    pathInput.value = prefs.path;
    useTypedPath();          // 恢复上次的目标文件（不存在时运行会给出明确报错）
  }
}

/* ================= 设置视图 ================= */

/* 设置页只展示「浏览器偏好」与「服务环境」两类事实：
   前者能改（清掉回到默认），后者只能看（由本地服务决定）。 */
function renderSettings() {
  if (!settingsPrefs) return;
  var project = state.projects.filter(function (p) { return p.id === state.currentProjectId; })[0];
  settingsPrefs.innerHTML = kv([
    ["分析模式", state.mode === "scan" ? "组合扫描（全部已实现能力）" : "多选能力"],
    ["已选能力", state.capabilities.length ? state.capabilities.join(", ") : "（未选择）"],
    ["服务器路径", pathInput && pathInput.value ? pathInput.value : "（未设置）"],
    ["当前项目", project ? project.name : "（未选择）"]
  ]);

  if (!settingsEnv) return;
  var h = state.health;
  if (!h) {
    settingsEnv.innerHTML = kv([["服务状态", "未连接到本地分析服务"]]);
    return;
  }
  settingsEnv.innerHTML = kv([
    ["服务状态", "正常"],
    ["版本", "v" + h.version],
    ["Python", h.python],
    ["平台", h.platform],
    ["仓库根目录", h.repo_root],
    ["已注册 Analyzer", String((h.registered_analyzers || []).length)],
    ["单次分析超时上限", h.analysis_timeout_seconds + " s"]
  ]);
}

/* 清除偏好：只动 localStorage 与页面状态，项目/任务在 SQLite 里，不受影响。 */
function clearPrefs() {
  openConfirm("清除本地偏好",
    "分析模式、已选能力、服务器路径与当前项目选择都会回到初始状态；已保存的项目、任务与分析结果不受影响。",
    function () {
      state.mode = "multi";
      state.capabilities = [];
      state.currentProjectId = null;
      state.currentProject = null;
      state.include = "";
      state.exclude = "";
      if (pathInput) pathInput.value = "";
      clearTarget();
      if (state.view === "project") switchView("config");   // 当前项目没了，详情页退回列表
      syncCapabilitySelection();   // 内部会 savePrefs()，所以删 key 放在最后
      updateRunButton();
      try { window.localStorage.removeItem(PREFS_KEY); } catch (e) { /* 隐私模式：内存状态已重置 */ }
      prefsCleared = true;
      renderSettings();
      showSuccess("本地偏好已清除");
    }, "清除");
}

/* ================= 初始化 ================= */

function init() {
  restorePrefs();
  buildPresets(null);   // 先用页面内置清单渲染，未连服务时面板也有内容
  renderCapabilityGrid();
  renderCapCount();
  refreshNavState();
  bindEvents();
  bindEmptyStateBack();
  renderOverview();
  syncTopbarHeight();
  window.addEventListener("resize", syncTopbarHeight);
  checkHealth();
  // 服务可能在页面打开后才启动/关闭：低频轮询一次，断线时能自己恢复
  state.healthTimer = setInterval(function () {
    if (document.hidden) return;   // 后台标签页不发请求
    checkHealth(true);
  }, HEALTH_POLL_MS);
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) checkHealth(true);   // 回到前台立刻补一次
  });
}

/* 顶栏高度随内容变化（窄屏时健康状态会换行），左侧固定导航要贴着它的下沿，
   否则导航与顶栏之间会露出 19px 的背景色缝隙。 */
function syncTopbarHeight() {
  var topbar = document.querySelector(".topbar");
  if (!topbar) return;
  document.documentElement.style.setProperty("--topbar-h", topbar.offsetHeight + "px");
}

function bindEvents() {
  dropzone.addEventListener("click", function () { fileInput.click(); });
  fileInput.addEventListener("change", function () {
    if (fileInput.files && fileInput.files[0]) setUploadTarget(fileInput.files[0]);
    fileInput.value = "";
  });
  ["dragenter", "dragover"].forEach(function (ev) {
    dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.add("drag"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.remove("drag"); });
  });
  dropzone.addEventListener("drop", function (e) {
    var file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (file) setUploadTarget(file);
  });

  $("use-sample").addEventListener("click", useSelectedSample);
  $("use-path").addEventListener("click", useTypedPath);
  pathInput.addEventListener("keydown", function (e) { if (e.key === "Enter") useTypedPath(); });
  $("chip-clear").addEventListener("click", clearTarget);
  $("cap-all").addEventListener("click", selectAllCapabilities);
  $("cap-none").addEventListener("click", clearCapabilities);
  if (presetSelect) {
    presetSelect.addEventListener("change", syncPresetButtons);
  }
  if (presetApplyBtn) presetApplyBtn.addEventListener("click", applySelectedPreset);
  if (presetSaveBtn) presetSaveBtn.addEventListener("click", saveCurrentPreset);
  if (presetDeleteBtn) presetDeleteBtn.addEventListener("click", deleteSelectedPreset);
  if (presetName) {
    presetName.addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); saveCurrentPreset(); }
    });
  }
  $("project-new").addEventListener("click", openProjectModal);
  $("overview-new-project").addEventListener("click", openProjectModal);
  $("overview-retry").addEventListener("click", function () { checkHealth(); });
  projectModalClose.addEventListener("click", closeProjectModal);
  projectModalCancel.addEventListener("click", closeProjectModal);
  projectModalCreate.addEventListener("click", createProject);
  projectModalName.addEventListener("keydown", function (e) { if (e.key === "Enter") createProject(); });
  projectModal.addEventListener("click", function (e) { if (e.target === projectModal) closeProjectModal(); });
  confirmModal.addEventListener("click", function (e) { if (e.target === confirmModal) closeConfirm(); });
  if (projectSearch) projectSearch.addEventListener("input", function () {
    state.projectQuery = projectSearch.value.trim().toLowerCase();
    state.projectPage = 1;
    renderProjectList();
  });
  // Tab 在弹窗内循环：不接这一步的话键盘用户会 Tab 到背后被遮挡的页面上
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Tab") return;
    var dlg = topDialog();
    if (dlg) trapTab(e, dlg);
  });
  // Esc 从上到下关闭最顶层弹窗；分析运行中不关向导，避免误触
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    if (taskModal && !taskModal.hidden && state.running) return;
    if (confirmModal && !confirmModal.hidden) { closeConfirm(); return; }
    if (editModal && !editModal.hidden) { closeEditModal(); return; }
    if (projectModal && !projectModal.hidden) { closeProjectModal(); return; }
    if (taskModal && !taskModal.hidden) { closeTaskModal(); return; }
    closeAllMenus();
  });
  // 项目管理列表 / 项目详情：事件委托
  if (projectListEl) projectListEl.addEventListener("click", onProjectListClick);
  if (projectDetailEl) projectDetailEl.addEventListener("click", onProjectDetailClick);
  // 通用编辑弹窗
  $("edit-modal-close").addEventListener("click", closeEditModal);
  $("edit-modal-cancel").addEventListener("click", closeEditModal);
  if (editModalSave) editModalSave.addEventListener("click", saveEdit);
  editModalName.addEventListener("keydown", function (e) { if (e.key === "Enter") saveEdit(); });
  editModal.addEventListener("click", function (e) { if (e.target === editModal) closeEditModal(); });
  // 确认对话框
  $("confirm-close").addEventListener("click", closeConfirm);
  $("confirm-cancel").addEventListener("click", closeConfirm);
  confirmOkBtn.addEventListener("click", function () {
    var action = confirmAction;
    closeConfirm();
    if (action) action();
  });
  if (settingsClear) settingsClear.addEventListener("click", clearPrefs);
  taskClose.addEventListener("click", closeTaskModal);
  taskCancel.addEventListener("click", closeTaskModal);
  taskPrev.addEventListener("click", function () { setTaskWizardStep(1); });
  taskNext.addEventListener("click", function () {
    if (!state.target) { showError("请先选择目标文件"); return; }
    setTaskWizardStep(2);
  });
  taskModal.addEventListener("click", function (e) {
    if (e.target === taskModal) closeTaskModal();
  });
  taskNameInput.addEventListener("keydown", function (e) {
    if (e.key !== "Enter") return;
    if (taskNext && !taskNext.hidden) taskNext.click();
    else if (runBtn && !runBtn.hidden) runBtn.click();
  });
  runBtn.addEventListener("click", runAnalysis);
  cancelBtn.addEventListener("click", cancelRun);
  pcCancel.addEventListener("click", cancelRun);
  $("retry-health").addEventListener("click", function () { checkHealth(); });
  Array.prototype.forEach.call(sidenav.querySelectorAll(".nav-item"), function (btn) {
    btn.addEventListener("click", function () { switchView(btn.dataset.view); });
  });
  // 阻止 checkbox 的默认行为冒泡到 <details> summary，避免误折叠/误聚焦
  resultTabs.addEventListener("mousedown", function (e) {
    var target = e.target;
    if (!target || !target.closest) return;
    if (target.closest(".result-group-check") || target.closest(".result-cap-check")) {
      e.preventDefault();
      e.stopPropagation();
    }
  });
  resultTabs.addEventListener("click", function (e) {
    var target = e.target;
    if (!target || !target.closest) return;
    var capCheck = target.closest(".result-cap-check");
    if (capCheck) {
      e.preventDefault();
      e.stopPropagation();
      toggleResultCap(capCheck.getAttribute("data-result-cap"));
      return;
    }
    var groupCheck = target.closest(".result-group-check");
    if (groupCheck) {
      // 只切换大类可见性，不让 checkbox 的无意冒泡把 <details> 折叠掉
      e.preventDefault();
      e.stopPropagation();
      toggleResultGroup(groupCheck.getAttribute("data-result-group"));
      return;
    }
    var btn = target.closest(".tab");
    if (btn) selectTab(btn.getAttribute("data-tab"));
  });
  resultTabs.addEventListener("keydown", function (e) {
    if (e.key === "ArrowUp") { e.preventDefault(); stepTab(-1); }
    if (e.key === "ArrowDown") { e.preventDefault(); stepTab(1); }
  });
  $("download-json").addEventListener("click", downloadJson);
  $("download-findings").addEventListener("click", exportFindingsCsv);
  pathInput.addEventListener("change", savePrefs);

  document.addEventListener("input", function (e) {
    var role = e.target.dataset ? e.target.dataset.role : "";
    if (role === "sym-q") { state.sym.q = e.target.value.trim().toLowerCase(); state.sym.shown = 200; rerenderSymbols(); }
    if (role === "sym-lang") { state.sym.lang = e.target.value; state.sym.shown = 200; rerenderSymbols(); }
  });
  document.addEventListener("click", function (e) {
    // 点击三个点菜单与其弹层之外的区域时收起所有打开的菜单
    if (e.target.closest && !e.target.closest(".menu-wrap")) closeAllMenus();
    var gotoBtn = e.target.closest ? e.target.closest("[data-goto-view]") : null;
    if (gotoBtn) { switchView(gotoBtn.dataset.gotoView); return; }
    var role = e.target.dataset ? e.target.dataset.role : "";
    if (role === "sym-more") { state.sym.shown += 400; rerenderSymbols(); }
    if (role === "sym-csv") exportSymbolsCsv();
    if (role === "finding-csv") exportFindingsCsv();
    var ovTask = e.target.closest ? e.target.closest("[data-ov-task]") : null;
    if (ovTask) { openTask(Number(ovTask.getAttribute("data-ov-task"))); return; }
    var ovProject = e.target.closest ? e.target.closest("[data-ov-project]") : null;
    if (ovProject) { openProjectDetail(Number(ovProject.getAttribute("data-ov-project"))); return; }
    onHistoryClick(e);
  });
}

/* 拉取服务端的能力登记表，填充 CATALOG_META（名称 + 说明）。
   失败不提示：能力清单本身由 /api/health 决定，这里只是补中文说明。 */
function loadCatalog() {
  return apiFetch("/api/modules", { cache: "no-store" })
    .then(readJson)
    .then(function (data) {
      if (!data || !data.ok) return;
      var meta = {};
      (data.modules || []).forEach(function (mod) {
        (mod.capabilities || []).forEach(function (cap) {
          meta[cap.id] = {
            name: cap.name || "",
            desc: cap.description || ""
          };
        });
      });
      CATALOG_META = meta;
    })
    .catch(function () { /* 说明缺失时退回页面内置 CAP_META */ });
}

var HEALTH_POLL_MS = 15000;      // 健康状态轮询间隔
var _analyzerSig = "";           // 上一次生效的 analyzer 清单签名

/* silent = true 时是轮询触发的后台检查：不闪"正在连接"，也不重复拉列表 */
function checkHealth(silent) {
  var dot = $("health-dot");
  var text = $("health-text");
  var banner = $("banner");
  if (!silent) {
    dot.className = "dot";
    text.textContent = "正在连接本地服务…";
  }
  apiFetch("/api/health", { cache: "no-store", timeout: 8000 })
    .then(readJson)
    .then(function (data) {
      if (!data.ok) throw new Error(data.catalog_error || "服务报告异常");
      var recovered = !state.health;   // 上一次是离线态，这次恢复
      state.health = data;
      state.healthChecked = true;
      state.timeout = Number(data.analysis_timeout_seconds) || state.timeout;
      dot.className = "dot ok";
      text.textContent = "服务正常 · Python " + data.python + " · 超时上限 " + state.timeout + " s";
      $("version-badge").textContent = "v" + data.version + " · " + data.registered_analyzers.length + " Analyzer";
      banner.classList.remove("show");
      // 能力清单只在服务端注册项变化时重建，避免轮询反复重绘勾选状态
      var sig = (data.registered_analyzers || []).join(",");
      if (sig !== _analyzerSig) {
        _analyzerSig = sig;
        loadCatalog().then(function () { applyAnalyzers(data.registered_analyzers); });
        applyAnalyzers(data.registered_analyzers);
      }
      if (recovered || !silent) {
        loadSamples();
        loadPresets();
        loadProjects();
      }
      updateRunButton();
      syncTopbarHeight();   // 顶栏文字变长后高度可能变，导航要跟着
      if (state.view === "settings") renderSettings();
      if (state.view === "overview") { renderOverview(); loadOverview(); }
    })
    .catch(function () {
      var wasOnline = !!state.health;
      state.health = null;
      state.healthChecked = true;
      dot.className = "dot bad";
      text.textContent = "未连接";
      $("version-badge").textContent = "离线模式";
      banner.classList.add("show");
      renderCapCount();
      updateRunButton();
      if (state.view === "settings") renderSettings();
      if (state.view === "overview") renderOverview();
      // 断线时结束正在进行的分析，否则界面会一直停在"分析中"
      if (wasOnline && state.running && !state.cancelling) {
        showError("与本地服务的连接已断开，本次分析中断。");
        if (state.abort) state.abort.abort();
      }
    });
}

function loadSamples() {
  apiFetch("/api/samples", { cache: "no-store" })
    .then(readJson)
    .then(function (data) {
      state.samples = data.samples || [];
      sampleSelect.innerHTML = state.samples.length
        ? '<option value="">— 选择 in/ 目录样本（' + state.samples.length + " 个）—</option>" +
          state.samples.map(function (s, i) {
            return '<option value="' + i + '">' + esc(s.name) + " · " + fmtBytes(s.size) + "</option>";
          }).join("")
        : '<option value="">（in/ 目录没有样本）</option>';
    })
    .catch(function () {
      sampleSelect.innerHTML = '<option value="">（样本列表加载失败）</option>';
    });
}

/* ================= 目标选择 ================= */

function refreshTargetName() {
  if (targetNameInput && state.target && !targetNameInput.value.trim()) {
    targetNameInput.value = state.target.name || "";
  }
}

function setUploadTarget(file) {
  state.target = { kind: "upload", name: file.name, size: file.size, file: file };
  renderTargetChip("上传文件");
  refreshTargetName();
}

function useSelectedSample() {
  var index = sampleSelect.value;
  if (index === "") return;
  var sample = state.samples[Number(index)];
  if (!sample) return;
  state.target = { kind: "sample", name: sample.name, size: sample.size, path: sample.path };
  renderTargetChip("验证样本");
  refreshTargetName();
}

function useTypedPath() {
  var value = pathInput.value.trim();
  if (!value) return;
  var name = value.split(/[\\/]/).pop() || value;
  state.target = { kind: "path", name: name, size: null, path: value };
  // The filters travel with the target: a directory is expanded with them.
  state.include = ($("include-input").value || "").trim();
  state.exclude = ($("exclude-input").value || "").trim();
  renderTargetChip("服务器路径");
  refreshTargetName();
}

function clearTarget() {
  state.target = null;
  targetChip.hidden = true;
  if (targetNameInput) targetNameInput.value = "";
  updateRunButton();
}

function renderTargetChip(sourceLabel) {
  chipName.textContent = state.target.name;
  chipMeta.textContent = sourceLabel +
    (state.target.size != null ? " · " + fmtBytes(state.target.size) : " · 大小将在分析后显示");
  targetChip.hidden = false;
  updateRunButton();
}

/* ================= 能力选择 ================= */

/* 按服务端返回的 analyzer id 清单重建可选能力。
   registered 为空时回退到页面内置的 CAP_META 顺序（离线预览用）。
   名称以 /api/modules 的登记信息为准；说明优先用页面里更详细的 CAP_META，
   页面没登记的新能力则直接用服务端的 description。 */
function buildPresets(registered) {
  var source = (registered && registered.length) ? registered : CAP_META_ORDER;
  PRESETS = source.map(function (id) {
    var remote = CATALOG_META[id];
    var local = CAP_META[id];
    var name = (remote && remote.name) || (local && local.name) || "";
    return {
      id: id,
      name: name || id,
      brief: (local && local.brief) || "",
      desc: (local && local.desc) || (remote && remote.desc) || "",
      unknown: !name
    };
  });
}

/* health 返回后刷新清单：保留仍存在的勾选，剔除服务端已移除的能力 */
function applyAnalyzers(registered) {
  buildPresets(registered);
  state.capabilities = state.capabilities.filter(function (id) {
    return PRESETS.filter(function (p) { return p.id === id; }).length > 0;
  });
  renderCapabilityGrid();
  renderCapCount();
  updateRunButton();
}

function renderCapCount() {
  var el = $("cap-count");
  if (!el) return;
  if (!state.health) {
    el.textContent = "未连接服务，下面是页面内置清单，连接后会改为以服务端返回为准。";
    return;
  }
  var unknown = PRESETS.filter(function (p) { return p.unknown; }).length;
  el.textContent = "当前服务端注册 " + PRESETS.length + " 个 Analyzer，全部可选" +
    (unknown ? "（其中 " + unknown + " 个页面缺少中文说明，显示原名）" : "") + "。";
}

/* 模块分组元数据：id 前缀 -> 展示名。新模块在此补一条即可。 */
var CAP_GROUPS = [
  { key: "basic",     name: "基础解析",   open: true },
  { key: "advanced",  name: "深度分析",   open: true },
  { key: "security",  name: "安全检测",   open: true },
  { key: "dynamic",   name: "动态执行",   open: false },
  { key: "automation", name: "自动化",     open: false },
  { key: "ai",        name: "AI 辅助",    open: false }
];

function groupOf(id) {
  var dot = id.indexOf(".");
  return dot > 0 ? id.slice(0, dot) : "other";
}

function renderCapabilityGrid() {
  // 主行：英文能力 id；副行：中文名 + 简短说明。id 是 CLI / JSON 里的正式名称，
  // 放主位便于与服务端输出对照，中文短语只作辅助说明。
  var cardHtml = function (preset) {
    return '<div class="cap-card" data-cap="' + esc(preset.id) + '" role="button" tabindex="0" aria-pressed="false"' +
      (preset.desc ? ' title="' + esc(preset.desc) + '"' : "") + ">" +
      '<span class="check" aria-hidden="true">✓</span>' +
      '<div class="t"><span class="cmd">' + esc(preset.id) + "</span></div>" +
      '<div class="d"><b>' + esc(preset.name) + "</b>" +
      (preset.brief ? " · " + esc(preset.brief) : "") +
      "</div></div>";
  };

  var buckets = {};
  PRESETS.forEach(function (preset) {
    var key = groupOf(preset.id);
    (buckets[key] = buckets[key] || []).push(preset);
  });
  // 分组表里没有的模块（例如插件注册的新前缀）归到"其他"，避免能力消失
  Object.keys(buckets).forEach(function (key) {
    if (!CAP_GROUPS.some(function (g) { return g.key === key; })) {
      CAP_GROUPS.push({ key: key, name: key, open: false });
    }
  });

  var html = CAP_GROUPS.map(function (group) {
    var items = buckets[group.key] || [];
    if (!items.length) return "";
    var selected = items.filter(function (p) {
      return state.capabilities.indexOf(p.id) >= 0;
    }).length;
    return '<details class="cap-group" data-group="' + esc(group.key) + '"' +
      (group.open ? " open" : "") + ">" +
      "<summary>" +
        '<span class="g-name">' + esc(group.name) + "</span>" +
        '<span class="g-count">' + selected + "/" + items.length + "</span>" +
        '<button type="button" class="g-all" data-group-all="' + esc(group.key) + '">全选</button>' +
      "</summary>" +
      '<div class="g-body">' + items.map(cardHtml).join("") + "</div>" +
      "</details>";
  }).join("");

  // 组合扫描开关保留在末尾，与分组列表互斥
  html += '<details class="cap-group" data-group="__scan">' +
    "<summary>" +
      '<span class="g-name">' + esc(SCAN_PRESET.name) + "</span>" +
      '<span class="g-count">scan --module-available</span>' +
    "</summary>" +
    '<div class="g-body">' +
      cardHtml({ id: "scan", name: SCAN_PRESET.name, brief: SCAN_PRESET.brief }) +
    "</div></details>";

  capGrid.innerHTML = html;
  Array.prototype.forEach.call(capGrid.querySelectorAll(".cap-card"), function (card) {
    var activate = function () {
      if (card.dataset.cap === "scan") {
        // 组合扫描是独立开关：开启后忽略单项勾选，运行全部已实现分析器
        state.mode = state.mode === "scan" ? "multi" : "scan";
      } else {
        var id = card.dataset.cap;
        var index = state.capabilities.indexOf(id);
        if (index >= 0) state.capabilities.splice(index, 1);
        else state.capabilities.push(id);
      }
      syncCapabilitySelection();
      updateRunButton();
    };
    card.addEventListener("click", activate);
    card.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); activate(); }
    });
  });
  Array.prototype.forEach.call(capGrid.querySelectorAll("[data-group-all]"), function (btn) {
    btn.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();   // 别顺手把 <details> 折叠了
      toggleGroup(btn.dataset.groupAll);
    });
  });
  syncCapabilitySelection();
}

/* 组级全选：已全选则取消本组，否则勾满本组 */
function toggleGroup(groupKey) {
  var items = PRESETS.filter(function (p) { return groupOf(p.id) === groupKey; });
  if (!items.length) return;
  var allSelected = items.every(function (p) {
    return state.capabilities.indexOf(p.id) >= 0;
  });
  items.forEach(function (p) {
    var index = state.capabilities.indexOf(p.id);
    if (allSelected && index >= 0) state.capabilities.splice(index, 1);
    else if (!allSelected && index < 0) state.capabilities.push(p.id);
  });
  if (state.mode === "scan") state.mode = "multi";
  syncCapabilitySelection();
  updateRunButton();
}

function syncCapabilitySelection() {
  var scanMode = state.mode === "scan";
  Array.prototype.forEach.call(capGrid.querySelectorAll(".cap-card"), function (card) {
    var isScan = card.dataset.cap === "scan";
    var selected = isScan ? scanMode : state.capabilities.indexOf(card.dataset.cap) >= 0;
    card.classList.toggle("selected", selected);
    card.classList.toggle("dim", !selected && scanMode);
    card.setAttribute("aria-pressed", selected ? "true" : "false");
  });
  syncGroupCounts();
  prefsCleared = false;   // 用户又做了选择，重新开始持久化
  savePrefs();   // 勾选变化即持久化，刷新后自动恢复
}

/* 分组标题上的 n/m 计数随勾选变化 */
function syncGroupCounts() {
  Array.prototype.forEach.call(capGrid.querySelectorAll(".cap-group"), function (group) {
    var key = group.dataset.group;
    if (key === "__scan") return;
    var items = PRESETS.filter(function (p) { return groupOf(p.id) === key; });
    var selected = items.filter(function (p) {
      return state.capabilities.indexOf(p.id) >= 0;
    }).length;
    var countEl = group.querySelector(".g-count");
    if (countEl) countEl.textContent = selected + "/" + items.length;
    var allBtn = group.querySelector("[data-group-all]");
    if (allBtn) allBtn.textContent = selected === items.length && items.length ? "取消" : "全选";
  });
}

function selectAllCapabilities() {
  state.capabilities = PRESETS.map(function (p) { return p.id; });
  state.mode = "multi";
  syncCapabilitySelection();
  updateRunButton();
}

function clearCapabilities() {
  state.capabilities = [];
  state.mode = "multi";
  syncCapabilitySelection();
  updateRunButton();
}

function updateRunButton() {
  var hasProject = !!state.currentProjectId;
  var hasCaps = state.capabilities.length > 0;
  var ready = hasProject && !!state.target && !!state.health && !state.running &&
    (state.mode === "scan" || hasCaps);
  if (runBtn) runBtn.disabled = !ready;
  if (!runStatus) return;
  if (state.running) return;
  if (!hasProject) runStatus.textContent = "请先在项目详情里创建任务";
  else if (!state.target) runStatus.textContent = "请选择目标文件";
  else if (!state.health) runStatus.textContent = "本地服务未连接，无法运行";
  else if (state.mode !== "scan" && !hasCaps) runStatus.textContent = "请至少勾选一项分析能力";
  else if (state.mode === "scan") runStatus.textContent = "就绪：组合扫描 basic + advanced + security";
  else runStatus.textContent = "就绪：" + state.capabilities.join(" + ") + "（" + state.capabilities.length + " 项）";
}

/* ================= 预置分析脚本 ================= */
/* 预置 = 一组勾选（mode + capabilities）存成服务端的一个 JSON 文件，
   下次选中即可一次性套用，避免每次逐项点选。 */

function loadPresets() {
  if (!presetSelect) return;
  apiFetch("/api/presets", { cache: "no-store" })
    .then(readJson)
    .then(function (data) {
      state.presets = (data && data.presets) || [];
      renderPresetOptions();
    })
    .catch(function () {
      state.presets = [];
      renderPresetOptions();
    });
}

function renderPresetOptions() {
  if (!presetSelect) return;
  var current = presetSelect.value;
  presetSelect.innerHTML = '<option value="">— 不使用预置 —</option>' +
    state.presets.map(function (p) {
      var label = p.name + (p.mode === "scan"
        ? " · 组合扫描"
        : " · " + p.capabilities.length + " 项");
      return '<option value="' + esc(p.id) + '">' + esc(label) + "</option>";
    }).join("");
  var stillExists = state.presets.some(function (p) { return p.id === current; });
  presetSelect.value = stillExists ? current : "";
  syncPresetButtons();
}

function selectedPreset() {
  if (!presetSelect || !presetSelect.value) return null;
  var id = presetSelect.value;
  return state.presets.filter(function (p) { return p.id === id; })[0] || null;
}

function syncPresetButtons() {
  var has = !!selectedPreset();
  if (presetApplyBtn) presetApplyBtn.disabled = !has;
  if (presetDeleteBtn) presetDeleteBtn.disabled = !has;
}

/* 套用预置：直接覆盖当前 mode 与勾选，再走统一同步逻辑 */
function applySelectedPreset() {
  var preset = selectedPreset();
  if (!preset) return;
  var known = PRESETS.map(function (p) { return p.id; });
  var usable = preset.capabilities.filter(function (id) { return known.indexOf(id) >= 0; });
  state.mode = preset.mode === "scan" ? "scan" : "multi";
  state.capabilities = usable;
  syncCapabilitySelection();
  updateRunButton();
  var missing = preset.capabilities.length - usable.length;
  showSuccess("已套用预置「" + preset.name + "」：共 " + usable.length + " 项" +
    (missing > 0 ? "（" + missing + " 项当前服务端不可用，已跳过）" : ""));
}

function saveCurrentPreset() {
  if (!presetName) return;
  var name = presetName.value.trim();
  if (!name) { showError("请先填写预置名称"); presetName.focus(); return; }
  if (state.mode !== "scan" && !state.capabilities.length) {
    showError("请至少勾选一项分析能力后再保存预置");
    return;
  }
  var params = new URLSearchParams();
  params.set("name", name);
  params.set("mode", state.mode);
  if (state.mode !== "scan") params.set("capabilities", state.capabilities.join(","));
  apiFetch("/api/presets?" + params.toString(), { method: "POST" })
    .then(readJson)
    .then(function (data) {
      if (!data || !data.ok) throw new Error((data && data.error) || "保存预置失败");
      presetName.value = "";
      return apiFetch("/api/presets", { cache: "no-store" })
        .then(readJson)
        .then(function (list) {
          state.presets = (list && list.presets) || [];
          renderPresetOptions();
          presetSelect.value = data.preset.id;
          syncPresetButtons();
          showSuccess("预置「" + data.preset.name + "」已保存");
        });
    })
    .catch(function (err) { showError(err && err.message ? err.message : String(err)); });
}

function deleteSelectedPreset() {
  var preset = selectedPreset();
  if (!preset) return;
  openConfirm("删除预置", "确定删除预置分析脚本「" + preset.name + "」吗？", function () {
    apiFetch("/api/presets/" + encodeURIComponent(preset.id), { method: "DELETE" })
      .then(readJson)
      .then(function (data) {
        if (!data || !data.ok) throw new Error((data && data.error) || "删除预置失败");
        showSuccess("预置「" + preset.name + "」已删除");
        if (presetSelect) presetSelect.value = "";
        loadPresets();
      })
      .catch(function (err) { showError(err && err.message ? err.message : String(err)); });
  });
}

/* ================= 视图切换 ================= */

function switchView(name) {
  if (state.view === name) return;
  state.view = name;
  closeProjectModal();
  closeTaskModal();
  closeEditModal();
  closeConfirm();
  closeAllMenus();
  Array.prototype.forEach.call(document.querySelectorAll(".view"), function (view) {
    view.classList.toggle("active", view.dataset.view === name);
  });
  // 项目详情属于"项目管理"的子页面，左侧导航保持高亮在项目管理上
  var navName = name === "project" ? "config" : name;
  Array.prototype.forEach.call(sidenav.querySelectorAll(".nav-item"), function (btn) {
    btn.classList.toggle("active", btn.dataset.view === navName);
  });
  if (name === "overview") { renderOverview(); loadOverview(); }
  if (name === "history") renderHistory();
  if (name === "settings") renderSettings();
  if (name !== "results") savePrefs();
  window.scrollTo({ top: 0, behavior: "instant" in window ? "instant" : "auto" });
}

/* 结果视图是否可进：至少产生过一次结果 */
function refreshNavState() {
  var hasResult = !!state.response;
  navResults.disabled = !hasResult;
  resultsBadge.hidden = !hasResult;
  historyBadge.hidden = state.tasks.length === 0;
  historyBadge.textContent = state.tasks.length;
}

/* ================= 运行分析 ================= */

function runAnalysis() {
  if (state.running || !state.target) return;
  if (state.mode !== "scan" && !state.capabilities.length) return;
  if (!state.currentProjectId) {
    showError("请先进入某个项目的详情页，再创建任务");
    return;
  }
  closeTaskModal();
  clearResults();                       // 每次运行前先清空上一次的分析结果
  showEmptyState("running");
  state.running = true;
  state.cancelling = false;
  runBtn.disabled = true;
  runSpinner.classList.add("on");
  runLabel.textContent = "分析中…";
  cancelBtn.hidden = false;
  cancelBtn.disabled = false;
  cancelBtn.textContent = "■ 停止分析";
  // 点运行即跳到结果视图，进度卡片接管后续反馈
  showProgress();
  switchView("results");
  // 上一次运行的 interval 必须真正停掉：finally 里只 clear 不清引用，
  // 残留的 id 会绕过 runBtn.disabled 之类的守卫继续跑。
  clearInterval(state.timer);
  state.timer = null;
  var startedAt = performance.now();
  state.timer = setInterval(function () {
    var secs = ((performance.now() - startedAt) / 1000).toFixed(1);
    elapsedEl.textContent = "已用 " + secs + " s / 上限 " + state.timeout + " s";
    pcElapsed.textContent = "已用 " + secs + " s / 上限 " + state.timeout + " s";
  }, 100);

  var params = new URLSearchParams();
  params.set("mode", state.mode);
  params.set("project_id", String(state.currentProjectId));
  // 向导里显式填写的「任务名称」优先于自动带入的目标名称
  params.set("task_name",
    taskNameInput.value.trim() || (targetNameInput && targetNameInput.value.trim()) || "");
  params.set("task_description", taskDescInput ? taskDescInput.value.trim() : "");
  if (state.mode === "scan") params.set("modules", "basic,advanced,security");
  else params.set("capabilities", state.capabilities.join(","));

  var headers = {};
  var body;
  if (state.target.kind === "upload") {
    body = state.target.file;
    headers["X-Filename"] = state.target.name;
  } else {
    params.set("path", state.target.path);
    if (state.include) params.set("include", state.include);
    if (state.exclude) params.set("exclude", state.exclude);
  }

  // 分析请求的超时要比服务端自己的超时更宽，否则会先于服务端报超时
  var controller = new AbortController();
  state.abort = controller;
  apiFetch("/api/analyze?" + params.toString(), {
    method: "POST",
    headers: headers,
    body: body,
    signal: controller.signal,
    timeout: (state.timeout + 30) * 1000
  })
    .then(function (resp) {
      return readJson(resp).then(function (data) {
        if (!data.ok && !data.payload) {
          var detail = [data.error || ("HTTP " + resp.status)];
          if (data.stderr_tail) detail.push("—— 子进程输出 ——\n" + data.stderr_tail.trim());
          throw new Error(detail.join("\n"));
        }
        state.response = data;
        renderResults(data);
        loadProjects();   // 服务端已把任务写入数据库，刷新项目与任务列表
      });
    })
    .catch(function (err) {
      var message = err && err.message ? err.message : String(err);
      if (message.indexOf("已取消") >= 0) {
        showNotice("已停止本次分析，服务端子进程已终止。");
        showEmptyState("notice");
      } else {
        showError(message);
        showEmptyState("error", message);
      }
      resultBody.hidden = true;
    })
    .then(function () {  // finally（无参 then 总会在其后执行）
      clearInterval(state.timer);
      state.timer = null;
      state.abort = null;
      hideProgress();
      state.running = false;
      state.cancelling = false;
      runSpinner.classList.remove("on");
      runLabel.textContent = "▶ 运行分析";
      elapsedEl.textContent = "";
      cancelBtn.hidden = true;
      cancelBtn.disabled = false;
      cancelBtn.textContent = "■ 停止分析";
      if (taskDescInput) taskDescInput.value = "";   // 描述是一次性的，运行后清空
      updateRunButton();
      refreshNavState();
    });
}

/* 停止正在跑的分析：服务端会 kill 子进程，请求随即以 "分析已取消" 返回。 */
function cancelRun() {
  if (!state.running || state.cancelling) return;
  state.cancelling = true;
  cancelBtn.disabled = true;
  cancelBtn.textContent = "正在停止…";
  runStatus.textContent = "正在停止分析…";
  apiFetch("/api/cancel", { method: "POST" })
    .then(readJson)
    .then(function (data) {
      // 没有可取消的任务（例如刚好结束）：不改 UI，等 analyze 请求自己收尾
      if (!data || !data.cancelled) runStatus.textContent = "分析已结束，正在收尾…";
    })
    .catch(function () {
      // 服务不可达时本地中断请求，避免界面卡在"正在停止"
      if (state.abort) state.abort.abort();
    });
}

/* ================= 全局轻提示（toast） ================= */

/* 统一从右下角弹出，自动消失；错误停留更久。
   旧版写在项目管理面板里的 error-box 在其他视图看不见，已废弃。 */
function showToast(message, kind) {
  if (!toastBox) return;
  var el = document.createElement("div");
  el.className = "toast " + (kind || "notice");
  el.textContent = message;
  toastBox.appendChild(el);
  while (toastBox.children.length > 4) toastBox.removeChild(toastBox.firstChild);
  setTimeout(function () {
    el.classList.add("out");
    setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 260);
  }, kind === "error" ? 4500 : 2400);
}

function showError(message) { showToast(message, "error"); }

function showNotice(message) { showToast(message, "notice"); }

function showSuccess(message) { showToast(message, "success"); }

/* ================= 进度卡片 ================= */

function showProgress() {
  if (!state.target) return;
  pcTitle.textContent = "正在分析…";
  pcTarget.textContent = state.target.name +
    (state.target.size != null ? "（" + fmtBytes(state.target.size) + "）" : "");
  var projectName = (state.projects.filter(function (p) { return p.id === state.currentProjectId; })[0] || {}).name || "";
  pcStage.textContent = projectName
    ? projectName + "：组合扫描 basic + advanced + security"
    : state.mode === "scan"
      ? "组合扫描 basic + advanced + security"
      : state.capabilities.length + " 项能力";
  pcElapsed.textContent = "已用 0.0 s";
  progressCard.hidden = false;
}

function hideProgress() {
  progressCard.hidden = true;
}

/* ================= 总览 ================= */

/* 单条任务卡：任务管理页与总览的「最近任务」共用同一套结构，
   点击由 document 上的 onHistoryClick 委托处理。 */
function taskItemHtml(t) {
  var time = new Date(t.created_at * 1000);
  var stamp = time.toLocaleString("zh-CN", { hour12: false });
  var statusCls = t.status === "success" ? "ok" : "fail";
  var caps = (t.capabilities || []).join(", ") || t.modules || "全量";
  return '<div class="history-item" data-tid="' + esc(t.id) + '">' +
    '<div class="h-main">' +
      '<div class="h-name">' + esc(t.project_name || "未分类") + " · " + esc(t.name) + "</div>" +
      '<div class="h-meta">' + esc(stamp) + " · " + esc(t.target_name) +
        " · " + esc(t.mode) + " · " + esc(caps) + "</div>" +
      '<div class="h-meta">' +
        '<span class="chip ' + statusCls + '">' + esc(t.status) + "</span> · " +
        esc(t.analyzer_count) + " 个分析器 · " + esc(t.finding_count) + " 项发现" +
        (typeof t.exit_code === "number" ? " · 退出码 " + esc(t.exit_code) : "") +
      "</div>" +
    "</div>" +
    '<div class="h-acts">' +
      '<button class="small" data-hact="view" type="button">查看</button>' +
      '<button class="small" data-hact="delete" type="button">删除</button>' +
    "</div>" +
  "</div>";
}

/* 百分比：整数或一位小数，去掉多余的 .0 */
function fmtPct(value) {
  var n = Number(value);
  if (!isFinite(n)) return "—";
  return (Math.round(n * 10) / 10).toString().replace(/\.0$/, "") + "%";
}

/* 总览聚合：趋势 / 严重级别 / 失败原因 / 运行中作业都由服务端一次算好。
   页面仍保留 state.tasks 的本地兜底，服务离线时至少能看到已有计数。 */
function loadOverview() {
  if (!state.health) { state.overview = null; renderOverview(); return Promise.resolve(); }
  if (state.overviewLoading) return Promise.resolve();
  state.overviewLoading = true;
  return apiFetch("/api/overview", { cache: "no-store", timeout: 8000 })
    .then(readJson)
    .then(function (data) {
      state.overview = (data && data.ok && data.overview) || null;
    })
    .catch(function () { state.overview = null; })
    .then(function () {
      state.overviewLoading = false;
      if (state.view === "overview") renderOverview();
    });
}

function overviewMetricsHtml() {
  var tasks = state.tasks || [];
  var success = tasks.filter(function (t) { return t.status === "success"; }).length;
  var localFindings = tasks.reduce(function (sum, t) { return sum + (Number(t.finding_count) || 0); }, 0);
  var localDuration = tasks.reduce(function (sum, t) {
    return sum + (typeof t.duration_ms === "number" ? t.duration_ms : 0);
  }, 0);
  var analyzers = (state.health && state.health.registered_analyzers || []).length;
  var ov = state.overview;
  var m = ov && ov.metrics;
  var jobs = ov && ov.jobs;
  var sev = ov && ov.severity;
  var rate = m ? m.success_rate : (tasks.length ? success / tasks.length * 100 : 0);
  var severe = sev ? (Number(sev.critical) || 0) + (Number(sev.high) || 0) : null;
  var avg = m ? m.avg_duration_ms : (tasks.length ? localDuration / tasks.length : 0);
  var items = [
    { n: m ? m.project_count : (state.projects || []).length, l: "项目" },
    { n: m ? m.task_count : tasks.length, l: "任务" },
    { n: fmtPct(rate), l: "成功率" },
    { n: jobs ? (jobs.running || 0) + " / " + (jobs.queued || 0) : "—", l: "运行 / 排队" },
    { n: severe === null ? "—" : severe, l: "高危+严重" },
    { n: m ? m.finding_total : localFindings, l: "发现项" },
    { n: avg ? fmtMs(Math.round(avg)) : "—", l: "平均耗时" },
    { n: analyzers, l: "已注册 Analyzer" }
  ];
  return items.map(function (it) {
    return '<div class="metric"><div class="n">' + esc(it.n) +
      '</div><div class="l">' + esc(it.l) + "</div></div>";
  }).join("");
}

function overviewSeverityHtml() {
  var ov = state.overview;
  if (!ov) return '<div class="ov-empty">连接本地服务后显示所有已保存任务的严重级别分布。</div>';
  var sev = ov.severity || {};
  var order = ["critical", "high", "medium", "low", "info"];
  var total = order.reduce(function (sum, key) { return sum + (Number(sev[key]) || 0); }, 0);
  if (!total) {
    return '<div class="ov-empty">还没有发现项。运行包含安全分析的任务后，这里会按严重级别汇总。</div>';
  }
  var rows = order.map(function (key) {
    var n = Number(sev[key]) || 0;
    var pct = total ? Math.round(n / total * 100) : 0;
    return '<div class="sev-row">' +
      '<span class="sev-name"><i class="sev-dot sev-' + key + '"></i>' + esc(SEV_LABEL[key] || key) + "</span>" +
      '<span class="sev-bar"><i class="sev-fill sev-' + key + '" style="width:' + pct + '%"></i></span>' +
      '<span class="sev-n">' + esc(n) + "</span>" +
    "</div>";
  }).join("");
  return '<div class="sev-list">' + rows + "</div>" +
    '<div class="sev-total">共 ' + esc(total) + " 项发现</div>";
}

function overviewTrendHtml() {
  var ov = state.overview;
  if (!ov || !ov.trend || !ov.trend.length) {
    return '<div class="ov-empty">连接本地服务后显示近 14 天的任务与发现项趋势。</div>';
  }
  var days = ov.trend;
  var maxTasks = 1;
  days.forEach(function (day) { maxTasks = Math.max(maxTasks, Number(day.tasks) || 0); });
  var totalTasks = days.reduce(function (sum, day) { return sum + (Number(day.tasks) || 0); }, 0);
  if (!totalTasks) return '<div class="ov-empty">近 14 天还没有任务。</div>';
  var cols = days.map(function (day) {
    var tasks = Number(day.tasks) || 0;
    var ok = Number(day.success) || 0;
    var err = Number(day.errors) || 0;
    var totalH = tasks ? Math.max(4, Math.round(tasks / maxTasks * 100)) : 0;
    var errPct = tasks ? Math.round(err / tasks * 100) : 0;
    var tip = day.date + " · " + tasks + " 个任务 · " + ok + " 成功 · " + err + " 失败 · " +
      (Number(day.findings) || 0) + " 项发现";
    var stack = totalH
      ? '<div class="trend-stack" style="height:' + totalH + '%">' +
          (err ? '<span class="trend-err" style="height:' + errPct + '%"></span>' : "") +
          '<span class="trend-ok"></span>' +
        "</div>"
      : '<span class="trend-zero"></span>';
    return '<div class="trend-col" title="' + esc(tip) + '">' +
      '<div class="trend-track">' + stack + "</div>" +
      '<span class="trend-day">' + esc(day.label) + "</span>" +
    "</div>";
  }).join("");
  return '<div class="trend-legend"><span><i class="lg-ok"></i>成功</span>' +
    '<span><i class="lg-err"></i>失败</span></div>' +
    '<div class="trend">' + cols + "</div>";
}

function overviewFailuresHtml() {
  var ov = state.overview;
  if (!ov) return '<div class="ov-empty">连接本地服务后显示最近的失败原因。</div>';
  var failures = ov.recent_failures || [];
  if (!failures.length) return '<div class="ov-empty">没有失败任务，最近的扫描全部成功。</div>';
  var topReason = (ov.failure_reasons || [])[0];
  var topHtml = topReason && topReason.count > 1
    ? '<div class="of-top">最常见原因：' + esc(topReason.message) +
      "（" + esc(topReason.count) + " 次）</div>"
    : "";
  return topHtml + failures.map(function (f) {
    var stamp = fmtTime(new Date(f.created_at * 1000).toISOString());
    return '<div class="ov-failure" data-ov-task="' + esc(f.id) + '">' +
      '<div class="of-head"><b>' + esc(f.project_name || "未分类") + " · " + esc(f.name) +
        '</b><span class="chip fail">失败</span></div>' +
      '<div class="of-meta">' + esc(stamp) +
        (f.target_name ? " · " + esc(f.target_name) : "") + "</div>" +
      '<div class="of-reason" title="' + esc(f.error_message) + '">' +
        esc(f.error_message) + "</div>" +
    "</div>";
  }).join("");
}

function overviewProjectsHtml() {
  var ov = state.overview;
  if (!ov) return '<div class="ov-empty">连接本地服务后显示每个项目的最近扫描时间。</div>';
  var projects = (ov.projects || []).slice(0, 6);
  if (!projects.length) {
    return '<div class="ov-empty">还没有项目。新建项目并运行分析后，这里会显示最近扫描时间。</div>';
  }
  var now = Date.now() / 1000;
  return '<div class="ov-project-list">' + projects.map(function (p) {
    var never = !p.last_scan_at;
    var stale = !never && (now - p.last_scan_at) > 7 * 86400;
    var statusHtml = p.last_status
      ? '<span class="chip ' + (p.last_status === "success" ? "ok" : "fail") + '">' +
          (p.last_status === "success" ? "最近成功" : "最近失败") + "</span>"
      : '<span class="chip info">未扫描</span>';
    return '<div class="ov-project" data-ov-project="' + esc(p.id) + '">' +
      '<div class="op-main"><div class="op-name">' + esc(p.name) +
        (stale ? '<span class="op-stale">超过 7 天</span>' : "") + "</div>" +
        '<div class="op-meta">' + esc(p.task_count) + " 个任务 · " + esc(p.success_count) +
          " 次成功 · " + esc(p.finding_count) + " 项发现</div></div>" +
      '<div class="op-side">' + statusHtml +
        '<div class="op-time">' + (never ? "尚未扫描" :
          esc(fmtTime(new Date(p.last_scan_at * 1000).toISOString()))) + "</div></div>" +
    "</div>";
  }).join("") + "</div>";
}

function renderOverview() {
  if (overviewMetrics) overviewMetrics.innerHTML = overviewMetricsHtml();
  if (overviewOffline) overviewOffline.hidden = !state.healthChecked || !!state.health;
  if (overviewSeverity) overviewSeverity.innerHTML = overviewSeverityHtml();
  if (overviewTrend) overviewTrend.innerHTML = overviewTrendHtml();
  if (overviewFailures) overviewFailures.innerHTML = overviewFailuresHtml();
  if (overviewProjects) overviewProjects.innerHTML = overviewProjectsHtml();
  if (overviewTrendSummary) {
    var ov = state.overview;
    if (ov && ov.trend && ov.trend.length) {
      var tasks = 0, success = 0, findings = 0;
      ov.trend.forEach(function (day) {
        tasks += Number(day.tasks) || 0;
        success += Number(day.success) || 0;
        findings += Number(day.findings) || 0;
      });
      overviewTrendSummary.textContent = "近 14 天 " + tasks + " 个任务 · 成功率 " +
        fmtPct(tasks ? success / tasks * 100 : 0) + " · " + findings + " 项发现。";
    } else {
      overviewTrendSummary.textContent = "每天的任务量、成功数与发现项变化。";
    }
  }
  if (!overviewRecent) return;
  var recent = (state.tasks || []).slice(0, 5);
  if (!recent.length) {
    overviewRecent.innerHTML =
      '<div class="empty-block">' +
        '<div class="eb-title">还没有任务</div>' +
        '<div class="eb-hint">进入项目详情创建任务并运行分析，这里会显示最近 5 条任务。</div>' +
        '<div class="eb-actions">' +
          '<button type="button" class="primary" data-goto-view="config">去项目管理</button>' +
        "</div>" +
      "</div>";
    return;
  }
  overviewRecent.innerHTML = recent.map(taskItemHtml).join("");
}

/* ================= 任务列表（SQLite 持久化） ================= */

function renderHistory() {
  if (!state.tasks.length) {
    historyList.innerHTML =
      '<div class="empty-block">' +
        '<div class="eb-title">还没有任务</div>' +
        '<div class="eb-hint">进入项目详情创建任务并运行分析，任务与完整结果会保存在本地数据库，刷新页面不丢失。</div>' +
        '<div class="eb-actions"><button type="button" class="primary" data-goto-projects>去项目管理</button></div>' +
      "</div>";
    return;
  }
  historyList.innerHTML = state.tasks.map(taskItemHtml).join("");
}

/* 任务列表事件：查看（从数据库回放结果）与删除 */
function onHistoryClick(e) {
  if (e.target.closest && e.target.closest("[data-goto-projects]")) { switchView("config"); return; }
  var item = e.target.closest ? e.target.closest(".history-item") : null;
  if (!item) return;
  var act = e.target.dataset ? e.target.dataset.hact : "";
  var taskId = Number(item.dataset.tid);
  if (act === "view") openTask(taskId);
  else if (act === "delete") {
    var t = state.tasks.filter(function (x) { return x.id === taskId; })[0];
    if (t) requestDeleteTask(t);
  }
}

/* ================= 结果渲染 ================= */

/* 完整 JSON 可达数 MB，页面不再渲染：服务端已把它落盘，这里只展示路径与
   下载入口。preview 模式（服务端未返回 report）退回内存下载。 */

function setRawJson(text, report) {
  if (report && report.path) {
    rawInfo.innerHTML =
      '<div class="raw-path">' +
        '<div class="raw-path-k">分析结果文件</div>' +
        '<div class="raw-path-v mono">' + esc(report.path) + "</div>" +
        '<div class="raw-path-meta">' +
          esc(fmtBytes(report.size)) + " · " +
          '<a href="' + esc(report.url) + '" download="' + esc(report.name) + '">下载 ' +
            esc(report.name) + "</a>" +
        "</div>" +
      "</div>" +
      '<p class="hint" style="margin-top:10px">结果 JSON 已由服务端保存到上述路径，' +
      "页面不再内联渲染（完整扫描可达数 MB）。分析器明细见左侧各 Tab。</p>";
    return;
  }
  // 没有落盘信息时给出内存下载，不渲染正文
  var len = text.length;
  rawInfo.innerHTML =
    '<div class="raw-path">' +
      '<div class="raw-path-k">分析结果</div>' +
      '<div class="raw-path-v">服务端未返回文件路径，可直接下载本次结果</div>' +
      '<div class="raw-path-meta">约 ' + esc(fmtBytes(len)) + "</div>" +
    "</div>";
}

/* ================= 批量结果 ================= */

/* 批量运行：逐目标的结果 + 汇总。目标之间互不影响，
   失败的列在汇总里，成功的可以逐个查看。 */
function renderBatchResults(data) {
  var payload = data.payload || {};
  var summary = payload.summary || {};
  var documents = payload.results || {};
  var paths = Object.keys(documents);

  emptyState.hidden = true;
  resultBody.hidden = false;
  // 批量结果没有可切换的分析器 Tab：收起单目标布局，正文写进独立容器，
  // 避免覆盖 #result-body 里的 #result-meta / #result-tabs / #result-panels。
  if (resultLayout) resultLayout.hidden = true;
  batchBody.hidden = false;

  var exitOk = data.exit_code === 0;
  var html =
    '<span class="chip ' + (exitOk ? "ok" : "warn") + '">退出码 ' + esc(data.exit_code) + "</span>" +
    '<span class="chip info">目标 ' + esc(summary.target_count || paths.length) + " 个</span>" +
    '<span class="chip info">完成 ' + esc(summary.completed_count || paths.length) + " 个</span>" +
    '<span class="chip ' + (summary.failed_count ? "warn" : "ok") + '">失败 ' +
      esc(summary.failed_count || 0) + " 个</span>" +
    '<span class="chip info">发现项 ' + esc(summary.finding_count || 0) + " 条</span>" +
    '<div class="meta-line">' +
      '<span class="meta-label">等价命令：</span>' +
      '<code class="cmd">' + esc((data.command || []).join(" ")) + "</code>" +
      '<button class="small" id="copy-cmd">复制命令</button>' +
    "</div>";
  resultMeta.innerHTML = html;

  var body = "";
  if (summary.failed_count) {
    body += '<div class="notice">' +
      "<b>失败的目标：</b><br>" +
      (summary.failed || []).map(function (p) { return esc(p); }).join("<br>") +
      "</div>";
  }
  body += '<div class="panel"><h3>逐目标结果</h3>';
  paths.forEach(function (path) {
    var scan = documents[path] || {};
    var findings = (scan.findings || []).length;
    var analyzers = Object.keys(scan.results || {}).length;
    body += '<div class="meta-line">' +
      '<code class="cmd">' + esc(path) + "</code>" +
      '<span class="chip info">' + esc(analyzers) + " 个分析器</span>" +
      '<span class="chip ' + (findings ? "warn" : "ok") + '">' + esc(findings) + " 条发现项</span>" +
      "</div>";
  });
  body += "</div>";
  batchBody.innerHTML = body;

  var cmdBtn = $("copy-cmd");
  if (cmdBtn) {
    cmdBtn.addEventListener("click", function (e) {
      copyText((data.command || []).join(" "), e.currentTarget);
    });
  }
}

function renderResults(data) {
  // A batch run returns one document per target plus a summary, while a
  // single run returns a single scan document.
  if (data.payload && data.payload.summary) {
    renderBatchResults(data);
    return;
  }
  var scan = data.payload && data.payload.result;
  if (!scan) {
    showError("服务未返回分析结果。" + (data.error ? "\n" + data.error : ""));
    showEmptyState("error", "服务未返回分析结果。" + (data.error ? "\n" + data.error : ""));
    resultBody.hidden = true;
    return;
  }
  emptyState.hidden = true;
  resultBody.hidden = false;
  // 单目标结果复用 Tab 布局：确保上一次批量结果已收起
  batchBody.hidden = true;
  batchBody.innerHTML = "";
  if (resultLayout) resultLayout.hidden = false;

  var exitOk = data.exit_code === 0;
  var startedAt = scan.started_at;
  var endedAt = endTimeFrom(startedAt, scan.duration_ms);
  var html =
    '<span class="chip ' + (exitOk ? "ok" : "warn") + '">退出码 ' + esc(data.exit_code) + "</span>" +
    '<span class="chip info">总耗时 ' + esc(fmtMs(scan.duration_ms)) + "</span>" +
    '<span class="chip mono" title="任务开始时间（服务端 UTC 时间戳，此处按本地时区显示）">开始 ' +
      esc(fmtTime(startedAt)) + "</span>" +
    '<span class="chip mono" title="按开始时间 + 总耗时推算">结束 ' + esc(endedAt) + "</span>" +
    '<div class="meta-line">' +
      '<span class="meta-label">等价命令：</span>' +
      '<code class="cmd">' + esc((data.command || []).join(" ")) + "</code>" +
      '<button class="small" id="copy-cmd">复制命令</button>' +
    "</div>";
  if (scan.target) {
    var t = scan.target;
    html += '<div class="meta-line">' +
      '<span class="meta-label">目标：</span>' +
      '<code class="cmd">' + esc(t.path || t.real_path || "") + "</code>" +
      "</div>";
    if (t.sha256) {
      // SHA-256 完整可读：截断值没法用于比对，这里给全量 + 一键复制
      html += '<div class="sha-line">' +
        '<span class="meta-label">SHA-256</span>' +
        "<code>" + esc(String(t.sha256)) + "</code>" +
        '<button class="small" id="copy-sha">复制</button>' +
        "</div>";
    }
  }
  resultMeta.innerHTML = html;
  var cmdBtn = $("copy-cmd");
  if (cmdBtn) cmdBtn.addEventListener("click", function (e) { copyText((data.command || []).join(" "), e.currentTarget); });
  var shaBtn = $("copy-sha");
  if (shaBtn) shaBtn.addEventListener("click", function () { copyText(scan.target.sha256, shaBtn); });

  var results = scan.results || {};
  var order = (scan.resolved_analyzers && scan.resolved_analyzers.length)
    ? scan.resolved_analyzers
    : Object.keys(results);
  var ids = order.filter(function (id) { return results[id]; });

  buildResultTabs(ids, results);
  renderSummaryStatus(ids, results);
  renderFindings(scan.findings || []);
  renderDiagnostics(scan.diagnostics || []);
  setRawJson(JSON.stringify(data, null, 2), data.report);
  selectTab(ids.indexOf(state.activeTab) >= 0 ? state.activeTab : "summary");

  if (results["basic.symbols"]) {
    state.sym.q = "";
    state.sym.lang = "all";
    state.sym.shown = 200;
    rerenderSymbols();
  }
}

/* ---- 结果 Tab ---- */

function statusClass(status) {
  var entry = STATUS_LABEL[status];
  return entry ? entry[1] : "info";
}

/* 能力 id -> 页面上展示的中文名称（与选择卡片一致）；未知 id 回退为 id 本身。
   名称优先取服务端登记（CATALOG_META），页面内置 CAP_META 作为离线兜底。 */
function capabilityName(id) {
  var remote = CATALOG_META[id];
  var meta = CAP_META[id];
  return (remote && remote.name) || (meta && meta.name) || id;
}

function resultGroupMeta(key) {
  for (var i = 0; i < CAP_GROUPS.length; i++) {
    if (CAP_GROUPS[i].key === key) return CAP_GROUPS[i];
  }
  return { key: key, name: key || "其他", open: false };
}

function resultGroupsFor(ids) {
  var groups = [];
  var seen = {};
  ids.forEach(function (id) {
    var key = groupOf(id);
    if (seen[key]) return;
    seen[key] = true;
    groups.push(key);
  });
  return groups.map(resultGroupMeta);
}

function resultTabButton(t) {
  return '<button type="button" class="tab" role="tab" aria-selected="false" tabindex="-1"' +
    ' data-tab="' + esc(t.tab) + '"' +
    (t.cap ? ' title="' + esc(t.cap) + '"' : "") + ">" +
    (t.status ? '<span class="st ' + statusClass(t.status) + '"></span>' : "") +
    '<span class="label">' + esc(t.label) + "</span>" +
    (t.cap ? '<span class="id">' + esc(t.cap) + "</span>" : "") +
    (t.dur != null ? '<span class="dur">' + esc(fmtMs(t.dur)) + "</span>" : "") +
    "</button>";
}

/* 结果页左侧：概览 + 按大类分组的分析结果 + 原始 JSON。
   大类可折叠，组头勾选框控制该大类下所有小类结果是否显示。 */
function buildResultTabs(ids, results) {
  clearAnalyzerPanels();
  var groups = resultGroupsFor(ids);
  var summaryTab = resultTabButton({ tab: "summary", label: "概览" });
  var rawTab = resultTabButton({ tab: "raw", label: "原始 JSON" });

  var groupHtml = groups.map(function (group) {
    var items = ids.filter(function (id) { return groupOf(id) === group.key; });
    var hidden = state.resultHiddenGroups.indexOf(group.key) >= 0;
    var tabsHtml = items.map(function (id) {
      var r = results[id] || {};
      var capHidden = state.resultHiddenCaps.indexOf(id) >= 0;
      return '<div class="result-cap" data-result-cap="' + esc(id) + '"' +
        (hidden || capHidden ? " hidden" : "") + ">" +
        '<input type="checkbox" class="result-cap-check" data-result-cap="' + esc(id) + '"' +
          ' aria-label="显示 ' + esc(capabilityName(id)) + ' 结果"' +
          (hidden || capHidden ? "" : " checked") + ">" +
        resultTabButton({
          tab: id,
          label: capabilityName(id),
          cap: id,
          status: r.status,
          dur: typeof r.duration_ms === "number" ? r.duration_ms : null
        }) +
      "</div>";
    }).join("");
    return '<details class="result-group" data-result-group="' + esc(group.key) + '"' +
      (group.open ? " open" : "") + ">" +
      "<summary>" +
        '<span class="rgg-check"><input type="checkbox" class="result-group-check"' +
          ' data-result-group="' + esc(group.key) + '"' +
          ' aria-label="显示 ' + esc(group.name) + ' 结果"' +
          (hidden ? "" : " checked") + "></span>" +
        '<span class="rgg-name">' + esc(group.name) + "</span>" +
        '<span class="rgg-count">' + items.length + "/" + items.length + "</span>" +
      "</summary>" +
      '<div class="result-group-body" data-result-group-body="' + esc(group.key) + '"' +
        (hidden ? " hidden" : "") + ">" + tabsHtml + "</div>" +
      "</details>";
  }).join("");

  resultTabs.innerHTML = summaryTab + groupHtml + rawTab;
  renderResultGroupVisibility();

  ids.forEach(function (id) {
    var panel = document.createElement("div");
    panel.className = "tab-panel";
    panel.setAttribute("data-tab", id);
    panel.setAttribute("data-kind", "analyzer");
    panel.setAttribute("role", "tabpanel");
    panel.innerHTML = renderAnalyzerBody(id, results[id]);
    resultPanels.insertBefore(panel, rawPanel);
  });
}

/* 勾选/取消大类：只控制结果 Tab 的显示，不改变已返回的分析数据 */
function toggleResultGroup(key) {
  var index = state.resultHiddenGroups.indexOf(key);
  if (index >= 0) state.resultHiddenGroups.splice(index, 1);
  else state.resultHiddenGroups.push(key);
  renderResultGroupVisibility();
}

/* 勾选/取消小类：只控制单个结果 Tab 的显示，不重新运行分析 */
function toggleResultCap(id) {
  var index = state.resultHiddenCaps.indexOf(id);
  if (index >= 0) state.resultHiddenCaps.splice(index, 1);
  else state.resultHiddenCaps.push(id);
  renderResultGroupVisibility();
}

function updateResultGroupCount(group, key) {
  var tabs = group.querySelectorAll(".tab");
  var visible = 0;
  Array.prototype.forEach.call(tabs, function (btn) {
    if (!btn.hidden) visible += 1;
  });
  var countEl = group.querySelector(".rgg-count");
  if (countEl) countEl.textContent = visible + "/" + tabs.length;
}

/* 大类或小类隐藏后：对应 tab 与整组内容隐藏，计数显示 n/m；若当前打开
   的结果被隐藏，自动切回第一个仍可见的结果。 */
function renderResultGroupVisibility() {
  Array.prototype.forEach.call(resultTabs.querySelectorAll(".result-group"), function (group) {
    var key = group.getAttribute("data-result-group");
    var groupHidden = state.resultHiddenGroups.indexOf(key) >= 0;
    var check = group.querySelector(".result-group-check");
    var body = group.querySelector(".result-group-body");
    if (check) check.checked = !groupHidden;
    if (body) body.hidden = groupHidden;
    Array.prototype.forEach.call(group.querySelectorAll(".result-cap"), function (row) {
      var capCheck = row.querySelector(".result-cap-check");
      var tab = row.querySelector(".tab");
      if (!capCheck) return;
      var id = capCheck.getAttribute("data-result-cap");
      var capHidden = state.resultHiddenCaps.indexOf(id) >= 0;
      var hidden = groupHidden || capHidden;
      capCheck.checked = !hidden;
      row.hidden = hidden;
      if (tab) tab.hidden = hidden;
    });
    updateResultGroupCount(group, key);
  });
  var active = resultTabs.querySelector('.tab.active:not([hidden])');
  if (!active && state.activeTab && state.activeTab !== "summary" && state.activeTab !== "raw") {
    var first = resultTabs.querySelector('.tab:not([hidden])');
    selectTab(first ? first.getAttribute("data-tab") : "summary");
  }
}

function selectTab(id) {
  state.activeTab = id;
  Array.prototype.forEach.call(resultTabs.querySelectorAll(".tab"), function (btn) {
    var active = btn.getAttribute("data-tab") === id;
    btn.classList.toggle("active", active);
    // 键盘与读屏器依赖 aria-selected / roving tabindex，仅切换 class 不够
    btn.setAttribute("aria-selected", active ? "true" : "false");
    btn.setAttribute("tabindex", active ? "0" : "-1");
  });
  Array.prototype.forEach.call(resultPanels.querySelectorAll(".tab-panel"), function (panel) {
    panel.classList.toggle("active", panel.getAttribute("data-tab") === id);
  });
  var active = resultTabs.querySelector(".tab.active");
  if (active && active.scrollIntoView) {
    // 竖排侧栏：只按块方向滚动，横向保持不动
    try { active.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" }); }
    catch (e) { active.scrollIntoView(); }
  }
}

/* ↑/↓：切换到上一个/下一个分析结果 Tab（键盘操作，箭头按钮已移除） */
function tabOrder() {
  return Array.prototype.map.call(resultTabs.querySelectorAll(".tab:not([hidden])"), function (btn) {
    return btn.getAttribute("data-tab");
  });
}

function stepTab(delta) {
  var order = tabOrder();
  if (!order.length) return;
  var cur = order.indexOf(state.activeTab);
  var next = cur < 0 ? (delta > 0 ? 0 : order.length - 1)
    : Math.min(order.length - 1, Math.max(0, cur + delta));
  if (next !== cur) selectTab(order[next]);
}

function renderSummaryStatus(ids, results) {
  if (!ids.length) {
    summaryStatus.innerHTML = '<span class="note" style="margin-top:0">本次运行没有产生分析器结果。</span>';
    return;
  }
  summaryStatus.innerHTML = ids.map(function (id) {
    var r = results[id] || {};
    var entry = STATUS_LABEL[r.status] || ["未知", "info"];
    return '<span class="chip ' + entry[1] + ' mono">' + esc(capabilityName(id)) +
      " · " + esc(entry[0]) + " · " + esc(fmtMs(r.duration_ms)) + "</span>";
  }).join("");
}

/* 清空上一次的结果：Tab、面板、发现项、诊断、原始 JSON 全部复位 */
function clearResults() {
  state.response = null;
  state.activeTab = "summary";
  state.resultHiddenGroups = [];
  state.resultHiddenCaps = [];
  state.sym = { q: "", lang: "all", shown: 200 };
  resultMeta.innerHTML = "";
  resultTabs.innerHTML = "";
  clearAnalyzerPanels();
  summaryStatus.innerHTML = "";
  findingsSection.innerHTML = "";
  diagnosticsSection.innerHTML = "";
  rawInfo.innerHTML = "";
  batchBody.innerHTML = "";
  batchBody.hidden = true;
  if (resultLayout) resultLayout.hidden = false;
  resultBody.hidden = true;
  showEmptyState("idle");
}

function clearAnalyzerPanels() {
  Array.prototype.forEach.call(
    resultPanels.querySelectorAll('.tab-panel[data-kind="analyzer"]'),
    function (panel) { panel.remove(); }
  );
}

function renderAnalyzerBody(id, result, slot) {
  var data = result.data || {};
  var bodyHtml;
  if (id === "basic.file") bodyHtml = renderFileData(data);
  else if (id === "basic.elf") bodyHtml = renderElfData(data);
  else if (id === "basic.symbols") bodyHtml = renderSymbolsData(data);
  else if (id === "basic.jni") bodyHtml = renderJniData(data);
  else if (id === "basic.dwarf") bodyHtml = renderDwarfData(data);
  else if (id === "advanced.strings") bodyHtml = renderStringsData(data);
  else if (id === "security.dangerous-api") bodyHtml = renderDangerousApiData(data);
  else if (id === "security.hardening") bodyHtml = '<div class="note">加固结论见「概览」Tab 的发现项汇总。</div>';
  else if (id === "security.risk") bodyHtml = renderRiskData(data);
  else bodyHtml = renderGenericData(data);

  var diags = (result.diagnostics || []).map(renderDiagnostic).join("");
  var cache = result.cache_hit ? '<span class="chip info">缓存命中</span>' : "";
  // 文本化结果默认展开：用户要的是先看到内容，右侧的折叠开关只在需要时收起来
  var textBlock = result.text
    ? '<details class="text-block" open><summary>文本化结果' +
      '<span class="len">' + esc(fmtCount(result.text.length)) + " 字符</span>" +
      "</summary>" +
      '<pre class="text-pre">' + esc(result.text) + "</pre></details>"
    : "";

  // 耗时与起止时刻都在左侧 tab 上，这里只留分析结果本身
  var meta = CAP_META[id] || {};
  return '<div class="panel-head">' +
    "<b>" + esc(capabilityName(id)) + "</b>" +
    '<span class="cap-id">' + esc(id) + "</span>" +
    '<span class="chip ' + statusClass(result.status) + '">' +
      esc((STATUS_LABEL[result.status] || ["未知"])[0]) + "</span>" +
    cache +
    "</div>" +
    // 一句话说明这个分析做什么、能拿到什么，降低逐个分析器的认知成本
    (meta.desc ? '<p class="panel-desc">' + esc(meta.desc) + "</p>" : "") +
    bodyHtml +
    textBlock +
    (diags ? '<div style="margin-top:10px">' + diags + "</div>" : "");
}

function renderFileData(d) {
  return kv([
    ["文件名", d.name, true],
    ["大小", typeof d.size === "number" ? fmtBytes(d.size) : d.size],
    ["格式", d.format],
    ["magic", d.magic, true],
    ["SHA-256", d.sha256, true, true]
  ]);
}

function renderElfData(d) {
  var relro = d.has_gnu_relro
    ? '<span class="chip ok">GNU RELRO 已开启</span>'
    : '<span class="chip fail">GNU RELRO 缺失</span>';
  var nx = d.executable_stack
    ? '<span class="chip fail">栈可执行（NX 关闭）</span>'
    : '<span class="chip ok">栈不可执行（NX 开启）</span>';
  return kv([
    ["ELF 类", d.elf_class], ["端序", d.endianness], ["类型", d.type],
    ["机器", d.machine], ["入口点", d.entry_point, true],
    ["程序头数量", d.program_header_count], ["节头数量", d.section_header_count]
  ]) + '<div class="fact-row">' + relro + nx + "</div>";
}

function countBox(n, label) {
  return '<div class="count-box"><div class="n">' + esc(n == null ? "—" : n) +
    '</div><div class="l">' + esc(label) + "</div></div>";
}

function renderSymbolsData(d) {
  var c = d.counts || {};
  var langCount = {};
  (d.functions || []).forEach(function (f) { langCount[f.language] = (langCount[f.language] || 0) + 1; });

  var countsHtml = '<div class="counts">' +
    countBox(c.exported_functions, "导出函数") +
    countBox(c.imports, "导入符号") +
    countBox(c.exported_data, "导出数据") +
    countBox(c.exported_unclassified, "未分类导出") +
    countBox(d.demangled_count, "已 demangle") +
    countBox(d.jni_count, "JNI 方法") +
    (d.stripped
      ? '<div class="count-box"><div class="n" style="color:var(--warn)">已剥离</div><div class="l">.symtab 缺失</div></div>'
      : "") +
    "</div>";

  var toolsHtml =
    '<div class="sym-tools" data-for="basic.symbols">' +
    '<input type="search" placeholder="搜索符号名 / 签名…" data-role="sym-q" aria-label="搜索符号">' +
    '<select data-role="sym-lang" aria-label="语言筛选"><option value="all">全部语言</option>' +
    Object.keys(langCount).sort().map(function (l) {
      return '<option value="' + esc(l) + '">' + esc(l) + " (" + langCount[l] + ")</option>";
    }).join("") +
    "</select>" +
    '<span class="count" data-role="sym-count"></span>' +
    '<button class="small" type="button" data-role="sym-csv" title="导出当前筛选结果的全部符号">导出 CSV</button>' +
    "</div>" +
    '<div class="table-wrap"><table class="data"><thead><tr>' +
    "<th>符号</th><th>签名 / 语言</th><th>绑定</th><th>可见性</th><th>地址</th><th>大小</th><th>来源</th>" +
    '</tr></thead><tbody data-role="sym-body"></tbody></table></div>' +
    '<div style="margin-top:10px"><button class="small" data-role="sym-more" hidden>显示更多</button></div>';

  return countsHtml + toolsHtml;
}

function renderJniData(d) {
  var regs = d.dynamic_registrations || [];
  var countsHtml = '<div class="counts">' +
    countBox(d.static_count, "静态注册") +
    countBox(d.dynamic_count, "动态注册") +
    countBox(d.dynamic_array_count, "注册数组") +
    (d.on_load_present
      ? '<div class="count-box"><div class="n">有</div><div class="l">JNI_OnLoad</div></div>'
      : '<div class="count-box"><div class="n">无</div><div class="l">JNI_OnLoad</div></div>') +
    "</div>";

  var tableHtml = "";
  if (regs.length) {
    var rows = regs.map(function (r) {
      var target = r.function_named ? r.function_symbol : r.function_address;
      var nameNote = r.qualified
        ? "全限定名"
        : "简名 · 所属类需 FindClass";
      return "<tr>" +
        '<td class="wrap mono">' + esc(r.method_name) + "</td>" +
        '<td class="wrap mono">' + esc(r.signature) + "</td>" +
        '<td class="wrap mono">' + esc(target) + (r.function_named ? "" : "（无符号名）") + "</td>" +
        '<td class="wrap small">' + esc(nameNote) + "</td>" +
        '<td class="wrap small mono">' + esc(r.array_slot) + "</td>" +
        "</tr>";
    }).join("");
    tableHtml = '<div class="table-wrap" style="margin-top:12px"><table class="data">' +
      "<thead><tr><th>方法名</th><th>Java 签名</th><th>native 函数</th><th>命名</th><th>数组位置</th></tr></thead>" +
      "<tbody>" + rows + "</tbody></table></div>";
  } else if (d.on_load_present || d.register_natives_imported) {
    tableHtml = '<div class="note">检测到 JNI_OnLoad / RegisterNatives，但没有找到形似 JNINativeMethod 的数组。' +
      "数组被混淆或位于非常规位置时会出现这种情况。</div>";
  } else {
    tableHtml = '<div class="note">该镜像不做动态 JNI 注册（没有 JNI_OnLoad，也没有导入 RegisterNatives）。</div>';
  }

  return countsHtml + tableHtml;
}

function renderDwarfData(d) {
  if (!d.has_debug_info) {
    return '<div class="note">' + esc(d.note || "没有调试信息（stripped 构建）。参数名来自 DWARF，缺失时其他分析器如实报告。") + "</div>";
  }
  var all = d.functions || [];
  var rows = all.slice(0, 300).map(function (f) {
    return "<tr>" +
      '<td class="wrap mono">' + esc(f.name) + "</td>" +
      '<td class="wrap">' + esc(f.return_type || "") + " " + esc(f.signature || "") + "</td>" +
      '<td class="wrap small">' + esc((f.parameters || []).map(function (p) { return p.name + ": " + p.type; }).join("; ")) + "</td>" +
      '<td class="mono">' + esc(f.decl_file ? f.decl_file + ":" + f.decl_line : "—") + "</td></tr>";
  }).join("");
  var more = all.length > 300
    ? '<div class="note">仅显示前 300 个函数（共 ' + esc(all.length) + " 个），完整列表见原始 JSON。</div>"
    : "";
  return kv([
    ["DWARF 版本", d.version],
    ["编译单元数", (d.units || []).length],
    ["函数数", all.length]
  ]) + '<div class="table-wrap" style="margin-top:10px"><table class="data"><thead><tr>' +
    "<th>函数</th><th>返回类型 / 签名</th><th>参数（名称: 类型）</th><th>声明位置</th>" +
    '</tr></thead><tbody>' + (rows || '<tr><td colspan="4" style="color:var(--muted)">无函数记录</td></tr>') + "</tbody></table></div>" + more;
}

function renderDangerousApiData(d) {
  var matched = (d.matched_apis || []).map(function (a) {
    return '<span class="chip warn mono">' + esc(a) + "</span>";
  }).join(" ");
  var bySev = d.counts_by_severity || {};
  var sevChips = Object.keys(bySev).sort(function (a, b) { return sevRank(b) - sevRank(a); }).map(function (s) {
    return '<span class="sev-badge ' + esc(s) + '">' + esc(SEV_LABEL[s] || s) + " × " + esc(bySev[s]) + "</span>";
  }).join(" ");
  return '<div class="fact-row" style="margin-top:0">' +
    '<span class="chip info">命中 ' + esc(d.finding_count) + " 项</span>" +
    (sevChips || '<span class="chip ok">未发现危险 API</span>') +
    "</div>" +
    (matched ? '<div class="fact-row" style="margin-top:8px"><span style="font-size:12.5px;color:var(--muted)">命中 API：</span>' + matched + "</div>" : "");
}

var RISK_LEVEL = { low: "ok", medium: "warn", high: "fail", critical: "fail" };
var RISK_LABEL = { low: "低风险", medium: "中风险", high: "高风险", critical: "严重风险" };

function renderStringsData(d) {
  var counts = d.counts || {};
  var classified = d.classified || {};
  var chipFor = function (label, key) {
    var c = classified[key] || { count: 0 };
    return '<span class="chip ' + (c.count ? "warn" : "ok") + '">' +
      esc(label) + " × " + esc(c.count) + "</span>";
  };
  var rows = [];
  ["url", "sensitive", "base64"].forEach(function (key) {
    ((classified[key] || {}).hits || []).slice(0, 100).forEach(function (hit) {
      rows.push("<tr>" +
        '<td><span class="chip ' + (key === "url" ? "info" : "warn") + '">' + esc(key) + "</span></td>" +
        '<td class="wrap mono">' + esc(hit.value || "") + "</td>" +
        '<td class="mono">' + esc(hit.offset || "") + "</td>" +
        '<td class="mono">' + esc(hit.section || "—") + "</td>" +
        '<td class="wrap small">' + esc(hit.label || (hit.decoded ? "解码预览: " + hit.decoded : "")) + "</td></tr>");
    });
  });
  return countBox(counts.unique_strings, "唯一字符串") + " " + countBox(counts.total_strings, "出现次数") +
    '<div class="fact-row" style="margin-top:10px">' +
    chipFor("URL", "url") + chipFor("敏感字符串", "sensitive") + chipFor("Base64", "base64") +
    ((d.scan_truncated ? '<span class="chip warn">输入被截断</span>' : "")) + "</div>" +
    '<div class="table-wrap" style="margin-top:10px"><table class="data"><thead><tr>' +
    "<th>类别</th><th>值</th><th>偏移</th><th>节</th><th>备注</th>" +
    '</tr></thead><tbody>' + (rows.join("") || '<tr><td colspan="5" style="color:var(--muted)">无分类命中</td></tr>') +
    "</tbody></table></div>";
}

function renderRiskData(d) {
  var sev = d.counts_by_severity || {};
  var sevChips = Object.keys(sev).sort(function (a, b) { return sevRank(b) - sevRank(a); }).map(function (s) {
    return '<span class="sev-badge ' + esc(s) + '">' + esc(SEV_LABEL[s] || s) + " × " + esc(sev[s]) + "</span>";
  }).join(" ");
  var level = d.risk_level || "";
  var ind = d.string_indicators || {};
  return '<div class="fact-row" style="margin-top:0">' +
    '<span class="chip ' + (RISK_LEVEL[level] || "info") + '">' + esc(RISK_LABEL[level] || level) + "（" + esc(d.risk_score) + " 分）</span>" +
    '<span class="chip info">去重后 ' + esc(d.unique_finding_count) + " / 原 " + esc(d.finding_count) + "</span>" +
    "</div>" +
    '<div class="fact-row" style="margin-top:8px">' + (sevChips || '<span class="chip ok">无分析器发现项</span>') + "</div>" +
    '<div class="fact-row" style="margin-top:8px"><span class="small" style="color:var(--muted)">字符串指标：URL × ' + esc(ind.url_count) +
    "（" + esc(ind.url_score) + "分）、敏感 × " + esc(ind.sensitive_count) + "（" + esc(ind.sensitive_score) +
    "分）、Base64 × " + esc(ind.base64_count) + "（" + esc(ind.base64_score) + "分）</span></div>";
}

/* 通用字段名 -> 中文。各分析器的 data 字段名不统一，逐个枚举代价过高，
   这里覆盖出现频率最高的一批，未命中的保持原样（英文 key 本身也是信息）。 */
var FIELD_LABELS = {
  // 基础属性
  name: "文件名", size: "大小", format: "格式", magic: "文件头",
  sha256: "SHA-256", md5: "MD5", path: "路径", real_path: "真实路径",
  type: "类型", kind: "类别", count: "数量", total: "总计", index: "序号",
  // ELF / 二进制
  elf_class: "ELF 类", endianness: "端序", machine: "机器架构",
  entry_point: "入口点", program_header_count: "程序头数量",
  section_header_count: "节头数量", sections: "节区", segments: "段",
  has_gnu_relro: "GNU RELRO", executable_stack: "栈可执行",
  has_canary: "栈保护", is_pie: "位置无关", stripped: "已剥离符号",
  soname: "SONAME", needed: "依赖库", rpath: "RPATH", runpath: "RUNPATH",
  interp: "解释器", build_id: "Build ID", notes: "注释段",
  // 符号 / 函数
  functions: "函数", symbols: "符号", exports: "导出", imports: "导入",
  exported_functions: "导出函数", exported_data: "导出数据",
  exported_unclassified: "未分类导出", demangled_count: "已 demangle",
  jni_count: "JNI 方法", language: "语言", address: "地址",
  signature: "签名", return_type: "返回类型", params: "参数",
  arguments: "参数列表", locals: "局部变量", size_bytes: "字节数",
  offset: "偏移", vaddr: "虚拟地址", file_offset: "文件偏移",
  // 字符串 / 常量
  strings: "字符串", value: "值", values: "取值列表", encoding: "编码",
  length: "长度", occurrences: "出现次数", constants: "常量",
  integers: "整数常量", confidence: "置信度",
  // 分析结论
  status: "状态", duration_ms: "耗时", message: "说明", detail: "详情",
  details: "详细信息", description: "描述", title: "标题", level: "级别",
  severity: "严重度", rule_id: "规则", evidence: "证据", source: "来源",
  version: "版本", analyzer_version: "分析器版本", findings: "发现项",
  results: "结果", summary: "摘要", warnings: "警告", errors: "错误",
  ok: "成功", error: "错误", reason: "原因", tags: "标签", category: "分类",
  features: "特征", matches: "匹配项", candidates: "候选",
  // 算法 / 库 / 编译器
  algorithm: "算法", algorithms: "算法列表", family: "算法族",
  compiler: "编译器", toolchain: "工具链", optimization: "优化级别",
  library: "库", libraries: "库列表", protocol: "协议", protocols: "协议列表",
  corroborated: "已佐证", constant: "常量", file: "文件", section: "节区",
  symbol: "符号", block: "基本块", instruction: "指令",
  edge: "边", node: "节点", match: "匹配", candidate: "候选",
  finding: "发现项", diagnostic: "诊断", warning: "警告", protection: "保护项",
  dependency: "依赖", imported: "导入", exported: "导出", demangled: "已 demangle",
  jni: "JNI", dwarf: "DWARF", elf: "ELF",
  static_count: "静态注册数", dynamic_count: "动态注册数",
  dynamic_array_count: "注册数组数", dynamic_registrations: "动态注册表",
  on_load_present: "JNI_OnLoad", register_natives_imported: "导入 RegisterNatives",
  method_name: "方法名", signature: "Java 签名", qualified: "是否全限定名",
  function_address: "函数地址", function_symbol: "函数符号", function_named: "是否有符号名",
  array_slot: "数组位置", relocation_offsets: "重定位槽",
  relocation: "重定位", struct: "结构体", enum: "枚举", global: "全局变量",
  field: "字段", member: "成员", vtable: "虚表", caller: "调用方",
  callee: "被调用方", xref: "交叉引用", reference: "引用", string: "字符串",
  integer: "整数常量", occurrence: "出现",
  // 调用关系
  callgraph: "调用图", callers: "调用方", callees: "被调用方", edges: "边",
  nodes: "节点", blocks: "基本块", instructions: "指令", cfg: "控制流图",
  dataflow: "数据流", xrefs: "交叉引用", references: "引用",
  // 高频漏网词根（各分析器 data 里反复出现）
  families: "算法族", scan_truncated: "是否截断扫描", scanned_bytes: "已扫描字节",
  comment_sections: "注释节区", has_android_ident: "是否含 Android 标识",
  toolchains: "工具链", hit_count: "命中次数", hits: "命中项",
  category_counts: "分类统计", formats: "格式", outer_format: "外层格式",
  verified_count: "已验证数量", categories: "分类", truncation_reason: "截断原因",
  entries: "条目", limit: "上限", mode: "模式",
  flags: "标志", bits: "位", width: "宽度", alignment: "对齐",
  compiler_version: "编译器版本", build_flags: "构建参数", debug_info: "调试信息",
  has_debug_info: "是否含调试信息", units: "编译单元", decl_file: "声明文件",
  decl_line: "声明行号", parameters: "参数", parameter_count: "参数数量",
  local_count: "局部变量数", call_count: "调用次数", callee_count: "被调用数",
  caller_count: "调用方数", symbol_table: "符号表", dynamic_symbols: "动态符号",
  needed_libs: "依赖库", exported_count: "导出数量", imported_count: "导入数量",
  weak: "弱符号", binding: "绑定", visibility: "可见性",
  section_name: "节区名", section_type: "节区类型", permissions: "权限",
  risk_score: "风险评分", overall: "总体", by_severity: "按严重度",
  api_count: "API 数量", apis: "API 列表", dangerous: "危险项",
  // 反汇编 / CFG / 数据流 / 二进制对比专用
  arch: "架构", call_edges: "调用边", code_region_count: "代码区数量",
  code_regions: "代码区", decoder: "解码器", def_count: "定义数量",
  diffed: "是否已对比", external_calls: "外部调用", function_count: "函数数量",
  import_count: "导入数量", indirect_count: "间接调用数", loop_count: "循环数量",
  reaching_pair_count: "可达定义对数量", scope: "作用域", signal_count: "信号数量",
  signals: "信号", truncated: "是否截断", use_count: "使用次数",
  added: "新增", removed: "移除", changed: "变更", unchanged: "未变更",
  basic_blocks: "基本块", block_count: "基本块数", jump_count: "跳转数",
  instruction_count: "指令数", mnemonic: "助记符", operands: "操作数",
  register: "寄存器", registers: "寄存器", stack: "栈", heap: "堆",
  // ELF 动态段细项
  authorization: "授权", bind_now: "立即绑定", events: "事件", executed: "已执行",
  fini: "FINI", fini_array: "FINI 数组", init: "INIT", init_array: "INIT 数组",
  interpose: "可插入", preinit_array: "PREINIT 数组",
  referenced_string_count: "引用字符串数", relative_path_entries: "相对路径条目",
  search_path: "搜索路径", state: "状态", strings_truncated: "字符串是否截断",
  symbol_function_count: "函数符号数", symbol_versions: "符号版本", symbolic: "符号方式",
  // 其余零散词根
  buffer_length_pair_count: "缓冲区-长度配对数量", by_kind: "按类别",
  class_count: "类数量", classes: "类", construction_vtable_count: "构造虚表数量",
  heuristic: "启发式", max_targets: "目标上限", min_score: "最低分",
  parser_like_count: "类解析器函数数", signatures: "签名", target_count: "目标数量",
  targets: "目标", textrel: "TEXTREL", variable_count: "变量数量",
  variables: "变量", versioned_libraries: "带版本库",
  world_writable_entries: "全局可写条目",
  // 风险 / 加固
  risk: "风险", score: "评分", grade: "等级", hardening: "加固",
  protections: "保护项", missing: "缺失项", present: "已具备",
  // 动态
  imports_resolved: "已解析导入", plt: "PLT", got: "GOT",
  relocations: "重定位", dynamic: "动态链接", trace: "追踪记录",
  // 结构体 / 类型
  types: "类型", structs: "结构体", enums: "枚举", globals: "全局变量",
  fields: "字段", members: "成员", base: "基类", bases: "基类列表",
  vtables: "虚表", rtti: "RTTI", inheritance: "继承关系"
};

/* 字段名中文化：命中映射用中文，否则尝试 _count/_list 等后缀规则，
   再不行保持原样（英文 key 本身也是信息）。 */
function fieldLabel(key) {
  var zh = FIELD_LABELS[key];
  if (zh) return { text: zh, known: true };
  var m = /^(.+?)_(count|total|num|size|len|list|items|entries|ids)$/.exec(key);
  if (m && FIELD_LABELS[m[1]]) {
    var suffix = { count: "数量", total: "总计", num: "数量", size: "大小",
                   len: "长度", list: "列表", items: "条目", entries: "条目", ids: "ID 列表" }[m[2]];
    return { text: FIELD_LABELS[m[1]] + suffix, known: true };
  }
  var p = /^(has|is|can|should)_(.+)$/.exec(key);
  if (p && FIELD_LABELS[p[2]]) {
    return { text: "是否" + FIELD_LABELS[p[2]], known: true };
  }
  return { text: key, known: false };
}

/* 通用渲染：单列 + 中文 key + 超长值折叠 */
function renderGenericData(d) {
  var entries = Object.keys(d || {}).map(function (k) { return [k, d[k]]; });
  if (!entries.length) return '<div class="note">该分析器没有返回数据字段。</div>';
  return kv(entries.map(function (e) {
    var complex = e[1] !== null && typeof e[1] === "object";
    var label = fieldLabel(e[0]);
    // 对象/数组直接透传，kv() 会尝试 JSON.parse 后缩进格式化
    return [label.text, e[1], false, complex, e[0]];
  }));
}

function renderFindings(findings) {
  if (!findings.length) {
    findingsSection.innerHTML = '<div class="section-title">发现项 <span class="n">0</span></div>' +
      '<div class="note">未发现 finding。当前规则覆盖加固基线与危险 API 两类事实。</div>';
    return;
  }
  var sorted = findings.slice().sort(function (a, b) { return sevRank(b.severity) - sevRank(a.severity); });
  var cards = sorted.map(function (f) {
    var evidence = (f.evidence || []).map(function (ev) {
      var rows = Object.keys(ev).map(function (k) {
        var v = ev[k];
        return "<tr><td>" + esc(k) + '</td><td class="mono">' +
          esc(typeof v === "object" ? JSON.stringify(v) : v) + "</td></tr>";
      }).join("");
      return '<div class="evidence"><table>' + rows + "</table></div>";
    }).join("");
    return '<div class="finding sev-' + esc(f.severity) + '">' +
      '<div class="head"><span class="sev-badge ' + esc(f.severity) + '">' +
      esc(SEV_LABEL[f.severity] || f.severity) + "</span>" +
      '<span class="title">' + esc(f.title) + "</span>" +
      '<span class="rule">' + esc(f.rule_id) + " · 置信度 " + esc(f.confidence) + "</span></div>" +
      '<div class="msg">' + esc(f.message) + "</div>" + evidence +
      (f.remediation ? '<div class="fix"><b>修复建议：</b>' + esc(f.remediation) + "</div>" : "") +
      "</div>";
  }).join("");
  findingsSection.innerHTML = '<div class="section-title">发现项 <span class="n">' + findings.length + "</span>" +
    '<button class="small" type="button" data-role="finding-csv" style="margin-left:auto">导出 CSV</button>' +
    "</div>" + cards;
}

function renderDiagnostic(d) {
  return '<div class="diag ' + esc(d.level) + '"><span class="code">' + esc(d.code) + "</span>" +
    "<span>" + esc(d.message) + "</span>" +
    (d.analyzer_id
      ? '<span style="color:var(--muted);font-family:var(--mono);font-size:11.5px">' + esc(d.analyzer_id) + "</span>"
      : "") +
    "</div>";
}

function renderDiagnostics(diags) {
  if (!diags.length) {
    diagnosticsSection.innerHTML = "";
    return;
  }
  diagnosticsSection.innerHTML = '<div class="section-title">诊断信息 <span class="n">' + diags.length + "</span></div>" +
    diags.map(renderDiagnostic).join("");
}

/* ---- 符号表交互 ---- */

/* 表格渲染与 CSV 导出共用同一套筛选条件，保证"看到什么就导出什么" */
function filterSymbols(list) {
  return (list || []).filter(function (f) {
    if (state.sym.lang !== "all" && f.language !== state.sym.lang) return false;
    if (state.sym.q) {
      var hay = (f.name + " " + (f.signature || "") + " " + (f.namespace || "")).toLowerCase();
      if (hay.indexOf(state.sym.q) === -1) return false;
    }
    return true;
  });
}

function rerenderSymbols() {
  var symbolsCard = state.response && state.response.payload
    ? state.response.payload.result.results["basic.symbols"]
    : null;
  if (!symbolsCard) return;
  var d = symbolsCard.data || {};
  var wrap = document.querySelector('[data-for="basic.symbols"]');
  if (!wrap) return;
  var body = wrap.querySelector('[data-role="sym-body"]');
  var count = wrap.querySelector('[data-role="sym-count"]');
  var moreBtn = wrap.querySelector('[data-role="sym-more"]');
  if (!body || !count || !moreBtn) return;

  var filtered = filterSymbols(d.functions);
  var rows = filtered.slice(0, state.sym.shown).map(function (f) {
    return "<tr>" +
      '<td class="wrap"><span class="sym-name" title="' + esc(f.name) + '">' + esc(f.name) + "</span></td>" +
      '<td class="wrap">' + esc(f.signature || f.name) + ' <span class="lang ' + esc(f.language) + '">' + esc(f.language) + "</span></td>" +
      "<td>" + esc(f.bind) + "</td><td>" + esc(f.visibility) + "</td>" +
      '<td class="mono">' + esc(f.address) + "</td>" +
      '<td class="mono">' + esc(f.size) + "</td>" +
      "<td>" + esc(f.source) + "</td></tr>";
  }).join("");
  body.innerHTML = rows || '<tr><td colspan="7" style="color:var(--muted);padding:14px">没有匹配的符号</td></tr>';
  count.textContent = "显示 " + Math.min(state.sym.shown, filtered.length) + " / " + filtered.length +
    "（共 " + (d.functions || []).length + "）";
  moreBtn.hidden = filtered.length <= state.sym.shown;
  moreBtn.textContent = "显示更多（剩余 " + Math.max(0, filtered.length - state.sym.shown) + "）";
}

/* ================= 下载 ================= */

function triggerDownload(blob, filename) {
  var a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
}

function baseFileName() {
  var name = state.target ? state.target.name : "analysis";
  return String(name).replace(/[\\/:*?"<>|\s]+/g, "_");
}

function downloadJson() {
  if (!state.response) return;
  // 服务端已落盘时直接走它的下载路由，省去在前端再物化一份数 MB 的 Blob
  var report = state.response.report;
  if (report && report.url) {
    var a = document.createElement("a");
    a.href = report.url;
    a.download = report.name || "analysis.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    return;
  }
  var blob = new Blob([JSON.stringify(state.response, null, 2)], { type: "application/json" });
  triggerDownload(blob, baseFileName() + ".soinsight.json");
}

/* ---- CSV 导出 ---- */

function csvCell(value) {
  if (value === null || value === undefined) return "";
  var text = String(value);
  // CSV 注入防护：以 = + - @ 开头的单元格会被 Excel/LibreOffice 当公式执行
  if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
  if (/[",\r\n]/.test(text)) return '"' + text.replace(/"/g, '""') + '"';
  return text;
}

function downloadCsv(filename, header, rows) {
  var body = [header.map(csvCell).join(",")];
  rows.forEach(function (row) { body.push(row.map(csvCell).join(",")); });
  // 带 UTF-8 BOM，Excel 才会正确显示中文
  var blob = new Blob(["\ufeff" + body.join("\r\n")], { type: "text/csv;charset=utf-8" });
  triggerDownload(blob, filename);
}

function analyzerResult(id) {
  var result = state.response && state.response.payload && state.response.payload.result;
  return result && result.results ? result.results[id] : null;
}

function exportSymbolsCsv() {
  var card = analyzerResult("basic.symbols");
  if (!card) return;
  var rows = filterSymbols((card.data || {}).functions).map(function (f) {
    return [f.name, f.signature || "", f.language, f.bind, f.visibility, f.address, f.size, f.source];
  });
  downloadCsv(baseFileName() + ".symbols.csv",
    ["符号", "签名", "语言", "绑定", "可见性", "地址", "大小", "来源"], rows);
}

function exportFindingsCsv() {
  var result = state.response && state.response.payload && state.response.payload.result;
  if (!result) return;
  var rows = (result.findings || []).slice().sort(function (a, b) {
    return sevRank(b.severity) - sevRank(a.severity);
  }).map(function (f) {
    return [SEV_LABEL[f.severity] || f.severity, f.title, f.rule_id, f.confidence, f.message, f.remediation || ""];
  });
  downloadCsv(baseFileName() + ".findings.csv",
    ["严重程度", "标题", "规则", "置信度", "说明", "修复建议"], rows);
}

init();
