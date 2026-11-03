#!/usr/bin/env bash
# SOInsight 一键启动：自动找 Python、建虚拟环境、装依赖、启动 Web 控制台。
#
# 设计要点：
# - 只依赖 bash + python3，不需要预装任何第三方工具；
# - 已存在 .venv 就复用，避免每次重装；
# - 依赖装过一次就跳过（用 .venv/.deps-installed 标记，改 requirements.txt 会自动失效）；
# - pip 镜像从 pip-mirrors.toml 读，改配置不用改脚本；
# - 所有输出同时落到 logs/start.log，出问题时可以直接贴这个文件。
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

VENV_DIR="$ROOT_DIR/.venv"
VENV_PY="$VENV_DIR/bin/python"
LOG_DIR="$ROOT_DIR/logs"
LOG_FILE="$LOG_DIR/start.log"
MIRROR_FILE="$ROOT_DIR/pip-mirrors.toml"
REQ_FILE="$ROOT_DIR/requirements.txt"
MARKER="$VENV_DIR/.deps-installed"
PORT="${SOINSIGHT_PORT:-8791}"

mkdir -p "$LOG_DIR"

# log 走 stderr：mirror_args 的 stdout 要交给 mapfile 当 pip 参数用，
# 日志若走 stdout 会被一起捕获，拼成 "[start] pip 源：…" 这种非法 requirement。
log()  { printf '[start] %s\n' "$*" >&2; }
warn() { printf '[start] 警告：%s\n' "$*" >&2; }
die()  { printf '[start] 错误：%s\n' "$*" >&2; exit 1; }

# 所有输出镜像到日志文件，方便回溯
exec > >(tee -a "$LOG_FILE") 2>&1

log "项目目录：$ROOT_DIR"

# ---------------------------------------------------------------- 找 Python
# 依次尝试 python3 / python，并要求 >= 3.10（setup.cfg 的 python_requires）。
find_python() {
  local candidate
  for candidate in python3 python; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
      command -v "$candidate"
      return 0
    fi
    warn "$candidate 版本低于 3.10，已跳过"
  done
  return 1
}

PYTHON=""
if [ -x "$VENV_PY" ]; then
  PYTHON="$VENV_PY"
  log "复用已有虚拟环境：$VENV_DIR"
else
  PYTHON="$(find_python)" || die "未找到 Python 3.10+。请先安装 Python 3.10 或更高版本。"
  log "使用系统 Python：$PYTHON ($("$PYTHON" -V 2>&1))"

  log "创建虚拟环境 .venv …"
  "$PYTHON" -m venv "$VENV_DIR" || die "创建虚拟环境失败。Debian/Ubuntu 可能需要：sudo apt install python3-venv"
  PYTHON="$VENV_PY"
fi

# ---------------------------------------------------------------- 读镜像配置
# 只解析 active 与对应 url，避免为读一个配置引入 TOML 依赖。
mirror_args() {
  local active url
  active="$(sed -n 's/^[[:space:]]*active[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$MIRROR_FILE" 2>/dev/null | head -1)"
  [ -n "${active:-}" ] || active="default"

  if [ "$active" = "default" ]; then
    log "pip 源：PyPI 官方"
    return 0
  fi

  url="$(awk -v key="[sources.$active]" '
    $0 ~ /^[[:space:]]*\[sources\./ { in_section = ($0 == key) }
    in_section && /^[[:space:]]*url[[:space:]]*=/ {
      gsub(/^[^"]*"/, ""); gsub(/"[[:space:]]*$/, ""); print; exit
    }' "$MIRROR_FILE" 2>/dev/null)"

  if [ -z "$url" ]; then
    warn "pip-mirrors.toml 里找不到 sources.$active 的 url，回落到 PyPI 官方源"
    log "pip 源：PyPI 官方（回落）"
    return 0
  fi

  log "pip 源：$active -> $url"
  printf '%s\n' "-i" "$url"
}

# PIP_INDEX_URL 由 pip 原生支持，设了就以它为准，本文件的 active 被忽略
PIP_EXTRA=()
if [ -n "${PIP_INDEX_URL:-}" ]; then
  log "检测到环境变量 PIP_INDEX_URL，优先使用它"
else
  if [ -f "$MIRROR_FILE" ]; then
    mapfile -t PIP_EXTRA < <(mirror_args)
  else
    warn "未找到 pip-mirrors.toml，使用 PyPI 官方源"
  fi
fi

# ---------------------------------------------------------------- 装依赖
# 标记文件记录 requirements.txt 的校验和：改了依赖清单才重装。
req_hash() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$REQ_FILE" | cut -d' ' -f1
  else md5sum "$REQ_FILE" | cut -d' ' -f1; fi
}

install_deps() {
  log "升级 pip / setuptools / wheel …"
  "$PYTHON" -m pip install --disable-pip-version-check -U pip setuptools wheel "${PIP_EXTRA[@]}" \
    || warn "升级 pip 失败，继续使用当前版本"

  log "安装项目依赖（requirements.txt）…"
  "$PYTHON" -m pip install --disable-pip-version-check -r "$REQ_FILE" "${PIP_EXTRA[@]}" \
    || die "依赖安装失败。可检查网络/镜像，或查看 $LOG_FILE"

  log "以可编辑模式安装项目本身（这样 soinsight 命令可直接用）…"
  "$PYTHON" -m pip install --disable-pip-version-check -e "$ROOT_DIR" "${PIP_EXTRA[@]}" \
    || warn "可编辑安装失败；Web 控制台仍可用，但 soinsight 命令可能未加入 PATH"

  printf '%s\n' "$(req_hash)" > "$MARKER"
  log "依赖安装完成"
}

if [ ! -f "$REQ_FILE" ]; then
  die "未找到 requirements.txt"
fi

if [ -f "$MARKER" ] && [ "$(cat "$MARKER" 2>/dev/null)" = "$(req_hash)" ]; then
  log "依赖已是最新（标记文件匹配），跳过安装"
else
  install_deps
fi

# ---------------------------------------------------------------- 启动
log "启动 Web 控制台 http://127.0.0.1:$PORT"
exec "$PYTHON" "$ROOT_DIR/web/server.py" --port "$PORT" "$@"
