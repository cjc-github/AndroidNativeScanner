# SOInsight 一键启动（Windows / PowerShell）
# 自动找 Python、建虚拟环境、装依赖、启动 Web 控制台。
#
# 用法：
#   powershell -ExecutionPolicy Bypass -File start.ps1
#   powershell -ExecutionPolicy Bypass -File start.ps1 -Port 9000
#
# 设计要点与 start.sh 一致：复用 .venv、按 requirements.txt 校验和跳过重复安装、
# pip 镜像从 pip-mirrors.toml 读、日志写入 logs\start.log。

[CmdletBinding()]
param(
    [int]$Port = $(if ($env:SOINSIGHT_PORT) { [int]$env:SOINSIGHT_PORT } else { 8791 })
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $RootDir
try {
    $VenvDir = Join-Path $RootDir ".venv"
    $VenvPy  = Join-Path $VenvDir "Scripts\python.exe"
    $LogDir  = Join-Path $RootDir "logs"
    $LogFile = Join-Path $LogDir "start.log"
    $MirrorFile = Join-Path $RootDir "pip-mirrors.toml"
    $ReqFile = Join-Path $RootDir "requirements.txt"
    $Marker  = Join-Path $VenvDir ".deps-installed"

    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

    function Log([string]$Message) {
        $line = "[start] $Message"
        Write-Host $line
        Add-Content -Path $LogFile -Value $line -Encoding utf8
    }
    function Warn([string]$Message) {
        $line = "[start] 警告：$Message"
        Write-Warning $Message
        Add-Content -Path $LogFile -Value $line -Encoding utf8
    }
    function Die([string]$Message) {
        $line = "[start] 错误：$Message"
        Write-Host $line -ForegroundColor Red
        Add-Content -Path $LogFile -Value $line -Encoding utf8
        exit 1
    }

    Log "项目目录：$RootDir"

    # ------------------------------------------------------------ 找 Python
    # 依次尝试 py -3 / python3 / python，并要求 >= 3.10。
    function Test-PythonVersion([string]$Exe, [string[]]$ExtraArgs) {
        $probe = "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
        $argList = @($ExtraArgs + @("-c", $probe))
        try {
            & $Exe @argList *> $null
            return $LASTEXITCODE -eq 0
        } catch {
            return $false
        }
    }

    $PythonExe = $null
    $PythonPrefix = @()

    if (Test-Path $VenvPy) {
        $PythonExe = $VenvPy
        Log "复用已有虚拟环境：$VenvDir"
    }
    else {
        $candidates = @(
            @{ Exe = "py";      Args = @("-3") },
            @{ Exe = "python3"; Args = @() },
            @{ Exe = "python";  Args = @() }
        )
        foreach ($c in $candidates) {
            $cmd = Get-Command $c.Exe -ErrorAction SilentlyContinue
            if (-not $cmd) { continue }
            if (Test-PythonVersion $cmd.Source $c.Args) {
                $PythonExe = $cmd.Source
                $PythonPrefix = $c.Args
                Log ("使用系统 Python：{0} {1}" -f $PythonExe, ($PythonPrefix -join " "))
                break
            }
            Warn "$($c.Exe) 版本低于 3.10，已跳过"
        }
        if (-not $PythonExe) {
            Die "未找到 Python 3.10+。请先从 https://www.python.org/downloads/ 安装，并勾选 Add Python to PATH。"
        }

        Log "创建虚拟环境 .venv …"
        & $PythonExe @PythonPrefix -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) {
            Die "创建虚拟环境失败。可尝试：py -3 -m pip install --user virtualenv"
        }
        $PythonExe = $VenvPy
        $PythonPrefix = @()
    }

    # ------------------------------------------------------------ 读镜像配置
    function Get-MirrorArgs {
        if ($env:PIP_INDEX_URL) {
            Log "检测到环境变量 PIP_INDEX_URL，优先使用它"
            return @()
        }
        if (-not (Test-Path $MirrorFile)) {
            Warn "未找到 pip-mirrors.toml，使用 PyPI 官方源"
            return @()
        }

        $active = "default"
        $url = $null
        $inSources = $false
        foreach ($line in Get-Content $MirrorFile -Encoding utf8) {
            if ($line -match '^\s*active\s*=\s*"([^"]+)"') {
                $active = $Matches[1]
            }
        }
        if ($active -eq "default") {
            Log "pip 源：PyPI 官方"
            return @()
        }
        foreach ($line in Get-Content $MirrorFile -Encoding utf8) {
            if ($line -match '^\s*\[sources\.') {
                $inSources = ($line.Trim() -eq "[sources.$active]")
                continue
            }
            if ($inSources -and $line -match '^\s*url\s*=\s*"([^"]+)"') {
                $url = $Matches[1]
                break
            }
        }
        if (-not $url) {
            Warn "pip-mirrors.toml 里找不到 sources.$active 的 url，回落到 PyPI 官方源"
            Log "pip 源：PyPI 官方（回落）"
            return @()
        }
        Log "pip 源：$active -> $url"
        return @("-i", $url)
    }

    $PipExtra = Get-MirrorArgs

    # ------------------------------------------------------------ 装依赖
    function Get-ReqHash {
        # requirements.txt 的哈希：改了依赖清单就重装
        return (Get-FileHash -Path $ReqFile -Algorithm SHA256).Hash
    }

    function Install-Deps {
        Log "升级 pip / setuptools / wheel …"
        & $PythonExe -m pip install --disable-pip-version-check -U pip setuptools wheel @PipExtra
        if ($LASTEXITCODE -ne 0) { Warn "升级 pip 失败，继续使用当前版本" }

        Log "安装项目依赖（requirements.txt）…"
        & $PythonExe -m pip install --disable-pip-version-check -r $ReqFile @PipExtra
        if ($LASTEXITCODE -ne 0) {
            Die "依赖安装失败。可检查网络/镜像，或查看 $LogFile"
        }

        Log "以可编辑模式安装项目本身…"
        & $PythonExe -m pip install --disable-pip-version-check -e $RootDir @PipExtra
        if ($LASTEXITCODE -ne 0) {
            Warn "可编辑安装失败；Web 控制台仍可用，但 soinsight 命令可能未加入 PATH"
        }

        Set-Content -Path $Marker -Value (Get-ReqHash) -Encoding ascii
        Log "依赖安装完成"
    }

    if (-not (Test-Path $ReqFile)) { Die "未找到 requirements.txt" }

    $needInstall = $true
    if ((Test-Path $Marker) -and $active) {
        $recorded = (Get-Content $Marker -Raw -ErrorAction SilentlyContinue)
        if ($recorded -and $recorded.Trim() -eq (Get-ReqHash)) {
            $needInstall = $false
            Log "依赖已是最新（标记文件匹配），跳过安装"
        }
    }
    if ($needInstall) { Install-Deps }

    # ------------------------------------------------------------ 启动
    Log "启动 Web 控制台 http://127.0.0.1:$Port"
    & $PythonExe (Join-Path $RootDir "web\server.py") --port $Port
    if ($LASTEXITCODE -ne 0) {
        Die "Web 控制台退出，代码 $LASTEXITCODE。详情见 $LogFile"
    }
}
finally {
    Pop-Location
}
