# pip 镜像源配置

`start.sh` / `start.ps1` 在安装依赖时会读取本文件选择 pip 镜像。
改这里即可，不需要动脚本。

## 如何切换

把下面 `active` 的值改成任一 `sources` 里已定义的 key，例如：

```toml
active = "aliyun"
```

可用的 key 见下表。设为 `"default"` 则不走镜像，直接用 pip 官方源
（PyPI，`https://pypi.org/simple`），适合网络环境良好或已在
`pip config` / `PIP_INDEX_URL` 里自行配置的机器。

## 配置格式

```toml
active = "aliyun"          # 当前使用的源 key

[sources.aliyun]
name = "阿里云"
url = "https://mirrors.aliyun.com/pypi/simple/"

[sources.tsinghua]
name = "清华大学"
url = "https://pypi.tuna.tsinghua.edu.cn/simple"
```

脚本只读 `active` 和对应 `[sources.<key>]` 段里的 `url`（`name` 仅作说明）。
写错格式、`active` 指向不存在的 key、或整个文件缺失时，脚本会打印告警并回落到
PyPI 官方源，不会中断启动。

## 可选源

| key | 名称 | 地址 |
|---|---|---|
| `default` | PyPI 官方 | https://pypi.org/simple |
| `aliyun` | 阿里云 | https://mirrors.aliyun.com/pypi/simple/ |
| `tsinghua` | 清华大学 | https://pypi.tuna.tsinghua.edu.cn/simple |
| `ustc` | 中科大 | https://pypi.mirrors.ustc.edu.cn/simple/ |
| `huawei` | 华为云 | https://repo.huaweicloud.com/repository/pypi/simple |
| `tencent` | 腾讯云 | https://mirrors.cloud.tencent.com/pypi/simple |

> 各镜像同步 PyPI 有分钟级到小时级延迟，装不到某个新版本时先试官方源。

## 优先级

脚本按以下顺序决定用哪个源，先命中者生效：

1. 命令行参数 `--mirror <key>`（仅 `start.sh` / `start.ps1` 透传给 pip）
2. 环境变量 `PIP_INDEX_URL`（pip 原生支持，设置后本文件被忽略）
3. 本文件的 `active`
4. `default`

第 2 条是 pip 自己的机制：设了 `PIP_INDEX_URL` 就无需改本文件，
适合 CI 或临时切换。
