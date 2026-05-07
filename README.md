# 👁️ Argus - 新一代自动化威胁狩猎与应急响应平台

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go%201.24-blue.svg" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Mode-Offline%20First-success.svg" alt="Offline">
  <img src="https://img.shields.io/badge/Rules-Updatable-orange.svg" alt="Rules">
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Gemini-purple.svg" alt="AI">
</p>

<p align="center">
  <strong>面向应急响应、主机取证、威胁狩猎的单机专业版安全工具</strong>
</p>

[English](README_EN.md) | [日本語](README_JP.md)

---

### 📖 项目简介

**Argus** 取名自希腊神话中的“百眼巨人” (Argus Panoptes)，寓意以永不闭合的眼睛守护系统安全。

它是一款面向 **应急响应、主机取证、威胁狩猎、蓝队排查** 的现代化跨平台安全工具。当前版本重点强化了“单机专业版”能力：**离线可用、规则外置、在线更新、低扰动默认扫描、结构化报告、可信发布**。

Argus 支持 **Windows**、**Linux** 与 **macOS**。Windows 平台尽量减少对 `cmd.exe`、`powershell.exe` 等外部命令的依赖，优先通过平台 API 获取系统状态；Linux 平台则以 `/proc`、系统日志、账户配置、启动项和常见持久化位置为核心；macOS 当前可运行通用本地模块，包括主机、进程、网络、文件、Webshell 和恶意软件规则扫描。

---

### 🎯 核心特性

#### 1. 离线优先的单机工具

- 默认扫描不主动联网，适合内网、隔离区、应急现场。
- `--offline` 会强制禁用 AI、威胁情报查询和更新类网络请求。
- 扫描报告默认保存在本地 `reports/` 目录。

#### 2. 外置规则库与在线更新

- 完整 YARA 规则库不再打进主二进制，降低发布物误报面。
- 默认使用二进制同级目录下的隐藏规则目录 `.rule/`，不需要每次手动指定。
- 支持自定义外置规则目录，适合 U 盘、内网共享、离线包分发。
- 新增 `argus rules update/status/verify/list`。
- 在线更新直接拉取当前项目使用的上游规则源。
- `rules.lock.json` 记录规则版本、来源、SHA256、许可证、更新时间和启用状态。

#### 3. 多档扫描 Profile

| Profile | 定位 | 默认行为 |
|---|---|---|
| `quick` | 快速巡检 | 主机、进程、网络概览 |
| `standard` | 默认推荐 | 低扰动应急初扫，不默认启用内存/堆栈 |
| `deep` | 深度排查 | 可显式启用内存、堆栈、更多平台插件 |
| `forensic` | 取证模式 | 带案件编号、规则版本、证据摘要和更完整报告 |

#### 4. Windows Native 检测能力

- 进程枚举：`CreateToolhelp32Snapshot`
- 进程路径与签名：`QueryFullProcessImageName`、`wintrust.dll`
- 内存区域扫描：`VirtualQueryEx`、`ReadProcessMemory`
- 取证痕迹：Prefetch、ShimCache、LNK、RecentDocs
- 持久化：注册表启动项、服务、计划任务、映像劫持等

#### 5. Linux 应急排查能力

- `/etc/passwd`、UID=0、异常账户检查
- SSH Key、Shell History、Auth 日志分析
- Cron、systemd、rc.local、inetd 等持久化位置检查
- `/tmp`、`/var/tmp`、`/dev/shm` 等高危落地点扫描

#### 6. 结构化报告

- JSON：机器可读，适合归档、二次分析、平台接入。
- HTML：人工阅读，展示摘要、覆盖范围、跳过模块、发现项。
- JSONL：可选输出，适合日志流水线。
- 报告包含规则版本、扫描 Profile、跳过模块、风险统计、证据摘要、简化时间线。

---

### 🧱 推荐发布包结构

```text
argus-release/
  argus.exe                 # Windows 二进制；Linux 下为 argus
  .rule/
    rules.lock.json         # 规则版本、来源、SHA256、许可证、启用状态
    RULES_LICENSE.md        # 当前规则包的许可证摘要
    malware_rules/
    webshell_rules/
  config/
    argus.yaml              # 默认 profile、规则目录、报告策略
    rule_sources.yaml       # 上游规则源配置
  SECURITY.md
  FALSE_POSITIVE.md
  PRIVACY.md
  RULES_LICENSE.md
  SHA256SUMS                # 建议发布时生成
```

如果没有同级 `.rule/`，Argus 会自动降级到最小内置规则，报告中会显示规则覆盖不足。

---

### 🚀 快速开始

#### 1. 编译

```bash
# 当前平台
make build

# 生成校验和
make checksums
```

也可以直接使用 Go，但发布包建议用 `make build`。`make build` 默认带 `-trimpath`、去符号和空 buildid，能减少本机源码路径泄漏。

```bash
go build -trimpath -ldflags "-s -w -buildid=" -o argus ./cmd/argus
```

Argus 主线使用完整 libyara 引擎，不再提供轻量 YARA 兼容模式。编译前需要先安装 libyara 和 pkg-config：

```bash
# macOS 示例
brew install yara pkg-config
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -buildid=" -o argus ./cmd/argus
```

规则扫描会直接使用 libyara 编译和执行规则，支持 hex、regex、condition、`pe`/`elf` 等 YARA 模块；遇到当前环境无法编译的规则文件会跳过并继续加载可用规则。

Linux/Windows 发布包也必须链接对应目标平台的 libyara，不能再按纯 Go 程序直接 `GOOS=... go build`。`make build-linux` 和 `make build-windows` 会给出目标依赖提示，实际发布建议在对应系统或专用交叉编译镜像里构建。

#### 2. 查看版本

```bash
argus version
```

用途：确认二进制版本、commit、构建时间。发布包排障时建议先记录该输出。

#### 3. 默认离线扫描

```bash
argus scan --offline
```

用途：推荐的现场应急初扫方式。默认读取二进制同级 `.rule/`，报告输出到 `reports/`。`standard` 默认低扰动，不主动启用内存/堆栈深度扫描。

#### 4. 快速巡检

```bash
argus scan --profile quick --offline
```

用途：快速查看主机、进程、网络概况，适合先判断机器是否值得深挖。

#### 5. 深度扫描

```bash
argus scan --profile deep --module memory,stack
```

用途：显式启用内存和堆栈相关能力。当前 `MemoryScan`、`StackHunter` 是 Windows 专属模块；在 macOS/Linux 上执行该命令会在终端和报告里标明平台不可用。该类能力可能需要管理员权限，也可能被 EDR/AV 视为敏感取证行为，所以不作为默认扫描。

#### 6. 取证模式

```bash
argus scan --profile forensic --case-id CASE-001
```

用途：需要案件编号、规则版本、跳过模块、证据摘要和完整报告时使用。

#### 7. 指定模块扫描

```bash
argus all
argus scan all
argus scan --module all
argus scan --module process,network
argus scan --module webshell
argus scan --module memory,stack --profile deep
```

常用模块关键字：

| 关键字 | 匹配模块 | 规则/引擎依据 | 用途 |
|---|---|---|---|
| `process` / `proc` | `ProcessScan` | `config/process_rules.yaml` 行为规则 | 进程命令行、父子进程、LoLBin、反弹 Shell、凭据转储、恢复破坏等 |
| `network` / `net` | `NetworkScan` / `ThreatIntel` | `config/network_rules.yaml` 行为规则；ThreatIntel 需显式联网/API | 网络连接、异常联网进程、恶意端口、可疑域名、连接数量异常 |
| `file` | `FileScan` | `config/file_rules.yaml` 行为规则 | 文件权限、可疑路径、敏感文件、启动项、小文件内容特征 |
| `malware` | `MalwareScan` | `.rule/malware_rules` 完整 libyara 规则 | 当前平台恶意软件、Hacktool、APT、勒索、后门等文件内容检测 |
| `webshell` | `WebshellScan` | `.rule/webshell_rules` 完整 libyara 规则 + 内置熵值/关键词兜底 | Web 目录脚本和 Webshell 规则检测 |
| `memory` / `mem` | `MemoryScan` / `StackHunter` | Windows `MemoryScan` 复用 `.rule/malware_rules` libyara；`StackHunter` 为栈/内存启发式 | 深度内存和堆栈检测 |
| `account` / `user` | 账户插件 | 平台 API、`/etc/passwd`、用户/组配置启发式 | Windows/Linux 账户安全检查 |
| `persist` | 持久化插件 | 内置 `persistence_rules.yaml` 行为规则，可复制到 `config/` 覆盖 + 平台 API/文件位置 | 注册表、服务、启动项、计划任务等 |

`all` 表示当前平台可用的全部本地模块一把跑完，等价于 `--module all --profile forensic`。例如 macOS 版会运行通用模块，但不会运行 Windows 专属的 `MemoryScan`、`StackHunter`；这些不可用项会写进 `skipped_modules[]`。外部威胁情报仍受 `--no-network` 控制；如果要连 VirusTotal/AbuseIPDB 这类外部服务，需要显式加 `--no-network=false` 并配置 API Key。

`ProcessScan`、`NetworkScan`、`FileScan` 使用项目内 YAML 行为规则：`process_rules.yaml`、`network_rules.yaml`、`file_rules.yaml`。它们分别检测进程命令行/父子进程、网络连接/端口/域名、文件权限/可疑路径/启动项/小文件内容特征。`MalwareScan`、`WebshellScan` 使用 `.rule/` 里的完整 YARA 规则扫描文件内容；Windows `MemoryScan` 会复用 malware YARA 扫内存。

YAML 行为规则的调研依据：

| 来源 | 映射到 Argus 的内容 |
|---|---|
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Windows `process_creation` 类规则思路：PowerShell、Certutil、Bitsadmin、MSHTA、Regsvr32、Rundll32、计划任务、服务创建、Office/WPS 拉起脚本等 |
| [MITRE ATT&CK](https://attack.mitre.org/) | ATT&CK 标签和战术归类：`T1059` 命令解释器、`T1003.001` LSASS 凭据转储、`T1490` 删除恢复、`T1543` 服务持久化、`T1053` 计划任务等 |
| [LOLBAS](https://lolbas-project.github.io/) | Windows 白利用程序行为：`certutil`、`bitsadmin`、`mshta`、`regsvr32`、`rundll32`、`msiexec`、`installutil`、`msbuild` 等 |
| [GTFOBins](https://gtfobins.org/) | Linux/macOS 常见反弹 Shell、解释器执行、`nc`、`socat`、`bash`、`python`、`perl` 等命令特征 |
| [腾讯云 kdevtmpfsi 挖矿木马应急案例](https://cloud.tencent.com/developer/article/1744547) | `kinsing`、`kdevtmpfsi`、`/etc/ld.so.preload`、`/etc/libsystem.so`、`bot.service`、crontab 持久化、进程端口隐藏 |
| [奇安信 95015 应急响应分析报告](https://pdf.dfcfw.com/pdf/H3_AP202602061819815147_1.pdf?1770412720000.pdf=) | SSH 弱口令、`/tmp/up.txt`、写入 SSH 公钥、计划任务维持挖矿木马、口令复用横向传播 |
| [Red Canary Linux Coinminers](https://redcanary.com/threat-detection-report/trends/linux-coinminers/) | Kinsing/TeamTNT 类挖矿木马常用 `authorized_keys` 与 `crontab` 做持久化 |
| [Linux systemd/cron persistence hunting](https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/) | `/etc/cron.*`、`/var/spool/cron`、systemd service/timer 等 Linux 持久化巡检点 |
| [Webshell SIEM 检测思路](https://www.blumira.com/blog/how-to-detect-web-shells) | Web 服务进程拉起 `cmd`、Shell、解释器、扫描器或代理工具的父子进程行为 |
| [FRP 执行检测思路](https://help.fortinet.com/fsiem/Public_Resource_Access/7_1_0/rules/PH_RULE_PUA_Fast_Reverse_Proxy_FRP_Execution.htm) | `frpc/frps/nps/npc/chisel/gost/ew/iox/ngrok` 等代理隧道工具的进程、端口和配置特征 |

---

### 🧩 命令说明

#### 主命令

```bash
argus --help
argus all
argus scan [flags]
argus scan all
argus rules [command]
argus modules
argus graph
argus version
```

| 命令 | 用途 |
|---|---|
| `argus scan` | 执行主机扫描 |
| `argus all` | 一键运行全部本地模块 |
| `argus scan all` | 同上，适合保持 scan 子命令风格 |
| `argus rules status` | 查看当前规则库状态 |
| `argus rules update` | 从上游更新规则库 |
| `argus rules verify` | 校验规则文件 SHA256、lock 和解析兼容性 |
| `argus rules list` | 列出规则文件，可显示来源和许可证 |
| `argus modules` | 查看模块、扰动等级、联网要求和管理员/root 要求 |
| `argus graph` | 生成 DOT 攻击图谱快照 |
| `argus version` | 输出版本、commit、构建时间 |

#### 全局参数

| 参数 | 示例 | 用途 |
|---|---|---|
| `--profile` | `--profile standard` | 选择扫描策略：`quick`、`standard`、`deep`、`forensic` |
| `--offline` / `-o` | `--offline` | 离线模式，禁用 AI、威胁情报和更新类网络请求 |
| `--no-network` | `--no-network=false` | 控制扫描期间是否允许外部网络请求，默认 true |
| `--rules-dir` | `--rules-dir /tmp/rules` | 指定外置规则目录；默认是二进制同级 `.rule/` |
| `--output-dir` | `--output-dir ./reports` | 指定报告输出目录 |
| `--case-id` | `--case-id CASE-001` | 写入报告的案件编号或任务编号 |
| `--jsonl` | `--jsonl` | 额外输出 JSONL 发现明细 |
| `--module` / `-m` | `--module process,network` | 只运行匹配模块 |
| `--ai` | `--ai deepseek` | 显式启用 AI 辅助研判 |
| `--key` | `--key YOUR_API_KEY` | AI API Key |

---

### 📦 规则库管理

默认规则目录是 **二进制同级 `.rule/`**。正常使用不需要手动指定：

```bash
argus rules update
argus rules status
argus rules verify
```

只有你想用 U 盘、共享目录或测试目录时，才需要 `--rules-dir`。

#### 查看规则状态

```bash
argus rules status
```

查看规则目录、状态、版本、更新时间和文件数。

#### 在线更新规则

```bash
argus rules update --source upstream
```

从 `config/rule_sources.yaml` 中配置的上游源下载规则。当前默认规则源包括：

| 来源 | 用途 | 许可证 |
|---|---|---|
| `Neo23x0/signature-base` | THOR/LOKI 风格 YARA 与 Webshell 规则 | Detection Rule License (DRL) 1.1 |
| `elastic/protections-artifacts` | Elastic 安全 YARA 规则 | Elastic License v2 |

更新流程：

1. 下载到临时目录。
2. 生成 `rules.lock.json`。
3. 解析规则并校验 SHA256。
4. 校验通过后替换旧规则目录。
5. 失败时保留旧规则。

#### 校验规则库

```bash
argus rules verify
```

用于发现规则缺失、SHA256 不匹配、lock 异常或规则解析失败。

#### 列出规则

```bash
argus rules list
argus rules list --source
argus rules list --license --source
```

用于审计规则文件、来源和许可证，便于交付给客户或安全团队审批。

---

### 📊 报告输出

扫描结束后默认输出到 `reports/`：

```text
reports/
  argus_report_YYYYMMDD_HHMMSS.json
  argus_report_YYYYMMDD_HHMMSS.html
  argus_findings_YYYYMMDD_HHMMSS.jsonl   # 使用 --jsonl 时生成
  argus_ai_report.txt                    # 显式启用 AI 且允许联网时生成
```

JSON 报告字段：

| 字段 | 说明 |
|---|---|
| `scan_session` | 主机、用户、系统、时间、耗时、离线状态 |
| `rule_bundle` | 规则目录、lock 路径、版本、更新时间、来源、文件数 |
| `profile` | 本次扫描策略 |
| `coverage` | 已加载插件、跳过插件、规则覆盖、网络策略、高扰动状态 |
| `summary` | critical/high/medium/low/info/pass/error 统计 |
| `findings[]` | 发现项，包含等级、评分、置信度、规则名、证据和建议 |
| `evidence[]` | 从发现项提炼的证据摘要 |
| `timeline[]` | 简化时间线 |
| `skipped_modules[]` | 被跳过模块及原因 |

---

### 🤖 AI 辅助研判

AI 是可选能力，不会在离线或 `--no-network` 下运行。

```bash
argus scan --profile standard --no-network=false --ai deepseek --key YOUR_API_KEY
```

AI 分析只发送筛选后的中高危结构化结果。真实客户环境使用前应确认数据出境和隐私合规要求。

---

### 🔐 权限说明

先看当前平台模块和权限要求：

```bash
argus modules
```

常见权限要求：

| 平台 | 模块 | 权限建议 | 原因 |
|---|---|---|---|
| Windows | `WindowsAccountScan` | 管理员 | 枚举本地账户、管理员组、隐藏账户信息更完整 |
| Windows | `WindowsPersistence` | 管理员 | HKLM、服务、计划任务、系统启动项读取更完整 |
| Windows | `Forensics` | 管理员 | Prefetch、ShimCache、RecentDocs、部分注册表取证位置需要更高权限 |
| Windows | `MemoryScan` | 管理员 | 读取其他进程内存需要管理员权限更完整 |
| Windows | `StackHunter` | 管理员 | 线程/堆栈类深度检查需要管理员权限更完整 |
| Linux | `LinuxAccountScan` | root | `/etc/shadow`、UID/口令状态检查需要 root |
| Linux | `LinuxBackdoorScan` | root | SUID、系统目录、部分持久化路径读取更完整 |
| Linux | `LinuxLogScan` | root | `/var/log/auth.log`、journal 等日志读取更完整 |
| macOS | 通用模块 | 普通用户可运行 | 当前不包含 Windows 内存/堆栈和 Linux 系统深度插件 |

没有管理员/root 权限时 Argus 也会尽量运行，但报告覆盖会下降，终端会提示哪些模块在高权限下结果更完整。

---

### 🕸️ 攻击图谱

```bash
argus graph
```

生成 `attack_graph.dot`。可用 Graphviz 渲染：

```bash
dot -Tpng attack_graph.dot -o attack_graph.png
```

---

### 🔧 配置文件

#### `config/argus.yaml`

```yaml
argus:
  default_profile: standard
  rules_dir: .rule
  output_dir: reports
  network:
    default_no_network: true
  reports:
    json: true
    html: true
    jsonl: false
```

#### `config/rule_sources.yaml`

```yaml
rule_sources:
  - name: neo23x0-thor-hacktools
    source: Neo23x0/signature-base
    url: https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-hacktools.yar
    destination: malware_rules/thor-hacktools.yar
    license: Detection Rule License (DRL) 1.1
    group: malware
    enabled: true
```

#### 行为规则配置

| 配置文件 | 调用模块 | 规则类型 |
|---|---|---|
| `config/process_rules.yaml` | `ProcessScan` | 进程命令行、父子进程、LoLBin、凭据转储、勒索前置、防御关闭、挖矿、代理隧道、内网探测、Linux/macOS 持久化命令 |
| `config/network_rules.yaml` | `NetworkScan` | 异常联网进程、恶意/高危端口、矿池/隧道/临时托管域名、单进程大量外连、对外监听端口 |
| `config/file_rules.yaml` | `FileScan` | 可疑文件名、可疑路径、敏感文件、小文件内容特征、Web 根目录异常脚本、LD_PRELOAD Rootkit、systemd/cron/SSH 持久化 |
| 内置 `persistence_rules.yaml`，可复制到 `config/` 覆盖 | Windows `Persistence` | 注册表、服务、启动项、计划任务、WMI 持久化 |

---

### 🆕 2026-05-08 更新说明

本次主要更新：

- 命令简化：新增 `argus all`、`argus scan all`、`--module all` 和 `argus modules`。
- 规则体系：默认使用同级 `.rule/`，支持 `rules status/update/verify/list`，主线接入完整 libyara。
- 行为规则：补强 `process_rules.yaml`、`network_rules.yaml`、`file_rules.yaml`，覆盖 LoLBin、挖矿、代理隧道、持久化、Webshell 行为等。
- 报告输出：JSON/HTML 增加扫描会话、规则来源、跳过模块、中文网络策略和 DOT 攻击图谱。
- 发布工程：构建默认使用 `-trimpath`、空 build id 和版本注入，新增 GitHub Actions 发布构建工作流。

---

### ✅ 当前验证状态

已验证：

```bash
go test ./...
make build
argus rules update --source upstream
argus rules verify
argus scan --profile quick --offline --jsonl
```

---

### 🛣️ 路线图

#### 🚧 进行中

- [ ] Linux LKM Rootkit 检测
- [ ] 更完整的规则元数据与 MITRE ATT&CK 映射
- [ ] 更强的取证时间线和事件关联
- [ ] Windows 代码签名和发布包自动校验

#### 📅 计划中

- [x] macOS 通用模块基础支持
- [ ] macOS 深度取证模块
- [ ] 容器/云环境检测
- [ ] 本地 IOC 库
- [ ] Sigma 规则支持
- [ ] 报告模板进一步美化

---

### 📄 许可证

Argus 主程序采用 [MIT License](LICENSE)。

规则库沿用上游许可证。当前默认规则源涉及 Elastic License v2 和 Detection Rule License (DRL) 1.1，使用和再分发前请确认符合你的业务场景。

---

### ⚠️ 免责声明

本工具仅供授权安全测试、应急响应和防御研究使用。请勿用于未授权目标。使用者需自行承担因滥用本工具产生的一切法律责任。
