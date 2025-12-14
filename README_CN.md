# 👁️ Argus - 新一代自动化威胁狩猎与应急响应平台

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go%201.24-blue.svg" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Build-Native%20API-orange.svg" alt="Native">
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Gemini-purple.svg" alt="AI">
</p>

[English](README.md) | [日本語](README_JP.md)

---

### 📖 项目简介

**Argus** 取名自希腊神话中的"百眼巨人" (Argus Panoptes)，寓意以永不闭合的眼睛时刻守护系统安全。这是一款专为**红蓝对抗、应急响应、威胁狩猎**设计的现代化跨平台安全工具，致力于提供更隐蔽、更强大、更智能的威胁检测能力。

Argus 完美支持 **Windows** 和 **Linux** 双系统，尤其针对 Windows 平台进行了深度 Native API 级重构，摒弃了对 `cmd.exe`、`powershell.exe` 等外部命令的依赖。即使在系统工具被 Rootkit 篡改的情况下，Argus 仍能通过底层 API 直接获取真实系统状态，确保取证结果的完整性和可信度。

---

### 🎯 核心特性

#### 1. 零依赖 Native 引擎
- **Windows 平台**
  - 全面使用 Native API：`CreateToolhelp32Snapshot`、`QueryFullProcessImageName`、`dbghelp.dll`、`wintrust.dll`
  - 无需 `cmd.exe`/`powershell.exe` 调用，避免命令行日志泄露
  - 绕过被篡改的用户态工具（tasklist、netstat 等）
  - 进程完整性级别检查，安全扫描系统进程
  
- **Linux 平台**
  - 纯 Go 实现 `/proc` 文件系统解析
  - 无需 Python、Shell 脚本依赖
  - 直接读取内核数据结构

- **单文件部署**
  - 静态编译，开箱即用
  - 无运行时依赖，适合离线/内网环境

#### 2. 深度内存对抗技术

- **RWX 内存段扫描**
  - 智能识别进程中的可执行内存区域（Read-Write-Execute）
  - 精准定位 Shellcode、CobaltStrike Beacon 等无文件攻击载荷
  
- **堆栈回溯分析 (Stack Walking)**
  - 使用 `dbghelp.dll` 遍历线程调用栈
  - 检测无模块支持的代码执行（Unbacked Code）
  - 发现进程注入、反射式 DLL 加载

- **内存 YARA 扫描**
  - 内置 YARA 引擎，直接在进程内存中匹配恶意特征
  - 支持自定义规则集扩展
  - ~~MiniDump 快照保全高危进程现场~~ (未实现，待完成)

#### 3. AI 智能分析引擎

- **集成大语言模型**
  - 支持 DeepSeek、Gemini AI 接口
  - 自动上传扫描报告，生成威胁分析和处置建议
  - 智能数据过滤，只发送 Critical/High/Medium 级别告警
  
- **配置灵活**
  - YAML 配置文件 (`config/ai.yaml`) 持久化设置
  - 命令行参数临时覆盖
  - 自动生成 `argus_ai_input.json` 供调试

#### 4. 深度取证与历史溯源

- **Windows 取证引擎**
  - **Prefetch 解析**：还原程序历史执行记录（即使文件已删除）
  - **ShimCache 分析**：提取应用程序兼容性缓存数据
  - **LNK 快捷方式**：解析最近访问文件痕迹
  - **RecentDocs**：注册表最近文档记录
  
- **Linux 审计日志**
  - Auth 日志分析
  - Bash/Zsh 历史记录
  - systemd journal 解析

#### 5. 威胁情报联动

- **在线情报查询**
  - VirusTotal 文件 Hash 检测
  - AbuseIPDB IP 信誉验证
  - 网络连接实时威胁评估

#### 6. 可视化攻击图谱

- **DOT 格式导出**
  - 进程关系树（Parent-Child）
  - 网络连接拓扑（Process → RemoteIP）
  - 支持 Graphviz 渲染

---

### 🔬 技术优势

#### 技术栈

| 组件 | 技术/库 | 说明 |
|------|---------|------|
| **语言** | Go 1.24 | 静态编译、高性能、跨平台 |
| **YARA 引擎** | hillu/go-yara v4 | 内存/文件恶意特征匹配 |
| **Windows EVTX** | 0xrawsec/golang-evtx | 事件日志解析（RDP登录等） |
| **系统信息** | gopsutil v3 | 跨平台系统指标采集 |
| **CLI 框架** | spf13/cobra | 命令行参数解析 |
| **日志** | zap | 高性能结构化日志 |
| **配置** | yaml.v3 | YAML 配置文件解析 |
| **Windows API** | golang.org/x/sys/windows | Native API 绑定 |

#### 架构亮点

1. **反检测设计**
   - 无 CMD/PowerShell 调用，避免 SIEM 告警
   - 直接读取内核数据，绕过用户态 Rootkit
   - 进程完整性级别检查，防止崩溃和暴露

2. **高效并发**
   - Go 协程并发扫描多进程
   - 超时保护机制，避免卡死

3. **模块化插件**
   - 插件化设计，易于扩展
   - 统一接口 (`core.Plugin`)
   - 平台特定插件自动加载

---

### 📋 功能矩阵

#### Windows 平台

| 类别 | 功能 | 实现方式 | 状态 |
|------|------|----------|------|
| **👤 用户安全** | 隐藏账户检测 ($前缀) | Native SAM API | ✅ 已完成 |
| | 克隆账号检测 | SID 对比分析 | ✅ 已完成 |
| | RDP 登录日志 | Event Log 解析 | ✅ 已完成 |
| **🚀 进程分析** | 进程列表枚举 | `CreateToolhelp32Snapshot` | ✅ 已完成 |
| | 数字签名验证 | `wintrust.dll` | ✅ 已完成 |
| | 进程参数分析 | 命令行特征检测 | ✅ 已完成 |
| | 隐藏进程检测 | PID 遍历对比 | ✅ 已完成 |
| **💾 内存对抗** | RWX 内存段扫描 | `VirtualQueryEx` | ✅ 已完成 |
| | 堆栈回溯 (Stack Walking) | `StackWalk64` | ✅ 已完成 |
| | 内存 YARA 扫描 | YARA 引擎 | ✅ 已完成 |
| | ~~MiniDump 快照~~ | ~~`MiniDumpWriteDump`~~ | ⏸️ 未启用 |
| **🌐 网络监控** | TCP/UDP 连接 | `GetExtendedTcpTable` | ✅ 已完成 |
| | 进程-连接映射 | OwnerPID 关联 | ✅ 已完成 |
| | 威胁情报查询 | VT/AbuseIPDB API | ✅ 已完成 |
| **🕷️ 持久化** | 注册表启动项 | Run/RunOnce/Winlogon 等 | ✅ 已完成 |
| | 服务后门 | 服务枚举 | ✅ 已完成 |
| | 计划任务 | `SchTasks` API | ✅ 已完成 |
| | WMI 事件订阅 | WMI 查询 | ✅ 已完成 |
| | 映像劫持 (IFEO) | 注册表扫描 | ✅ 已完成 |
| **📂 文件扫描** | Webshell 检测 | 熵 + YARA | ✅ 已完成 |
| | 敏感文件扫描 | 路径白名单 | ✅ 已完成 |
| | Hash 威胁情报 | VirusTotal | ✅ 已完成 |
| **🕰️ 取证溯源** | Prefetch 解析 | 二进制格式解析 | ✅ 已完成 |
| | ShimCache 分析 | 注册表提取 | ✅ 已完成 |
| | LNK 文件解析 | Shell Link 格式 | ✅ 已完成 |
| | RecentDocs 提取 | 注册表遍历 | ✅ 已完成 |
| **🔍 威胁狩猎** | 黑客工具检测 | 进程名/路径特征 | ✅ 已完成 |
| | LoLBin 滥用 | 可疑参数检测 | ✅ 已完成 |

#### Linux 平台

| 类别 | 功能 | 实现方式 | 状态 |
|------|------|----------|------|
| **👤 用户安全** | /etc/passwd 异常 | 文件解析 | ✅ 已完成 |
| | Root 权限账户 | UID=0 检测 | ✅ 已完成 |
| | SSH Key 后门 | ~/.ssh 检查 | ✅ 已完成 |
| **🚀 进程分析** | 进程列表 | /proc 解析 | ✅ 已完成 |
| | 恶意进程名 | 特征匹配 | ✅ 已完成 |
| | CPU/内存异常 | 资源占用分析 | ✅ 已完成 |
| **🌐 网络监控** | TCP/UDP 连接 | /proc/net/tcp | ✅ 已完成 |
| | 反弹 Shell 检测 | 网络行为分析 | ✅ 已完成 |
| **🕷️ 持久化** | Cron 定时任务 | /etc/crontab 等 | ✅ 已完成 |
| | RC 启动脚本 | /etc/rc.local | ✅ 已完成 |
| | systemd 服务 | systemctl 分析 | ✅ 已完成 |
| | inetd 后门 | /etc/inetd.conf | ✅ 已完成 |
| **📂 文件扫描** | Webshell 检测 | YARA 规则 | ✅ 已完成 |
| | SUID 程序 | find + perm 检查 | ✅ 已完成 |
| | 敏感文件监控 | 路径黑名单 | ✅ 已完成 |
| **🕰️ 日志分析** | Auth 日志 | /var/log/auth.log | ✅ 已完成 |
| | Bash History | ~/.bash_history | ✅ 已完成 |
| **🔍 Rootkit 检测** | LD_PRELOAD 劫持 | 环境变量检查 | ✅ 已完成 |
| | 隐藏进程 | PID 遍历对比 | ⏳ 计划中 |
| | LKM Rootkit | /proc/modules | ⏳ 计划中 |

---

### 🚀 快速开始

#### 1. 编译

```bash
# 克隆仓库
git clone https://github.com/25smoking/Argus.git
cd Argus

# 编译 Windows 版本
GOOS=windows GOARCH=amd64 go build -o argus.exe ./cmd/argus

# 编译 Linux 版本
GOOS=linux GOARCH=amd64 go build -o argus ./cmd/argus
```

#### 2. 基础扫描

```bash
# Windows (需要管理员权限)
.\argus.exe

# Linux (需要 root 权限)
sudo ./argus
```

#### 3. AI 分析模式

**方法一：配置文件（推荐）**

编辑 `config/ai.yaml`：

```yaml
ai:
  enabled: true
  model: "deepseek"  # 或 "gemini"
  api_key: "sk-xxxxxxxxxxxxxxxx"
  api_base: "https://api.deepseek.com"
  language: "zh-CN"
```

然后直接运行：
```bash
.\argus.exe
```

**方法二：命令行参数（临时）**

```bash
.\argus.exe --ai deepseek --key sk-xxxxxxxx
```

#### 4. 生成攻击图谱

```bash
.\argus.exe graph
# 生成 attack_graph.dot，可用 Graphviz 或 http://www.webgraphviz.com/ 查看
```

#### 5. 输出报告

扫描结束后自动生成：
- `argus_report_YYYYMMDD_HHMMSS.html` - 交互式可视化报告
- `argus_report_YYYYMMDD_HHMMSS.json` - 机器可读格式
- `argus_ai_input.json` - AI 调试数据（仅 AI 模式）
- `argus_ai_report.txt` - AI 分析报告（仅 AI 模式）

---

### 🛣️ 路线图 (Roadmap)

#### 🚧 进行中

- [ ] **Linux LKM Rootkit 检测**
  - 内核模块签名验证
  - 隐藏模块检测（/proc/modules vs /sys/module）
  
- [ ] **实时监控模式**
  - ETW (Event Tracing for Windows) 集成
  - 文件/注册表/进程事件监控
  
- [ ] **Java 内存马检测**
  - JVM Attach API
  - 字节码反编译分析

#### 📅 计划中

- [ ] **macOS 支持**
  - 进程/网络/持久化检测
  - Endpoint Security Framework 集成
  
- [ ] **容器/云环境检测**
  - Docker 容器逃逸检测
  - K8s Pod 异常行为分析
  
- [ ] **Web 管理界面**
  - RESTful API 服务
  - React 前端可视化
  - 多主机集中管理
  
- [ ] **增强威胁情报**
  - 本地威胁情报库
  - MITRE ATT&CK 映射
  - IOC 自动提取

#### 💡 未来探索

- [ ] **自定义规则引擎**
  - Sigma 规则支持
  - 可视化规则编辑器
  
- [ ] **取证时间线**
  - 自动生成攻击时间轴
  - 事件关联分析
  
- [ ] **协同响应**
  - 自动隔离/阻断
  - Webhook 告警通知

---

### 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！开发建议：

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

**编码规范**：
- 遵循 Go 官方代码风格
- 添加必要的中文注释
- 新增功能需编写单元测试

---

### 📄 许可证

本项目采用 [MIT License](LICENSE) 开源协议。

---

### ⚠️ 免责声明

本工具仅供安全研究和授权测试使用，请勿用于非法用途。使用者需自行承担因滥用本工具产生的一切法律责任。
