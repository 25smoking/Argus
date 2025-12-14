# 👁️ Argus - Next-Gen Incident Response & Threat Hunting Platform

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go%201.24-blue.svg" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Build-Native%20API-orange.svg" alt="Native">
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Gemini-purple.svg" alt="AI">
</p>

<p align="center">
  <strong>Next-Gen Automated Threat Hunting & Incident Response Platform</strong>
</p>

[简体中文](README.md) | [日本語](README_JP.md)

---

### 📖 Introduction

**Argus** is named after "Argus Panoptes" (All-seeing) from Greek mythology, symbolizing eternal vigilance over system security. It is a modern, cross-platform security tool designed for **Red/Blue Teams, Incident Response, and Threat Hunting**, dedicated to providing more covert, powerful, and intelligent threat detection capabilities.

Argus fully supports both **Windows** and **Linux**, and has been deeply refactored with Native API integration specifically for the Windows platform, eliminating dependencies on external commands like `cmd.exe` and `powershell.exe`. Even if system tools are tampered with by Rootkits, Argus can still bypass them to retrieve the true system state via low-level APIs, ensuring the integrity and credibility of forensic results.

---

### 🎯 Key Features

#### 1. Zero-Dependency Native Engine
- **Windows Platform**
  - Fully utilizes Native API: `CreateToolhelp32Snapshot`, `QueryFullProcessImageName`, `dbghelp.dll`, `wintrust.dll`
  - No `cmd.exe`/`powershell.exe` calls, avoiding command-line log leakage
  - Bypasses tampered user-mode tools (tasklist, netstat, etc.)
  - Process Integrity Level checks for safe scanning of system processes
  
- **Linux Platform**
  - Pure Go implementation of `/proc` filesystem parsing
  - No dependency on Python or Shell scripts
  - Directly reads kernel data structures

- **Single Binary Deployment**
  - Statically compiled, ready to use out of the box
  - No runtime dependencies, ideal for offline/intranet environments

#### 2. Deep Memory Adversarial Technology

- **RWX Memory Segment Scanning**
  - Intelligently identifies executable memory areas (Read-Write-Execute) in processes
  - Accurately locates fileless attack payloads like Shellcode and CobaltStrike Beacons
  
- **Stack Walking Analysis**
  - Uses `dbghelp.dll` to traverse thread call stacks
  - Detects code execution without module backing (Unbacked Code)
  - Uncovers process injection and reflective DLL loading

- **In-Memory YARA Scanning**
  - Built-in YARA engine directly matches malicious signatures in process memory
  - Supports extension with custom rule sets
  - ~~MiniDump Snapshot for preserving high-risk process scenes~~ (Not implemented, pending)

#### 3. AI Intelligent Analysis Engine

- **Large Language Model Integration**
  - Supports DeepSeek and Gemini AI interfaces
  - Automatically uploads scan reports to generate threat analysis and mitigation suggestions
  - Intelligent data filtering, sending only Critical/High/Medium level alerts
  
- **Flexible Configuration**
  - Persistent settings via YAML config file (`config/ai.yaml`)
  - Temporary override via command-line arguments
  - Auto-generation of `argus_ai_input.json` for debugging

#### 4. Deep Forensics & Historical Traceback

- **Windows Forensics Engine**
  - **Prefetch Parsing**: Restores program execution history (even if files are deleted)
  - **ShimCache Analysis**: Extracts application compatibility cache data
  - **LNK Shortcuts**: Parses traces of recently accessed files
  - **RecentDocs**: Registry records of recent documents
  
- **Linux Audit Logs**
  - Auth log analysis
  - Bash/Zsh history
  - systemd journal parsing

#### 5. Threat Intelligence Integration

- **Online Intelligence Query**
  - VirusTotal file hash detection
  - AbuseIPDB IP reputation verification
  - Real-time threat assessment of network connections

#### 6. Visual Attack Graph

- **DOT Format Export**
  - Process relationship tree (Parent-Child)
  - Network connection topology (Process → RemoteIP)
  - Supports Graphviz rendering

---

### 🔬 Technical Advantages

#### Tech Stack

| Component | Tech/Library | Description |
|------|---------|------|
| **Language** | Go 1.24 | Static compilation, high performance, cross-platform |
| **YARA Engine** | hillu/go-yara v4 | Memory/File malicious signature matching |
| **Windows API** | golang.org/x/sys/windows | Native API bindings |

#### Architecture Highlights

1. **Anti-Detection Design**
   - No CMD/PowerShell calls, avoiding SIEM alerts
   - Directly reads kernel data, bypassing user-mode Rootkits

2. **High-Efficiency Concurrency**
   - Go routines for concurrent scanning
   - Timeout protection mechanisms

3. **Modular Plugins**
   - Unified interface (`core.Plugin`)
   - Auto-loading of platform-specific plugins

---

### 📋 Feature Matrix

#### Windows Platform

| Category | Feature | Implementation | Status |
|------|------|----------|------|
| **👤 User Security** | Hidden Account Detection | Native SAM API | ✅ Completed |
| | Clone Account Detection | SID Comparison | ✅ Completed |
| **🚀 Process Analysis** | Process List Enumeration | `CreateToolhelp32Snapshot` | ✅ Completed |
| | Digital Signature Verification | `wintrust.dll` | ✅ Completed |
| | Hidden Process Detection | PID Traversal Comparison | ✅ Completed |
| **💾 Memory Adversarial** | RWX Scanning | `VirtualQueryEx` | ✅ Completed |
| | Stack Walking | `StackWalk64` | ✅ Completed |
| | In-Memory YARA | YARA Engine | ✅ Completed |
| | ~~MiniDump Snapshot~~ | ~~`MiniDumpWriteDump`~~ | ⏸️ Not Enabled |
| **🌐 Network Monitoring** | TCP/UDP Connections | `GetExtendedTcpTable` | ✅ Completed |
| **🕷️ Persistence** | Registry/Services/Tasks | Native API Scanning | ✅ Completed |
| **📂 File Scanning** | Webshell Detection | Entropy + YARA | ✅ Completed |
| **🕰️ Forensics** | Prefetch/ShimCache/LNK | Binary/Registry Parsing | ✅ Completed |

---

**Built with ❤️ for Cybersecurity Community**
