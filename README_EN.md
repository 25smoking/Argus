# Argus - Offline-First Incident Response and Threat Hunting Tool

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go%201.24-blue.svg" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Mode-Offline%20First-success.svg" alt="Offline">
  <img src="https://img.shields.io/badge/Rules-Updatable-orange.svg" alt="Rules">
  <img src="https://img.shields.io/badge/AI-Optional-purple.svg" alt="AI">
</p>

<p align="center">
  <strong>A standalone professional security tool for incident response, host forensics, and threat hunting.</strong>
</p>

[简体中文](README.md) | [日本語](README_JP.md)

---

### Introduction

**Argus** is named after Argus Panoptes, the all-seeing guardian from Greek mythology.

Argus is a modern cross-platform security tool for **incident response, host forensics, threat hunting, and blue-team triage**. The current version focuses on a standalone professional workflow: **offline use, external rule bundles, explicit online updates, low-disturbance default scanning, structured reports, and reproducible release packages**.

Argus supports **Windows**, **Linux**, and **macOS**. On Windows it prefers platform APIs over external commands such as `cmd.exe` and `powershell.exe`. On Linux it focuses on `/proc`, logs, accounts, startup items, and persistence locations. On macOS it currently supports the common local modules, including host, process, network, file, webshell, and malware rule scanning.

---

### Key Features

#### 1. Offline-First Standalone Operation

- Normal scans do not automatically connect to the Internet.
- `--offline` disables AI, threat-intelligence lookups, and rule-update network requests.
- Reports are written locally to `reports/` by default.

#### 2. External Rule Bundle and Online Updates

- Full YARA rules are no longer embedded into the main binary.
- The default rule directory is the hidden `.rule/` directory next to the binary.
- External rule directories are supported for USB, intranet, and offline distribution.
- Rule management commands: `argus rules update/status/verify/list`.
- `rules.lock.json` records source, SHA256, license, update time, compatibility, and enabled status.

#### 3. Scan Profiles

| Profile | Purpose | Default Behavior |
|---|---|---|
| `quick` | Fast triage | Host, process, and network overview |
| `standard` | Recommended default | Low-disturbance scan, no memory/stack scan by default |
| `deep` | Deeper investigation | Enables deeper modules when explicitly selected |
| `forensic` | Case-oriented scan | Includes case ID, rule version, evidence summary, and richer reports |

#### 4. Platform Capabilities

- Windows: process enumeration, signature checks, memory scanning, Prefetch, ShimCache, LNK, RecentDocs, registry/services/tasks persistence.
- Linux: account checks, SSH key and shell history review, auth logs, cron/systemd/rc.local persistence, high-risk drop locations.
- macOS: host, process, network, file, webshell, malware, and general local triage modules.

#### 5. Structured Reports

- JSON: machine-readable session report.
- HTML: human-readable summary with coverage, skipped modules, findings, and advice.
- JSONL: optional finding stream.
- DOT attack graph: generated for each scan and referenced by the JSON report.

---

### Recommended Release Layout

```text
argus-release/
  argus or argus.exe
  .rule/
    rules.lock.json
    RULES_LICENSE.md
    malware_rules/
    webshell_rules/
  config/
    argus.yaml
    rule_sources.yaml
  SECURITY.md
  FALSE_POSITIVE.md
  PRIVACY.md
  RULES_LICENSE.md
  SHA256SUMS
```

If `.rule/` is missing, Argus falls back to the minimal built-in rules and marks the coverage gap in the report.

---

### Quick Start

#### Build

```bash
make build
make checksums
```

Argus uses the YARA-X Go binding. Install YARA-X CAPI and pkg-config before building:

```bash
# macOS example
brew install yara-x pkg-config
CGO_ENABLED=1 go build -tags static_link -trimpath -ldflags "-s -w -buildid=" -o argus ./cmd/argus
```

Release builds should use `-trimpath`, stripped symbols, and an empty Go build id to reduce local build-path exposure.

#### Version

```bash
argus version
```

#### Default Offline Scan

```bash
argus scan --offline
```

Recommended first scan for incident response. It reads `.rule/` next to the binary and writes reports to `reports/`.

#### Quick Scan

```bash
argus scan --profile quick --offline
```

#### Deep Scan

```bash
argus scan --profile deep --module memory,stack
```

`MemoryScan` and `StackHunter` are Windows-only. On macOS/Linux they are reported as unavailable in the terminal and reports.

#### Forensic Scan

```bash
argus scan --profile forensic --case-id CASE-001
```

#### Module Selection

```bash
argus all
argus scan all
argus scan --module all
argus scan --module process,network
argus scan --module webshell
argus scan --module memory,stack --profile deep
```

Common module keywords:

| Keyword | Module | Rule/Engine Basis | Purpose |
|---|---|---|---|
| `process` / `proc` | `ProcessScan` | `config/process_rules.yaml` behavior rules | Process command lines, parent-child relations, LoLBin abuse, reverse shells, credential dumping, recovery disruption |
| `network` / `net` | `NetworkScan` / `ThreatIntel` | `config/network_rules.yaml` behavior rules; ThreatIntel requires explicit network/API access | Connections, suspicious processes, ports, domains, connection spikes |
| `file` | `FileScan` | `config/file_rules.yaml` behavior rules | Permissions, suspicious paths, sensitive files, startup locations, small-file content patterns |
| `malware` | `MalwareScan` | Full YARA-X rules in `.rule/malware_rules` | Malware, hacktools, APT, ransomware, backdoors |
| `webshell` | `WebshellScan` | Full YARA-X rules in `.rule/webshell_rules` plus entropy/keyword fallback | Webshell and web script scanning |
| `memory` / `mem` | `MemoryScan` / `StackHunter` | Windows `MemoryScan` reuses `.rule/malware_rules`; `StackHunter` is heuristic | Deep memory and stack checks |
| `account` / `user` | Account plugins | Platform APIs, `/etc/passwd`, user/group heuristics | Account security review |
| `persist` | Persistence plugins | Built-in `persistence_rules.yaml`, overrideable under `config/`, plus platform APIs/files | Registry, services, startup items, scheduled tasks |

`all` runs all local modules available on the current platform and is equivalent to `--module all --profile forensic`. External threat intelligence remains controlled by `--no-network`.

`ProcessScan`, `NetworkScan`, and `FileScan` use project YAML behavior rules. `MalwareScan` and `WebshellScan` use full YARA rules under `.rule/`. Windows `MemoryScan` reuses malware YARA rules for memory scanning.

Behavior-rule references include:

| Source | Used For |
|---|---|
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Windows process creation ideas: PowerShell, Certutil, Bitsadmin, MSHTA, Regsvr32, Rundll32, scheduled tasks, service creation |
| [MITRE ATT&CK](https://attack.mitre.org/) | ATT&CK technique mapping such as `T1059`, `T1003.001`, `T1490`, `T1543`, `T1053` |
| [LOLBAS](https://lolbas-project.github.io/) | Windows LOLBin behavior |
| [GTFOBins](https://gtfobins.org/) | Linux/macOS reverse shell and interpreter behavior |
| [Tencent Cloud kdevtmpfsi case](https://cloud.tencent.com/developer/article/1744547) | Kinsing, kdevtmpfsi, `ld.so.preload`, `bot.service`, crontab persistence |
| [QiAnXin 95015 IR report](https://pdf.dfcfw.com/pdf/H3_AP202602061819815147_1.pdf?1770412720000.pdf=) | SSH weak password, SSH key persistence, mining via scheduled tasks, lateral movement |
| [Red Canary Linux Coinminers](https://redcanary.com/threat-detection-report/trends/linux-coinminers/) | Kinsing/TeamTNT persistence using `authorized_keys` and `crontab` |
| [Linux persistence hunting](https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/) | cron, systemd service/timer persistence locations |
| [Webshell behavior detection](https://www.blumira.com/blog/how-to-detect-web-shells) | Web service process spawning shells, interpreters, scanners, or proxy tools |
| [FRP execution detection](https://help.fortinet.com/fsiem/Public_Resource_Access/7_1_0/rules/PH_RULE_PUA_Fast_Reverse_Proxy_FRP_Execution.htm) | FRP/NPS/tunnel process, port, and config indicators |

---

### Commands

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

| Command | Purpose |
|---|---|
| `argus scan` | Run host scan |
| `argus all` | Run all local modules available on the current platform |
| `argus scan all` | Same as above, under the `scan` command |
| `argus rules status` | Show rule-bundle status |
| `argus rules update` | Update rules from upstream sources |
| `argus rules verify` | Verify SHA256, lock file, and YARA compatibility |
| `argus rules list` | List rule files, optionally with license/source |
| `argus modules` | Show modules, disturbance level, network need, and admin/root requirement |
| `argus graph` | Generate a DOT attack-graph snapshot |
| `argus version` | Print version, commit, and build time |

Global flags:

| Flag | Example | Purpose |
|---|---|---|
| `--profile` | `--profile standard` | Select `quick`, `standard`, `deep`, or `forensic` |
| `--offline` / `-o` | `--offline` | Disable AI, threat intel, and update network requests |
| `--no-network` | `--no-network=false` | Control scan-time outbound requests |
| `--rules-dir` | `--rules-dir /tmp/rules` | Use an external rule directory |
| `--output-dir` | `--output-dir ./reports` | Report output directory |
| `--case-id` | `--case-id CASE-001` | Case/task identifier |
| `--jsonl` | `--jsonl` | Also write JSONL findings |
| `--module` / `-m` | `--module process,network` | Run selected modules |
| `--ai` | `--ai deepseek` | Enable optional AI-assisted analysis |
| `--key` | `--key YOUR_API_KEY` | AI API key |

---

### Rule Management

```bash
argus rules status
argus rules update --source upstream
argus rules verify
argus rules list --license --source
```

- Online updates are only triggered by `argus rules update`.
- Normal scans do not update rules automatically.
- `--offline` blocks rule updates.
- Existing rules are kept if update or verification fails.

Rule sources are configured in `config/rule_sources.yaml`. Default upstream sources include Neo23x0 signature-base and Elastic protections-artifacts YARA rules.

---

### Output Files

By default, reports are written to `reports/`:

```text
argus_report_YYYYMMDD_HHMMSS.json
argus_report_YYYYMMDD_HHMMSS.html
argus_findings_YYYYMMDD_HHMMSS.jsonl
attack_graph_YYYYMMDD_HHMMSS.dot
```

Report fields include:

- `scan_session`
- `rule_bundle`
- `profile`
- `coverage`
- `findings[]`
- `evidence[]`
- `timeline[]`
- `skipped_modules[]`

---

### Configuration

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

#### Behavior Rules

| Config File | Module | Rule Type |
|---|---|---|
| `config/process_rules.yaml` | `ProcessScan` | Command lines, parent-child relations, LoLBin abuse, credential dumping, ransomware preparation, defense tampering, mining, proxy tunnels, reconnaissance |
| `config/network_rules.yaml` | `NetworkScan` | Suspicious network processes, risky ports, mining/tunnel/staging domains, connection spikes, exposed listeners |
| `config/file_rules.yaml` | `FileScan` | Suspicious names, paths, sensitive files, small-file content, webroot scripts, LD_PRELOAD rootkits, systemd/cron/SSH persistence |
| Built-in `persistence_rules.yaml` | Windows `Persistence` | Registry, services, startup items, scheduled tasks, WMI persistence |

---

### 2026-05-08 Update Notes

- Simplified commands: `argus all`, `argus scan all`, `--module all`, and `argus modules`.
- Rule system: default `.rule/`, `rules status/update/verify/list`, and full YARA-X integration.
- Behavior rules: expanded process, network, and file YAML rules for LoLBin abuse, mining, proxy tunnels, persistence, and webshell behavior.
- Reports: JSON/HTML now include scan session, rule source, skipped modules, Chinese network-policy text, and DOT attack graph metadata.
- Release engineering: default builds use `-trimpath`, empty build id, version injection, and GitHub Actions release builds.

---

### Verification Status

Verified locally:

```bash
go test ./...
make build
argus rules update --source upstream
argus rules verify
argus scan --profile quick --offline --jsonl
```

---

### Roadmap

- Linux LKM rootkit detection
- More rule metadata and MITRE ATT&CK mapping
- Stronger forensic timeline and event correlation
- Windows code signing and release verification
- macOS deep forensic modules
- Container/cloud environment checks
- Local IOC database
- Sigma rule support

---

### License

Argus itself is released under the MIT License.

Third-party rule sources keep their original licenses. See `RULES_LICENSE.md` and the generated `.rule/RULES_LICENSE.md` after `argus rules update`.
