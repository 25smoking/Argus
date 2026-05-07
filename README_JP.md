# Argus - オフライン優先のインシデントレスポンス / 脅威ハンティングツール

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go%201.24-blue.svg" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Mode-Offline%20First-success.svg" alt="Offline">
  <img src="https://img.shields.io/badge/Rules-Updatable-orange.svg" alt="Rules">
  <img src="https://img.shields.io/badge/AI-Optional-purple.svg" alt="AI">
</p>

<p align="center">
  <strong>インシデントレスポンス、ホストフォレンジック、脅威ハンティング向けの単体プロフェッショナルツール。</strong>
</p>

[简体中文](README.md) | [English](README_EN.md)

---

### 概要

**Argus** は、ギリシャ神話に登場する百眼の巨人 Argus Panoptes に由来します。

Argus は **インシデントレスポンス、ホストフォレンジック、脅威ハンティング、ブルーチーム調査** 向けのクロスプラットフォームセキュリティツールです。現在のバージョンでは、**オフライン利用、外部ルールバンドル、明示的なオンライン更新、低負荷のデフォルトスキャン、構造化レポート、再現可能なリリースパッケージ** を重視しています。

Argus は **Windows**、**Linux**、**macOS** をサポートします。Windows では `cmd.exe` や `powershell.exe` などの外部コマンドよりもプラットフォーム API を優先します。Linux では `/proc`、ログ、アカウント、起動項目、永続化箇所を中心に確認します。macOS ではホスト、プロセス、ネットワーク、ファイル、Webshell、マルウェアルールスキャンなどの共通ローカルモジュールを利用できます。

---

### 主な機能

#### 1. オフライン優先の単体運用

- 通常のスキャンでは自動的に外部通信しません。
- `--offline` は AI、脅威インテリジェンス照会、ルール更新のネットワーク要求を無効化します。
- レポートはデフォルトでローカルの `reports/` に保存されます。

#### 2. 外部ルールバンドルとオンライン更新

- 完全な YARA ルールはメインバイナリに埋め込みません。
- デフォルトのルールディレクトリは、バイナリと同じ場所の隠しディレクトリ `.rule/` です。
- USB、イントラネット共有、オフライン配布向けに外部ルールディレクトリを指定できます。
- ルール管理コマンド: `argus rules update/status/verify/list`。
- `rules.lock.json` には、ソース、SHA256、ライセンス、更新時刻、互換性、有効状態が記録されます。

#### 3. スキャン Profile

| Profile | 目的 | デフォルト動作 |
|---|---|---|
| `quick` | 高速確認 | ホスト、プロセス、ネットワーク概要 |
| `standard` | 推奨デフォルト | 低負荷スキャン。メモリ/スタックはデフォルト無効 |
| `deep` | 深掘り調査 | 明示的に指定した深度モジュールを利用 |
| `forensic` | 取証向け | Case ID、ルールバージョン、証拠概要、詳細レポート |

#### 4. プラットフォーム別能力

- Windows: プロセス列挙、署名確認、メモリスキャン、Prefetch、ShimCache、LNK、RecentDocs、レジストリ/サービス/タスク永続化。
- Linux: アカウント確認、SSH key、Shell history、auth log、cron/systemd/rc.local 永続化、高リスク落下場所。
- macOS: ホスト、プロセス、ネットワーク、ファイル、Webshell、マルウェア、共通ローカル調査モジュール。

#### 5. 構造化レポート

- JSON: 機械処理しやすいスキャンセッションレポート。
- HTML: カバレッジ、スキップモジュール、発見項目、対処案を表示。
- JSONL: オプションの発見項目ストリーム。
- DOT 攻撃グラフ: 各スキャンで生成され、JSON レポートに記録されます。

---

### 推奨リリース構成

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

`.rule/` が存在しない場合、Argus は最小限の内蔵ルールへフォールバックし、レポート内にカバレッジ不足を記録します。

---

### クイックスタート

#### ビルド

```bash
make build
make checksums
```

Argus は完全な libyara エンジンを使用します。ビルド前に libyara と pkg-config をインストールしてください。

```bash
# macOS example
brew install yara pkg-config
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -buildid=" -o argus ./cmd/argus
```

リリースビルドでは `-trimpath`、シンボル削除、空の Go build id を使い、ローカルビルドパスの露出を減らします。

#### バージョン表示

```bash
argus version
```

#### デフォルトのオフラインスキャン

```bash
argus scan --offline
```

インシデント対応の初期確認に推奨されるスキャンです。バイナリ横の `.rule/` を読み込み、`reports/` にレポートを出力します。

#### 高速スキャン

```bash
argus scan --profile quick --offline
```

#### 深度スキャン

```bash
argus scan --profile deep --module memory,stack
```

`MemoryScan` と `StackHunter` は Windows 専用です。macOS/Linux ではターミナルとレポートに利用不可として記録されます。

#### 取証モード

```bash
argus scan --profile forensic --case-id CASE-001
```

#### モジュール指定

```bash
argus all
argus scan all
argus scan --module all
argus scan --module process,network
argus scan --module webshell
argus scan --module memory,stack --profile deep
```

よく使うモジュールキーワード:

| キーワード | モジュール | ルール/エンジン根拠 | 用途 |
|---|---|---|---|
| `process` / `proc` | `ProcessScan` | `config/process_rules.yaml` 行動ルール | コマンドライン、親子プロセス、LoLBin、リバースシェル、認証情報ダンプ、復旧妨害 |
| `network` / `net` | `NetworkScan` / `ThreatIntel` | `config/network_rules.yaml` 行動ルール。ThreatIntel は明示的なネットワーク/API が必要 | 通信、異常プロセス、ポート、ドメイン、接続急増 |
| `file` | `FileScan` | `config/file_rules.yaml` 行動ルール | 権限、疑わしいパス、機密ファイル、起動項目、小ファイル内容 |
| `malware` | `MalwareScan` | `.rule/malware_rules` の完全 libyara ルール | マルウェア、Hacktool、APT、ランサムウェア、バックドア |
| `webshell` | `WebshellScan` | `.rule/webshell_rules` の完全 libyara ルール + エントロピー/キーワード補助 | Webshell と Web スクリプト検出 |
| `memory` / `mem` | `MemoryScan` / `StackHunter` | Windows `MemoryScan` は `.rule/malware_rules` を再利用。`StackHunter` はヒューリスティック | 深度メモリ/スタック確認 |
| `account` / `user` | アカウント系プラグイン | プラットフォーム API、`/etc/passwd`、ユーザー/グループのヒューリスティック | アカウントセキュリティ確認 |
| `persist` | 永続化プラグイン | 内蔵 `persistence_rules.yaml`。`config/` で上書き可能 + API/ファイル位置 | レジストリ、サービス、起動項目、タスク |

`all` は現在のプラットフォームで利用可能なすべてのローカルモジュールを実行し、`--module all --profile forensic` と同等です。外部脅威インテリジェンスは `--no-network` に従います。

`ProcessScan`、`NetworkScan`、`FileScan` はプロジェクト内 YAML 行動ルールを使用します。`MalwareScan` と `WebshellScan` は `.rule/` 内の完全な YARA ルールを使用します。Windows の `MemoryScan` は malware YARA ルールをメモリスキャンに再利用します。

行動ルールの参考元:

| ソース | Argus での利用 |
|---|---|
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Windows process creation: PowerShell、Certutil、Bitsadmin、MSHTA、Regsvr32、Rundll32、タスク、サービス作成 |
| [MITRE ATT&CK](https://attack.mitre.org/) | `T1059`、`T1003.001`、`T1490`、`T1543`、`T1053` などの技術マッピング |
| [LOLBAS](https://lolbas-project.github.io/) | Windows LOLBin 行動 |
| [GTFOBins](https://gtfobins.org/) | Linux/macOS のリバースシェル、インタプリタ実行 |
| [Tencent Cloud kdevtmpfsi case](https://cloud.tencent.com/developer/article/1744547) | Kinsing、kdevtmpfsi、`ld.so.preload`、`bot.service`、crontab 永続化 |
| [QiAnXin 95015 IR report](https://pdf.dfcfw.com/pdf/H3_AP202602061819815147_1.pdf?1770412720000.pdf=) | SSH 弱パスワード、SSH key 永続化、タスクによるマイニング、横展開 |
| [Red Canary Linux Coinminers](https://redcanary.com/threat-detection-report/trends/linux-coinminers/) | Kinsing/TeamTNT の `authorized_keys`、`crontab` 永続化 |
| [Linux persistence hunting](https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/) | cron、systemd service/timer 永続化 |
| [Webshell behavior detection](https://www.blumira.com/blog/how-to-detect-web-shells) | Web サービスプロセスが Shell、インタプリタ、スキャナ、プロキシツールを起動する行動 |
| [FRP execution detection](https://help.fortinet.com/fsiem/Public_Resource_Access/7_1_0/rules/PH_RULE_PUA_Fast_Reverse_Proxy_FRP_Execution.htm) | FRP/NPS/トンネル系のプロセス、ポート、設定痕跡 |

---

### コマンド

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

| コマンド | 用途 |
|---|---|
| `argus scan` | ホストスキャンを実行 |
| `argus all` | 現在のプラットフォームで利用可能な全ローカルモジュールを実行 |
| `argus scan all` | `scan` サブコマンド形式で全ローカルモジュールを実行 |
| `argus rules status` | ルールバンドル状態を表示 |
| `argus rules update` | 上流ソースからルール更新 |
| `argus rules verify` | SHA256、lock、YARA 互換性を検証 |
| `argus rules list` | ルールファイルを一覧表示。ライセンス/ソース表示も可能 |
| `argus modules` | モジュール、負荷、ネットワーク要否、管理者/root 要否を表示 |
| `argus graph` | DOT 攻撃グラフを生成 |
| `argus version` | バージョン、commit、ビルド時刻を表示 |

グローバルフラグ:

| フラグ | 例 | 用途 |
|---|---|---|
| `--profile` | `--profile standard` | `quick`、`standard`、`deep`、`forensic` を選択 |
| `--offline` / `-o` | `--offline` | AI、脅威インテリジェンス、更新系通信を無効化 |
| `--no-network` | `--no-network=false` | スキャン中の外部通信を制御 |
| `--rules-dir` | `--rules-dir /tmp/rules` | 外部ルールディレクトリを指定 |
| `--output-dir` | `--output-dir ./reports` | レポート出力先 |
| `--case-id` | `--case-id CASE-001` | 案件/タスク番号 |
| `--jsonl` | `--jsonl` | JSONL 形式の発見項目も出力 |
| `--module` / `-m` | `--module process,network` | 指定モジュールのみ実行 |
| `--ai` | `--ai deepseek` | 任意の AI 補助分析を有効化 |
| `--key` | `--key YOUR_API_KEY` | AI API Key |

---

### ルール管理

```bash
argus rules status
argus rules update --source upstream
argus rules verify
argus rules list --license --source
```

- オンライン更新は `argus rules update` を実行した場合のみ行われます。
- 通常スキャンでは自動更新しません。
- `--offline` はルール更新を禁止します。
- 更新や検証に失敗した場合、既存ルールを保持します。

ルールソースは `config/rule_sources.yaml` で設定します。デフォルトでは Neo23x0 signature-base と Elastic protections-artifacts の YARA ルールを利用します。

---

### 出力ファイル

デフォルトでは `reports/` に出力されます。

```text
argus_report_YYYYMMDD_HHMMSS.json
argus_report_YYYYMMDD_HHMMSS.html
argus_findings_YYYYMMDD_HHMMSS.jsonl
attack_graph_YYYYMMDD_HHMMSS.dot
```

主なレポートフィールド:

- `scan_session`
- `rule_bundle`
- `profile`
- `coverage`
- `findings[]`
- `evidence[]`
- `timeline[]`
- `skipped_modules[]`

---

### 設定

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

#### 行動ルール

| 設定ファイル | モジュール | ルール種別 |
|---|---|---|
| `config/process_rules.yaml` | `ProcessScan` | コマンドライン、親子プロセス、LoLBin、認証情報ダンプ、ランサム前段、防御無効化、マイニング、プロキシトンネル、偵察 |
| `config/network_rules.yaml` | `NetworkScan` | 異常通信プロセス、高リスクポート、マイニング/トンネル/一時ホスティングドメイン、接続急増、外部公開リスナー |
| `config/file_rules.yaml` | `FileScan` | 疑わしい名前、パス、機密ファイル、小ファイル内容、Webroot スクリプト、LD_PRELOAD Rootkit、systemd/cron/SSH 永続化 |
| 内蔵 `persistence_rules.yaml` | Windows `Persistence` | レジストリ、サービス、起動項目、タスク、WMI 永続化 |

---

### 2026-05-08 更新メモ

- コマンド簡略化: `argus all`、`argus scan all`、`--module all`、`argus modules`。
- ルール体系: デフォルト `.rule/`、`rules status/update/verify/list`、完全 libyara 連携。
- 行動ルール: process/network/file YAML を拡張し、LoLBin、マイニング、プロキシトンネル、永続化、Webshell 行動を追加。
- レポート: JSON/HTML にスキャンセッション、ルールソース、スキップモジュール、中国語ネットワークポリシー、DOT 攻撃グラフ情報を追加。
- リリース工程: `-trimpath`、空 build id、バージョン注入、GitHub Actions リリースビルドを追加。

---

### 検証状態

ローカル検証済み:

```bash
go test ./...
make build
argus rules update --source upstream
argus rules verify
argus scan --profile quick --offline --jsonl
```

---

### ロードマップ

- Linux LKM Rootkit 検出
- より詳細なルールメタデータと MITRE ATT&CK マッピング
- フォレンジックタイムラインとイベント相関の強化
- Windows コード署名とリリース検証
- macOS 深度フォレンジックモジュール
- コンテナ/クラウド環境検出
- ローカル IOC データベース
- Sigma ルール対応

---

### ライセンス

Argus 本体は MIT License です。

第三者ルールは各上流のライセンスに従います。`RULES_LICENSE.md` および `argus rules update` 後に生成される `.rule/RULES_LICENSE.md` を確認してください。
