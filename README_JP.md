# 👁️ Argus - 次世代インシデントレスポンス＆脅威ハンティングプラットフォーム

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go%201.24-blue.svg" alt="Go">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Build-Native%20API-orange.svg" alt="Native">
  <img src="https://img.shields.io/badge/AI-DeepSeek%20%7C%20Gemini-purple.svg" alt="AI">
</p>

[English](README.md) | [简体中文](README_CN.md)

---

### 📖 概要

**Argus**（アルゴス）は、ギリシャ神話の「百眼の巨人」に由来し、システムセキュリティを常時監視することを意味します。これは、**レッド/ブルーチーム、インシデントレスポンス、脅威ハンティング**向けに設計された最新のクロスプラットフォームセキュリティツールであり、より隠密で、強力で、インテリジェントな脅威検出機能を提供することを目指しています。

Argus は **Windows** と **Linux** の両方を完全にサポートしており、特に Windows では Native API レベルで深く再構築され、`cmd.exe` や `powershell.exe` などの外部コマンドへの依存を排除しました。たとえシステムツールが Rootkit によって改ざんされていたとしても、Argus は低レベル API を通じて真のシステム状態を直接取得し、フォレンジック結果の完全性と信頼性を保証します。

---

### 🎯 主な機能

#### 1. ゼロ依存 Native エンジン
- **Windows プラットフォーム**
  - Native API を全面的に使用：`CreateToolhelp32Snapshot`、`QueryFullProcessImageName`、`dbghelp.dll`、`wintrust.dll`
  - `cmd.exe`/`powershell.exe` の呼び出しなし、コマンドラインログの漏洩を回避
  - 改ざんされたユーザーモードツール（tasklist、netstat など）をバイパス
  - プロセス整合性レベルのチェック、システムプロセスの安全なスキャン
  
- **Linux プラットフォーム**
  - 純粋な Go による `/proc` ファイルシステム解析
  - Python や Shell スクリプトへの依存なし
  - カーネルデータ構造の直接読み取り

- **単一ファイル展開**
  - 静的コンパイル、即時使用可能
  - ランタイム依存なし、オフライン/イントラネット環境に最適

#### 2. 深度メモリ対抗技術

- **RWX メモリセグメントスキャン**
  - プロセス内の実行可能なメモリ領域（Read-Write-Execute）をインテリジェントに識別
  - Shellcode、CobaltStrike Beacon などのファイルレス攻撃ペイロードを正確に特定
  
- **スタックバックトレース分析 (Stack Walking)**
  - `dbghelp.dll` を使用してスレッド呼び出しスタックを走査
  - モジュールサポートのないコード実行（Unbacked Code）を検出
  - プロセスインジェクション、反射型 DLL ロードを発見

- **メモリ YARA スキャン**
  - 内蔵 YARA エンジン、プロセスメモリ内の悪意のある特徴を直接マッチング
  - カスタムルールセットの拡張をサポート
  - ~~MiniDump スナップショット~~ (未実装、計画中)

#### 3. AI インテリジェント分析エンジン

- **大規模言語モデルの統合**
  - DeepSeek、Gemini AI インターフェースをサポート
  - スキャンレポートを自動アップロードし、脅威分析と対処提案を生成
  - インテリジェントなデータフィルタリング、Critical/High/Medium レベルのアラートのみを送信
  
- **柔軟な設定**
  - YAML 設定ファイル (`config/ai.yaml`) による永続設定
  - コマンドライン引数による一時的な上書き
  - デバッグ用の `argus_ai_input.json` 自動生成

#### 4. 深度フォレンジックと履歴追跡

- **Windows フォレンジックエンジン**
  - **Prefetch 解析**：プログラムの実行履歴を復元（ファイルが削除されていても可）
  - **ShimCache 分析**：アプリケーション互換性キャッシュデータを抽出
  - **LNK ショートカット**：最近アクセスしたファイルの痕跡を解析
  - **RecentDocs**：レジストリの最近のドキュメント記録
  
- **Linux 監査ログ**
  - Auth ログ分析
  - Bash/Zsh 履歴
  - systemd journal 解析

#### 5. 脅威インテリジェンス連携

- **オンラインインテリジェンス照会**
  - VirusTotal ファイルハッシュ検出
  - AbuseIPDB IP 評判検証
  - ネットワーク接続のリアルタイム脅威評価

#### 6. 攻撃グラフの可視化

- **DOT 形式のエクスポート**
  - プロセス関係ツリー（Parent-Child）
  - ネットワーク接続トポロジ（Process → RemoteIP）
  - Graphviz レンダリングをサポート

---

### 🔬 技術的利点

#### 技術スタック

| コンポーネント | 技術/ライブラリ | 説明 |
|------|---------|------|
| **言語** | Go 1.24 | 静的コンパイル、高性能、クロスプラットフォーム |
| **YARA エンジン** | hillu/go-yara v4 | メモリ/ファイルの悪意のある特徴マッチング |
| **Windows EVTX** | 0xrawsec/golang-evtx | イベントログ解析（RDP ログインなど） |
| **システム情報** | gopsutil v3 | クロスプラットフォームシステム指標収集 |
| **CLI フレームワーク** | spf13/cobra | コマンドライン引数解析 |
| **ログ** | zap | 高性能構造化ログ |
| **設定** | yaml.v3 | YAML 設定ファイル解析 |
| **Windows API** | golang.org/x/sys/windows | Native API バインディング |

#### アーキテクチャのハイライト

1. **反検出設計**
   - CMD/PowerShell 呼び出しなし、SIEM アラートを回避
   - カーネルデータを直接読み取り、ユーザーモード Rootkit をバイパス
   - プロセス整合性レベルチェック、クラッシュと暴露を防止

2. **高効率並行処理**
   - Go ルーチンによる複数プロセスの並行スキャン
   - タイムアウト保護メカニズム、フリーズを回避

3. **モジュラープラグイン**
   - プラグイン設計、拡張が容易
   - 統一インターフェース (`core.Plugin`)
   - プラットフォーム固有プラグインの自動ロード

---

### 📋 機能マトリックス

#### Windows プラットフォーム

| カテゴリ | 機能 | 実装方法 | ステータス |
|------|------|----------|------|
| **👤 ユーザーセキュリティ** | 隠しアカウント検出 ($ 接尾辞) | Native SAM API | ✅ 完了 |
| | クローンアカウント検出 | SID 比較分析 | ✅ 完了 |
| | RDP ログインログ | Event Log 解析 | ✅ 完了 |
| **🚀 プロセス分析** | プロセスリスト列挙 | `CreateToolhelp32Snapshot` | ✅ 完了 |
| | デジタル署名検証 | `wintrust.dll` | ✅ 完了 |
| | プロセス引数分析 | コマンドライン特徴検出 | ✅ 完了 |
| | 隠しプロセス検出 | PID 走査比較 | ✅ 完了 |
| **💾 メモリ対抗** | RWX メモリセグメントスキャン | `VirtualQueryEx` | ✅ 完了 |
| | スタックバックトレース (Stack Walking) | `StackWalk64` | ✅ 完了 |
| | メモリ YARA スキャン | YARA エンジン | ✅ 完了 |
| | ~~MiniDump スナップショット~~ | ~~`MiniDumpWriteDump`~~ | ⏸️ 未有効化 |
| **🌐 ネットワーク監視** | TCP/UDP 接続 | `GetExtendedTcpTable` | ✅ 完了 |
| | プロセス-接続マッピング | OwnerPID 関連付け | ✅ 完了 |
| | 脅威インテリジェンス照会 | VT/AbuseIPDB API | ✅ 完了 |
| **🕷️ 持続化** | レジストリ起動項目 | Run/RunOnce/Winlogon 等 | ✅ 完了 |
| | サービスバックドア | サービス列挙 | ✅ 完了 |
| | タスクスケジューラ | `SchTasks` API | ✅ 完了 |
| | WMI イベントサブスクリプション | WMI クエリ | ✅ 完了 |
| | イメージハイジャック (IFEO) | レジストリスキャン | ✅ 完了 |
| **📂 ファイルスキャン** | Webshell 検出 | シャノンエントロピー + YARA | ✅ 完了 |
| | 機密ファイルスキャン | パスホワイトリスト | ✅ 完了 |
| | Hash 脅威インテリジェンス | VirusTotal | ✅ 完了 |
| **🕰️ フォレンジック追跡** | Prefetch 解析 | バイナリ形式解析 | ✅ 完了 |
| | ShimCache 分析 | レジストリ抽出 | ✅ 完了 |
| | LNK ファイル解析 | Shell Link 形式 | ✅ 完了 |
| | RecentDocs抽出 | レジストリ走査 | ✅ 完了 |
| **🔍 脅威ハンティング** | ハッカーツール検出 | プロセス名/パス特徴 | ✅ 完了 |
| | LoLBin 悪用 | 不審な引数検出 | ✅ 完了 |

#### Linux プラットフォーム

| カテゴリ | 機能 | 実装方法 | ステータス |
|------|------|----------|------|
| **👤 ユーザーセキュリティ** | /etc/passwd 異常 | ファイル解析 | ✅ 完了 |
| **🚀 プロセス分析** | プロセスリスト | /proc 解析 | ✅ 完了 |
| **🌐 ネットワーク監視** | TCP/UDP 接続 | /proc/net/tcp | ✅ 完了 |
| **🕷️ 持続化** | Cron/Systemd | ファイル解析 | ✅ 完了 |
| **🔍 Rootkit 検出** | LD_PRELOAD ハイジャック | 環境変数チェック | ✅ 完了 |

---

**Built with ❤️ for Cybersecurity Community**
