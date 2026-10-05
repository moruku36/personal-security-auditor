# Personal Security Auditor

[English](README.md) | [日本語](README.ja.md)

## 概要

PCのセキュリティ状態をローカルで確認するCLIだよ。Secretの値は集めず、
設定や権限などのメタデータから見直し候補を表示する。

## なぜ作るか

開発用の認証情報やAIエージェント設定はあちこちに分散しがち。
まず安全な方法で現状を整理するためのツールです。

## 機能

- macOSのFileVault、Firewall、Gatekeeper、SIP、Remote Login
- Windowsのドライブ暗号化、Firewall、Defender、UAC、Secure Boot
- ブラウザの存在、Chrome拡張manifestの限定メタデータと権限確認
- `.env`やシェル設定ファイルの存在・権限メタデータ（本文は読み取らない）
- Git、SSH、クラウド認証ファイルの権限
- 開発用CLIの存在と認証ファイルの権限
- macOS/Windowsでローカル以外を待ち受けるTCPポートとAIエージェント設定ディレクトリ
- Terminal、Markdown、JSONレポートと権限修正のプレビュー

## アーキテクチャ

Scannerは`detect`、`scan`、`recommendations`を実装し、共通のFindingを返す。
[設計](docs/architecture.md)、[安全設計](docs/security-model.md)、
[脅威モデル](docs/threat-model.md)を参照。

## インストール

Python 3.11以上。実行時の外部依存とネットワーク通信はないよ。

```sh
python3 -m pip install -e .
```

WindowsではPowerShellで`py -3.11 -m pip install -e .`を実行する。
Windowsの検査はWSLではなくWindows上で実行してね。通常のスキャンに管理者権限は不要。
権限不足で読めない項目は「確認できない」と表示する。

## すぐ使う

```sh
security-audit scan --full
security-audit scan api
security-audit report --format markdown --output reports/latest.md
security-audit fix            # プレビューのみ
security-audit fix --apply    # 表示された権限変更を適用
```

## セキュリティモデル

Secret値、ブラウザの保存パスワード、秘密鍵の内容を取得・出力しない。
`api`は選択した設定ファイルの存在と権限だけを確認し、本文を開かない。
ブラウザ監査は上限付きmanifestだけを読み、レポートはmacOSで0600、
Windowsで本人専用のACLを設定して保存し、
Git管理から除外する。詳しくは[安全設計](docs/security-model.md)へ。

## プライバシー

Telemetry、Cloud Upload、Remote API、Secret CollectionはすべてOFF。
CIは架空の認証情報だけでテストし、実環境監査はしない。

## 対応OS

macOSとWindows 10/11に対応。Windowsは標準搭載のWindows PowerShellを使って
ローカルで確認する。LinuxのOS・Network検査は未実装と表示する。
Windowsの検査範囲と制限は[Windows checks](docs/windows.md)を参照。

## Scanner一覧

| カテゴリ | 現在の範囲 |
| --- | --- |
| `os` | macOS/Windowsの主要設定 |
| `browser` | ブラウザdir、限定manifestメタデータ、Windows Chromeポリシーの有無 |
| `api` | 設定ファイルの存在と権限。本文は読まない |
| `git` | `.gitignore`と履歴検査の案内 |
| `ssh` | ディレクトリと鍵の権限、WindowsではACL |
| `cloud` | CLIと認証ファイルの存在・権限、WindowsではACL |
| `dev` | 開発用CLIと認証ファイルの存在・権限、WindowsではACL |
| `network` | macOS/WindowsのTCP待受 |
| `ai` | エージェント設定ディレクトリの存在・権限 |

実際に許可された拡張権限、MFA、passkey、Windows Hello/PIN、クラウドIAM、
Git履歴内Secretなどは手動確認が必要。本人用の[チェックリスト](docs/manual-security-checklist.ja.md)を参照。

## リスクレベル

`CRITICAL`、`HIGH`、`MEDIUM`、`LOW`、`INFO`の順。
非ループバックのListenは確認優先度としてHIGHにするが、
それだけでインターネット公開を意味しない。

## 修正

macOSでは`fix`はプレビュー、`fix --apply`は一部の権限を狭めるだけ。
WindowsのACL検査は読み取り専用で、自動修正しない。
キー失効、IAMやMFA変更、削除は自動実行しないよ。

## ロードマップ

OS対応拡大、拡張機能・AI権限の詳細確認、オプトインのオフラインGit履歴検査、
MFAチェックリストを順に検討する。

## コントリビューション

[CONTRIBUTING.md](CONTRIBUTING.md)を参照。実際の認証情報はテストやIssueに入れないでね。

## ライセンス

MIT。詳細は[LICENSE](LICENSE)。
