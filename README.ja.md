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
- ブラウザの存在とChromium系拡張機能ディレクトリ数
- 一部のシェル設定と`.env`にあるSecretらしい設定名
- Git、SSH、クラウド認証ファイルの権限
- 開発用CLIの存在と認証ファイルの権限
- ローカル以外でListenするTCPポートとAIエージェント設定ディレクトリ
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
設定ファイルの代入値は組み立てずに読み飛ばす。レポートは0600で保存し、
Git管理から除外する。詳しくは[安全設計](docs/security-model.md)へ。

## プライバシー

Telemetry、Cloud Upload、Remote API、Secret CollectionはすべてOFF。
CIは架空の認証情報だけでテストし、実環境監査はしない。

## 対応OS

macOSを優先実装。WindowsとLinuxのOS・Network検査は未実装と表示する。

## Scanner一覧

| カテゴリ | 現在の範囲 |
| --- | --- |
| `os` | macOSの主要設定 |
| `browser` | 存在と拡張機能数 |
| `api` | Secretらしい設定名とファイル権限 |
| `git` | `.gitignore`と履歴検査の案内 |
| `ssh` | ディレクトリと鍵の権限 |
| `cloud` | CLIと認証ファイルの存在・権限 |
| `dev` | 開発用CLIと認証ファイルの存在・権限 |
| `network` | macOSのTCP Listen |
| `ai` | エージェント設定ディレクトリの存在・権限 |

拡張機能の権限、MFA、クラウドIAM、Git履歴内Secretなどは手動確認が必要。

## リスクレベル

`CRITICAL`、`HIGH`、`MEDIUM`、`LOW`、`INFO`の順。
非ループバックのListenは確認優先度としてHIGHにするが、
それだけでインターネット公開を意味しない。

## 修正

`fix`はプレビュー。`fix --apply`は一部の権限を狭めるだけ。
キー失効、IAMやMFA変更、削除は自動実行しないよ。

## ロードマップ

OS対応拡大、拡張機能・AI権限の詳細確認、オプトインのオフラインGit履歴検査、
MFAチェックリストを順に検討する。

## コントリビューション

[CONTRIBUTING.md](CONTRIBUTING.md)を参照。実際の認証情報はテストやIssueに入れないでね。

## ライセンス

MIT。詳細は[LICENSE](LICENSE)。
