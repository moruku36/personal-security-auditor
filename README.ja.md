# Personal Security Auditor

[English](README.md) | [日本語](README.ja.md)

## 概要

**自分のmacOS／Windows端末を防御するための、ローカル実行型セキュリティ確認CLI**です。
OSの保護設定、認証情報を置くファイルの権限、Chrome拡張のmanifest宣言、
ループバック以外で待ち受けるTCPポートなどを調べ、確認すべき点と推奨対応をまとめます。

パスワード、トークン、秘密鍵の値は収集しません。**Google Password Checkupは未実装**です。
保存済みパスワードやアカウント保護、ブラウザー上で実際に有効な権限は別途手動で確認します。
指摘がないことは、端末が安全である証明にはなりません。

自動テストは合成fixtureに加え、Windows上でローカルPowerShellの出力形式と
一時レポートのACLを確認します。[実機での検証](#実機での検証)に記載した
MacとWindows各1台での確認は、その時点の範囲に限られます。すべての端末への対応や
検出の網羅性を保証しません。取得する情報と制約は[安全設計](docs/security-model.md)を参照してください。

## なぜ作るか

秘密の値や端末固有のレポートを外へ送らず、設定と権限の問題を整理し、
本人が手動で見直す項目の優先順位を付けるためのツールです。

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
CIは架空の認証情報を使うfixtureと、Windows上の限定的なOS・ネットワークprobeの
出力形式および一時レポートのACLを確認する。runner全体の監査や安全性の認定は行わない。

## 対応OS

macOSとWindows 10/11に対応。Windowsは標準搭載のWindows PowerShellを使って
ローカルで確認する。LinuxのOS・Network検査は未実装と表示する。
Windowsの検査範囲と制限は[Windows checks](docs/windows.md)を参照。

## 実機での検証

2026-10-06、macOS 27.2 / Python 3.11.4 のMac実機で、監査CLIのスキャンと権限修正フローを実行し、再スキャンまで完了。対象ソースはcommit `20332630d64626a421b5508244cc002bdd64eb44`。端末固有の結果とレポートはローカルに保持し、このリポジトリには掲載しない。

同日、Windows実機でもCLIのOS/browser監査と、ユーザー本人だけが読めるACLでのレポート生成を確認した。ブラウザー画面では保護状態を確認し、有効な拡張機能について画面に表示された権限・サイトアクセスを確認して、本人から提供されたStore／開発元情報と照合した。AIサービスの画面では、承認済みサイト一覧と表示中の会話に対する適用範囲を確認した。端末固有の監査値、拡張名、サイト名、アカウント識別子、スクリーンショット、レポートは公開していない。

これらは個別端末と画面に表示された範囲での、その時点の動作・表示確認であり、セキュリティ認証、他の端末やセッションの保証、悪性コードが存在しないことの証明ではない。CLIのChrome manifest検査が示すのは宣言・保存メタデータで、実効権限や提供元を独立に確定するものではない。CIは合成fixtureと限定的なWindowsローカルprobe・レポートACLを確認するが、runnerの安全性を認定するものではなく、実機確認の代替でもない。権限やsandboxの状態により、一部の項目が確認できない場合がある。

## Scanner一覧

| カテゴリ | 現在の範囲 |
| --- | --- |
| `os` | macOS/Windowsの主要設定 |
| `browser` | Chrome 拡張メタデータと権限、Windows Chrome の Safe Browsing 管理ポリシー |
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

今後の拡張案と安全境界は[セキュリティ監査ロードマップ](docs/roadmap.ja.md)を参照。記載項目は将来案であり、現時点で実装・有効化されている機能ではない。

## コントリビューション

[CONTRIBUTING.md](CONTRIBUTING.md)を参照。実際の認証情報はテストやIssueに入れないでね。

## ライセンス

MIT。詳細は[LICENSE](LICENSE)。
