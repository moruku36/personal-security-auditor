# 手動確認と前回比較

## Password Checkup

`security-audit password-checkup`で確認方法を表示します。
Chromeの「パスワードと自動入力 → Google パスワード マネージャー → チェックアップ」で、
漏えい・脆弱さ・使い回しを確認してください。
[Googleの手順](https://support.google.com/chrome/answer/95606?hl=ja)も参照できます。
チェックはGoogle側で行います。CLIは認証DBを読まず、パスワードをエクスポートせず、通信もしません。
passwords.google.comで確認できるのはGoogleアカウントに保存した範囲です。
端末だけに保存したものは該当するChromeプロファイルで確認してください。

```sh
security-audit password-checkup --result clear
security-audit password-checkup --result issues --date 2026-10-08
security-audit password-checkup --result unchecked
security-audit password-checkup --forget
```

`clear`は確認した範囲で「問題なし」、`issues`は「問題あり」、
`unchecked`は「未確認」です。確認日は指定を省略すると端末の今日の日付になります。
日付はYYYY-MM-DDで、有効な過去または当日の日付を指定します。未確認には確認日を付けません。

保存先は`~/.security-audit/password-checkup.json`で、内容は`result`と`checked_on`だけです。
パスワード、サイト名、アカウント名、プロファイル名、画像、問題件数は入力・保存しません。
結果を記録すると前の記録を上書きし、履歴は保存しません。`--forget`で削除できます。
案内の表示や通常スキャンだけではファイルを作りません。
macOS／WindowsでChromeのデータディレクトリを検出したらレポートにも案内を出します。

結果は利用者の自己申告で、確認した日付と範囲に限られます。
以前の「問題なし」は現在の保護を保証しません。複数プロファイル・アカウントの識別子は保存しないため、
対象範囲を変えたら確認し直してください。

## 実効拡張権限の手動確認

```sh
security-audit browser-review Chrome
security-audit browser-review Chrome --result clear --date 2026-10-08
security-audit browser-review Brave --result issues
security-audit browser-review Chrome --forget
```

ブラウザー名はChrome／Brave／Edge／Firefox／Safariです。
有効な拡張機能、画面に表示された権限・サイトアクセス・提供元を利用者が確認します。
結果と確認日だけを`~/.security-audit/extensions-<browser>.json`に保存します。
拡張名・ID・サイト名・アカウント名は受け付けません。
保持・削除はPassword Checkupと同じです。自動検出と独立して手動確認の案内も使えます。

レポートではmanifestの「宣言」と手動確認の`user_reported_ui`を別Findingにします。
手動で問題なしを記録してもmanifestの宣言を自動的に検証済みにはしません。
Chromeの宣言には任意権限や保存された版も含まれ、有効な版・実効権限・提供元は確定できません。
Brave／Edgeは拡張ディレクトリ数、Firefox／Safariは存在確認までです。
`security-audit coverage`で実装・fixture・実機確認を別々に表示します。

## レポートの状態と互換性

JSONは`schema_version: 2`です。従来の`overall_risk`、`findings`、
Findingの既存フィールドに加えて、`id`、`category`、`status`、
`evidence_source`、`limitations`、`checked_on`を持ちます。

| 状態 | 意味 |
| --- | --- |
| observed | メタデータ・設定の事実を観測。安全判定ではない |
| needs_review | 解釈や利用者の判断が必要 |
| pass | 個別検査の成功、または利用者による問題なしの申告。証拠の種類も確認する |
| issue | 設定・権限の問題、または利用者による問題ありの申告 |
| unknown | 未確認・情報不足・ポリシー競合 |
| unavailable | アクセス不能・不正形式・上限到達・未対応 |

未確認や記録なしはunknownで、壊れた記録・読めない記録はunavailableです。
どちらもpassとして数えません。生データや例外本文をレポートには表示しません。
重大度は確認の優先度であり、検査の完全性とは別です。

OS検査は成功状態も返すようになりました。
各検査は成功／問題／確認不能でも同じルールコードとIDを維持します。
従来「問題だけ返る」と仮定していた利用側は状態で絞り込んでください。
旧JSONは読めますが比較用snapshotには使えません。新しい基準を作成してください。
自動移行は行いません。

## ローカルでの前回比較

```sh
security-audit scan browser --snapshot reports/browser-baseline.json
security-audit report browser --format json --compare reports/browser-baseline.json
security-audit scan browser --compare reports/browser-baseline.json --snapshot reports/browser-baseline.json
```

比較結果はstderrに出し、JSON／Markdownのstdoutを保ちます。
最後のコマンドは比較に成功した後、利用者の明示指定で基準を上書きします。
通常スキャンではsnapshotを残しません。`--output`と`--snapshot`には別ファイルを指定します。

snapshotのschemaは1で、schema／ID仕様の版、検査範囲のハッシュ、FindingのIDと状態だけを保存します。
本文・パス・推奨対応・拡張メタデータ・重大度・件数・確認日・生の出力は保存しません。
IDはカテゴリ・ルール・locationのSHA-256、範囲はOS・ホーム／リポジトリのパス・
カテゴリ・full指定のハッシュです。比較用の識別子であり匿名化の保証ではありません。
ローカルで非公開に保管してください。同じIDが複数ある場合は集約し、
unavailable／unknownをissue／needs_review／observed／passより優先します。

同じ端末パス・リポジトリ・OS・カテゴリ・full指定だけを比較します。
schemaやID仕様の不一致、異なる範囲、不正データは汎用エラーで中断します。
入力上限は1 MB／5,000件です。消えたIDは**今回観測されない**と表示し、解決済みと断定しません。
アクセス不能や検査上限で指摘が見えなくなる場合があります。
件数・重大度・日付だけの変化は比較しません。変化なしの場合もこの限界を表示します。

記録とsnapshotは既存の安全なatomic保存を使い、POSIXでは0600、
Windowsでは書き込み前に本人専用ACLを適用します。
状態／snapshotのパスはsymlink・Windows reparse pointを拒否します。
保護設定や比較に失敗すると保存を中断し、既存の基準を保ちます。
Git外か、除外された`reports/`に置いてください。
snapshotは明示的な上書き・利用者による削除まで保持し、定期実行・アップロードは追加していません。
