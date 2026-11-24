# データモデル

[English version](data-model.md)

金庫のファイルが何を持ち、行どうしがどう関係するかを述べます。実装されている金庫の形式 2
（`kVaultFormatVersion`）について書いています。値の暗号化の方法は [crypto.ja.md](crypto.ja.md) に
あります。

**プレアルファの間は、形式を予告なく変えることがあります。**

## 表

金庫は 1 つの SQLite ファイルで、次の表を持ちます。

| 表 | 持つもの |
|---|---|
| `crypto_meta` | 解錠に要るもの。ソルト、Argon2id のパラメータ、包んだ鍵 |
| `entries` | サービス、名義、アカウント、子を 1 つの表に |
| `fields` | エントリの自由な値。ユーザー名、パスワード、ワンタイムパスワードの秘密など、何でも |
| `login_methods` | アカウントへのログイン方法。「〜でログイン」の場合は、別のアカウントへのリンクを持つ |
| `categories` | カテゴリの木。7 つのプリセットと、利用者が作ったもの |
| `tags`、`entry_tags` | タグと、どのエントリにどのタグが付いているか |
| `settings` | この金庫に属する設定 |
| `access_logs` | エントリを見た、値をコピーした、という記録 |

名前が `_enc` で終わる列は暗号化されています。そのほかはすべて平文で保存されます。それで何が
分かるかは、[crypto.ja.md](crypto.ja.md#ファイルから分かること) に挙げてあります。

## エントリ：2 つの親

このプロジェクトの理由は、「サイト、ユーザー名、パスワード」の一覧では持てないデータです。
同じサービスの上の複数の名義、パスワードでない値、アカウントの下にぶら下がるもの。モデルは、
独立した 2 つの軸を持つ格子です。

エントリは、`entry_type` に種類を持ちます。

| 種類 | 何か | `parent_id` | `persona_id` |
|---|---|---|---|
| `service` | サイトや組織 | なし | なし |
| `persona` | 利用者が名乗る名義 | なし | なし |
| `account` | 1 つのログイン。名義を通して見たサービス | そのサービス | その名義、またはなし |
| `child` | アカウントに属するもの。カード、トークン、バックアップコード | そのアカウント | なし |

- サービスと名義は、互いに親子にはなりません。種類の違うものなので、列も 2 つです。
- **2 つの親を持つエントリは、アカウントだけです**。それぞれの種類から 1 つずつ。アカウントは
  1 つだけ存在し、両方の木に現れます。
- アカウントは名義を持たなくても構いません。名義を分けない人のためです。
- **値はアカウントと子に載せます**。ログインが 1 つだけの単純なサービスでも同じです。サービスは
  入れ物なので、「フィールドがサービスに属するときと、アカウントに属するとき」を分ける規則が
  要りません。

アプリケーションが見せる 2 つの表示は、同じ行の投影です。

```
サービス軸（parent_id による）       名義軸（persona_id による）

Example Bank                         Personal
└─ main login                        ├─ main login            (Example Bank)
   └─ debit card                     └─ @example_main         (Example Social)
Example Social                       Work
├─ @example_main                     └─ @example_work         (Example Social)
└─ @example_work
```

エントリの文字列は、`label_enc`（名前）、`url_enc`、`login_url_enc`（ログインページ。`url_enc` と
違うとき）、`display_name_enc`、`notes_enc` にあります。平文の列は、種類、2 つの親、`category_id`、
`is_favorite` です。

## フィールド

フィールドは、エントリの持つ、ラベルの付いた 1 つの値です。`label_enc`、`value_enc`、`notes_enc`
と、平文の `field_type` を持ちます。ラベルは自由な文字列なので、エントリは必要なものを、いくつでも
持てます。

種類は、`text`、`password`、`totp`、`url` のような平文の文字列です。コアはこれを制限しません。
平文にしてあるのは、アプリケーションが値を復号せずに、種類に応じて扱えるようにするためです。
たとえば、パスワードを隠す、ワンタイムパスワードを計算する、といったことです。

フィールドの値は、ほかとは別に（`Vault::field_value`）、保護メモリへ読み出します。エントリの
フィールドを一覧しても、値は復号されません。

## ログイン方法：親ではなくリンク

アカウントにどうログインするかは、上の格子とは別の層です。ログイン方法はエントリに属し
（`entry_id`）、平文の `method_type`（`email`、`google`、`github` など）、暗号化された `notes_enc`、
そして任意で `linked_entry_id` を持ちます。これは「〜でログイン」のときに**経由する**アカウントです。

このリンクは、2 つのアカウントの間の辺です。`parent_id` では表しません。別のサービスのアカウントを
経由してログインするアカウントは、そのアカウントに属しているわけではないからです。

## カテゴリとタグ

- `categories` は、暗号化された名前の木（`parent_id`）です。金庫を作るときに 7 つのプリセットを
  作ります（`is_preset = 1`）。列の形を 1 つにするため、プリセットも利用者のものと同じように
  暗号化します。プリセットは、名前の変更も削除もできません。エントリが持てるカテゴリは 1 つまで
  です（`entries.category_id`）。カテゴリを削除すると、その下のカテゴリとエントリは、カテゴリを
  持たない状態になります。
- `tags` は暗号化された名前で、`entry_tags` がエントリと多対多で結びます。暗号文どうしは比べられ
  ないので、名前の重複は、コアが復号して防ぎます。`Vault::add_tag` は、同じ名前がすでにあれば、
  そのタグを返します。

## 設定

設定 1 つにつき 1 行です。名前は `key` に平文で、値は `value_enc` にあります。書き込むたびに
すべてのキーを保存するので、どれを変えたかは表から分かりません。

| キー | 既定値 | 最小の値 |
|---|---|---|
| `log_retention_days` | 7 | 0（何も記録しない） |
| `session_duration_minutes` | 30 | 1 |
| `session_lock_idle_minutes` | 10 | 0 |
| `session_use_os_keyring` | オン | |
| `session_lock_on_screensaver` | オン | |
| `session_require_password_for_export` | オン | |

コアは値を保存するだけで、アクセス記録の保持を除いて、それに従って動くことはありません。動くのは
アプリケーションです。すべての設定が、アプリケーションですでに効いているわけではありません。
保存されていないキーは既定値として読み、コアの知らないキーには触れません。

## アクセス記録

出来事 1 つにつき 1 行です。`value_enc` は、3 行の文字列を 1 つの値として暗号化したものです。
エントリの `uuid`、操作（`view` または `copy`）、Unix 秒の時刻です。そのため、ファイルから分かる
のは出来事の数だけです。`log_retention_days` より古い記録は返さず、`Vault::purge_access_records`
が削除します。

## どの行も持つ列

将来、端末間の同期が対象にする表は、次の列を持ちます。

| 列 | 意味 |
|---|---|
| `uuid` | 挿入のときに作る乱数のバージョン 4 の UUID。変わらない。暗号文を結び付ける相手でもある |
| `revision` | 1 から始まり、変更で増える |
| `updated_at` | 最後の変更の時刻。ISO 8601、UTC、秒まで |
| `deleted_at` | 行に削除の印を付けた時刻。生きている行では空 |
| `device_id` | 予約。書き込まない |

**削除は、行に印を付けて残します。** コアが印を付けるのは、削除を求められた行だけです。削除された
エントリの下にある行には、印を付けません。同期の機能はまだありません。これらの列は、同期を足す
ときに新しい形式を要しないように置いてあります。

## 予約の列

次の列は表にありますが、この版は書き込みも読み出しもしません。
`entries.icon_type`、`entries.icon_data`、`entries.sort_order`、
`entries.browser_extension_allowed`、`fields.linked_entry_id`、`categories.sort_order`、
`login_methods.sort_order`（並べ替えに読むが、書き込まない）、そしてすべての `device_id`。

## コアが守る規則

コアは、渡されたものを保存します。確かめるのは、次のことです。

- プリセットのカテゴリは、名前の変更も、移動も、削除もできない。カテゴリは、自分自身の親に
  なれない。
- タグの名前は重複しない。
- `Vault::merge_service` は、異なる 2 つのサービスを取る。`Vault::set_accounts_persona` は、
  アカウントと名義を取る。
- 最小の値を下回る設定は断る。

次のことは確かめ**ません**。エントリの親が上の表の種類であること、ログイン方法がアカウントに
属すること、リンクが別のサービスのアカウントを指すこと。これらの規則は、コアの上に作る
アプリケーションが守ります。スキーマに外部キーの制約はありません。

## スキーマ

```sql
CREATE TABLE crypto_meta (
  key   TEXT PRIMARY KEY,
  value BLOB NOT NULL
);
CREATE TABLE entries (
  id INTEGER PRIMARY KEY,
  parent_id INTEGER,
  persona_id INTEGER,
  entry_type TEXT,
  label_enc BLOB NOT NULL,
  url_enc BLOB,
  login_url_enc BLOB,
  display_name_enc BLOB,
  notes_enc BLOB,
  category_id INTEGER,
  is_favorite INTEGER DEFAULT 0,
  icon_type TEXT,
  icon_data TEXT,
  sort_order INTEGER,
  browser_extension_allowed INTEGER DEFAULT 1,
  created_at TEXT,
  updated_at TEXT,
  uuid TEXT NOT NULL UNIQUE,
  revision INTEGER DEFAULT 1,
  deleted_at TEXT,
  device_id TEXT
);
CREATE TABLE fields (
  id INTEGER PRIMARY KEY,
  entry_id INTEGER,
  label_enc BLOB NOT NULL,
  value_enc BLOB NOT NULL,
  notes_enc BLOB,
  field_type TEXT NOT NULL,
  linked_entry_id INTEGER,
  uuid TEXT NOT NULL UNIQUE,
  revision INTEGER DEFAULT 1,
  updated_at TEXT NOT NULL,
  deleted_at TEXT,
  device_id TEXT
);
CREATE TABLE login_methods (
  id INTEGER PRIMARY KEY,
  entry_id INTEGER,
  method_type TEXT NOT NULL,
  linked_entry_id INTEGER,
  notes_enc BLOB,
  sort_order INTEGER,
  uuid TEXT NOT NULL UNIQUE,
  revision INTEGER DEFAULT 1,
  updated_at TEXT NOT NULL,
  deleted_at TEXT,
  device_id TEXT
);
CREATE TABLE categories (
  id INTEGER PRIMARY KEY,
  parent_id INTEGER,
  name_enc BLOB NOT NULL,
  is_preset INTEGER DEFAULT 0,
  sort_order INTEGER,
  uuid TEXT NOT NULL UNIQUE,
  revision INTEGER DEFAULT 1,
  updated_at TEXT NOT NULL,
  deleted_at TEXT,
  device_id TEXT
);
CREATE TABLE tags (
  id INTEGER PRIMARY KEY,
  name_enc BLOB NOT NULL,
  uuid TEXT NOT NULL UNIQUE,
  revision INTEGER DEFAULT 1,
  updated_at TEXT NOT NULL,
  deleted_at TEXT,
  device_id TEXT
);
CREATE TABLE entry_tags (
  entry_id INTEGER NOT NULL,
  tag_id INTEGER NOT NULL,
  PRIMARY KEY (entry_id, tag_id)
);
CREATE TABLE access_logs (
  id INTEGER PRIMARY KEY,
  value_enc BLOB NOT NULL,
  uuid TEXT NOT NULL UNIQUE
);
CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value_enc BLOB NOT NULL
);
```

形式 1 から上げた金庫も、同じ列を持ちます。表の中での列の順序は、違うことがあります。
