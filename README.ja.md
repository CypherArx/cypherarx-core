# CypherArx Core

[English version / 英語版はこちら](README.md)

`cypherarx-core` は **CypherArx** の C++ コアです。CypherArx は、主流のパスワードマネージャーでは
表現できない *複雑な* 認証情報（階層構造のエントリ、自由フィールド、複数名義のアカウント）を扱う、
オープンソース・完全ローカル・ネイティブのパスワードマネージャーです。

> **状態: プレアルファ、一般利用不可。** 開発中はリポジトリを非公開にしています。
> オープンソースライセンスは最初の公開時に決めます。

## 範囲

これは **UI を持たない** コアです: 暗号、KEK/DEK の鍵階層、暗号化 SQLite ストレージ、
エントリ／フィールドのロジック、パスワード生成、TOTP、インポート。**ライブラリ API のみ**を
公開し、**CLI はありません**（設計上の判断）。**UI もありません**（Dear ImGui の GUI は別リポジトリ
`cypherarx-gui` にあります）。

金庫のパスは `std::filesystem::path` で受け取り、SQLite 向けの UTF-8 変換はコア側で行うため、
非 ASCII のパスもどのプラットフォームでも動作します。

金庫の設定（`cypherarx/settings.hpp`、`Vault::settings` と `Vault::set_settings`）は、1 つの
金庫に属し、解錠した後にだけ読めればよい値です。アクセス記録の保持日数、セッションの長さ、
無操作でのロックなどが入ります。コアは値を保存するだけで、それに従って動くのは
アプリケーション側です。値は `settings` テーブルの 1 行ずつで、DEK で暗号化し、キーに
結び付けてあるので、ある値を別のキーへ移すことはできません。書き込みは全キーを保存する
ので、どれを変えたかはテーブルから分かりません。保存されていないキーは既定の値として
読み、この版が知らないキーには触れず、復号や解釈ができない値は既定の値で置き換えずに
`Corrupt` として報告します。金庫を開く前に分かっている必要があるものは、ここには
置きません。それはアプリケーション自身の設定ファイルの役目です。

## 技術

- **C++23**、libsodium（XChaCha20-Poly1305 / Argon2id）、SQLite3
- CMake ＋ vcpkg（マニフェストモード）、Ninja
- GoogleTest、CI で AddressSanitizer / UBSan
- エラーモデル: `std::expected` / 結果型。例外は本当に例外的な場合のみ

## ビルド

C++23 コンパイラ、CMake 3.21 以上、Ninja、vcpkg（`VCPKG_ROOT` 設定済み）が必要です。

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

Windows では Visual Studio の開発者シェルから構成する（MSVC の `cl` が `PATH` にある状態）か、
フォルダを Qt Creator / Visual Studio で開いてください（どちらも `CMakePresets.json` を読みます）。

## 構成

```
include/cypherarx/   公開ヘッダ
src/                 実装
tests/               GoogleTest 単体テスト
```

## 設計

設計の正典は組織リポジトリの `claude-handover/cypherarx-design-final.md` にあります。
