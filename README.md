# CypherArx Core

[日本語版はこちら / Japanese version](README.ja.md)

`cypherarx-core` is the C++ core of **CypherArx** — an open-source, fully-local,
native password manager for *complex* credential data (hierarchical entries,
free-form fields, multi-persona accounts) that mainstream managers can't model.

> **Status: pre-alpha, not for public use.** The repository is kept private during
> development; the open-source license will be chosen at the first public release.

## Scope

This is the **UI-free** core: cryptography, the KEK/DEK key hierarchy, encrypted
SQLite storage, entry/field logic, password generation, TOTP, and CSV import. It exposes
a **library API only** — there is **no CLI** (by design) and **no UI** (the Dear ImGui
GUI lives in a separate repository, `cypherarx-gui`).

Vault paths are `std::filesystem::path`; the core converts them to UTF-8 for SQLite
itself, so non-ASCII paths work on every platform.

Vault settings (`cypherarx/settings.hpp`, `Vault::settings` and `Vault::set_settings`) are
the values that belong to one vault and may be read only after it is unlocked: how long the
access log is kept, the session length, the idle lock and so on. The core stores them and
does not act on them; the application does. Each value is one row of the `settings` table,
encrypted with the DEK and bound to its key, so a value cannot be moved to another key. A
write stores every key, so the table does not show which ones were changed. A key that is
not stored reads as its default, a key this version does not know is left alone, and a value
that does not decrypt or parse is reported as `Corrupt` rather than replaced by a default.
What has to be known before a vault is open does not go here; that is the application's
own preferences file.

The access log (`cypherarx/access_log.hpp`, `Vault::record_access`, `access_records` and
`purge_access_records`) records that an entry was viewed or a value copied, for a "recently
used" list and a ranking by use. A record is the entry's uuid, the action and the time,
encrypted as one value, so the file shows only how many records there are. Each record is
bound to a random id of its own row, so one cannot be copied over another. The core never
reads a clock: every call takes the current time in Unix seconds. The setting
`log_retention_days` decides how long a record counts: older records are not returned and
`purge_access_records` deletes them, and with 0 nothing is recorded at all. Reading and
purging decrypt every record, as the retention keeps their number small. A record that does
not decrypt or parse is `Corrupt`, and purging stops without deleting anything.

Key rotation (`Vault::rotate_key`) replaces the DEK. It takes the master password, because
the new DEK has to be wrapped under the KEK and the KEK is not kept after unlocking. In one
database transaction it makes a new DEK, decrypts every encrypted value with the old one
and encrypts it with the new one (deleted rows too), and stores the new wrapped DEK with a
fresh salt; then the new DEK replaces the old one in memory. A failure at any point, a wrong
password or a value that does not decrypt leaves the vault exactly as it was. The old and
the new key never coexist in the file, so there is no table of keys and no per-row key id
to follow: this is simpler than the staged, resumable rotation of the design document
(§6.2, §6.3), whose guarantee the transaction already gives. The encrypted columns are
listed once, in `kEncryptedColumns` in `src/vault.cpp`; a new encrypted column must be
added there, and `tests/test_rotation.cpp` fails for any column ending in `_enc` that the
rotation left unchanged or that the test has no data for.

After the commit the file is rewritten (`secure_delete` and `VACUUM`) so the old ciphertext
and the old wrapped DEK are no longer in it; if that step fails the rotation has still
happened and the call returns `ScrubFailed`. What the core cannot reach is outside the
file: the rollback journal and the temporary file SQLite deletes, earlier copies and
backups, and blocks the file system or an SSD has not yet reused. Rotation protects against
a leaked DEK. It does not help against a leaked master password by itself, since the new
DEK is wrapped under the same password.

Changing the master password (`Vault::change_master_password`) is the same operation with
a new password and new KDF parameters: it verifies the old password, replaces the DEK,
re-encrypts every value and rewrites the file, in the same transaction and with the same
failure behaviour as a rotation. There is no way to change the password and keep the DEK.
If the DEK stayed, whoever has the old password and an old copy of the file could take the
DEK from that copy and read every later copy with it, which is the case a password is
usually changed for. This differs from the design document (§7.4), which re-wraps the same
DEK so that no value has to be re-encrypted. The old copy itself stays readable with the
old password; nothing can change that.

Import (`cypherarx/import.hpp`, `Vault::import_logins`) reads the CSV files that browsers
and password managers export. `parse_logins_csv` works in place on the caller's buffer and
returns views into it, so the caller can keep the file in guarded memory and wipe it once.
It does not know each product's format: it finds the columns by their header names, in any
order and case (`name`/`title`, `url`/`uri`/`login_uri`/`website`,
`username`/`login_username`/`login`, `email` when there is no user name,
`password`/`login_password`, `totp`/`login_totp`/`otpauth`/`otpsecret`/`otpurl`,
`note`/`notes`/`extra`/`comments`), and refuses a file with neither a password nor a TOTP
column. Quoted fields, doubled quotes, line breaks inside a field, CRLF and a byte-order
mark are handled. **It has been tested with headers shaped like those exports,
not with files exported by the products themselves.** KeePass XML
and 1Password 1PUX are not read.

`import_logins` stores the rows in one transaction, as services and accounts.

A service has a name, any number of URLs and a login URL, and these are three things. The
name is for display and may be empty. The URLs are fields of the type `url` on the service
(`kUrlFieldType`, read back with `Vault::urls`); a service with no URL is possible, for
something that has no site or an app whose site is unknown. The login URL is the service's
own `login_url`, because the place to log in belongs to the service, not to each account.

Rows are grouped by site: the host of the row's URL, compared without case, or the name
when there is no URL. A row goes to the service already in the vault that has that host in
any of its URL fields or in its `url`, or that has that name when it has no URL; otherwise a
service is made, with the scheme and the host of the row's URL as its URL field, the row's
URL as its login URL, and the row's name as its name unless the name is just the host.
Because the host is compared as written, `www.example.com` and `example.com` are still two
sites; telling which hosts are one registered domain needs the public suffix list.

Each row becomes one account under its service, named by the user name, with the note as
its notes and, when `ImportOptions::persona_id` is set, that persona (it must be a persona
entry, or nothing is imported). The account keeps a login URL of its own only when the
row's URL differs from its service's. Its fields are the user name itself (labelled as an
email address when it has the shape of one, as an ID otherwise; the shape is all that is
checked, and the value is kept either way), the password and the TOTP secret (taken out of
an `otpauth://` URL). The user name is a field as well as the account's name because an
account has any number of identifiers of equal standing (an email address, a phone number,
a handle), an export carries one of them, and a field is what can be copied and added to.

A row with nothing to store is skipped, and so is a row whose site and user name are
already there, so importing a file twice adds nothing; a changed password in the second
file is therefore not picked up. Entries already in the vault are never changed. The
summary counts what was added and what was skipped.

`Vault::merge_service(source, target)` makes two services one, in one transaction, for
services that turned out to be the same (one made by hand, one imported). The target keeps
its name and category. The source's accounts move under the target, its URL fields move to
the target unless the target already has that URL (compared without case), and the source
is deleted. The target takes the source's login URL when it has none. An account that had
no login URL of its own, and so used its service's, keeps the URL it used: when the
target's login URL is a different one, the source's is written to the account.

`Vault::set_accounts_persona(ids, persona)` gives several accounts one persona, or none, in
one transaction: every id must be an account and the persona a persona entry, or nothing
is changed.

## Tech

- **C++23**, libsodium (XChaCha20-Poly1305 / Argon2id), SQLite3
- CMake + vcpkg (manifest mode), Ninja
- GoogleTest, with AddressSanitizer / UBSan in CI
- Error model: `std::expected` / result types; exceptions only for truly exceptional cases

## Build

Requires a C++23 compiler, CMake ≥ 3.21, Ninja, and vcpkg (`VCPKG_ROOT` set).

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

On Windows, configure from a Visual Studio Developer shell (so MSVC `cl` is on PATH),
or open the folder in Qt Creator / Visual Studio (both read `CMakePresets.json`).

## Layout

```
include/cypherarx/   public headers
src/                 implementation
tests/               GoogleTest unit tests
```

## Design

The canonical design document is in the org repository:
`claude-handover/cypherarx-design-final.md`.
