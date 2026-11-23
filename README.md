# CypherArx Core

[日本語版はこちら / Japanese version](README.ja.md)

`cypherarx-core` is the C++ core of **CypherArx** — an open-source, fully-local,
native password manager for *complex* credential data (hierarchical entries,
free-form fields, multi-persona accounts) that mainstream managers can't model.

> **Status: pre-alpha, not for public use.** The repository is kept private during
> development; the open-source license will be chosen at the first public release.

## Scope

This is the **UI-free** core: cryptography, the KEK/DEK key hierarchy, encrypted
SQLite storage, entry/field logic, password generation, TOTP, and import. It exposes
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
DEK is wrapped under the same password, and changing the master password does not rotate
the DEK: whoever has the old password and an old copy of the file can still read a newer
copy unless the key is rotated as well.

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
