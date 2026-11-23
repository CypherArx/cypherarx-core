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
