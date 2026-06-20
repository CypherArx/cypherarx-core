# CypherArx Core

`cypherarx-core` is the C++ core of **CypherArx** — an open-source, fully-local,
native password manager for *complex* credential data (hierarchical entries,
free-form fields, multi-persona accounts) that mainstream managers can't model.

> **Status: pre-alpha, not for public use.** The repository is kept private during
> development; the open-source license will be chosen at the first public release.

## Scope

This is the **Qt-free** core: cryptography, the KEK/DEK key hierarchy, encrypted
SQLite storage, entry/field logic, password generation, TOTP, and import. It exposes
a **library API only** — there is **no CLI** (by design) and **no UI** (the Qt GUI
lives in a separate repository, `cypherarx-gui`).

## Tech

- **C++23**, libsodium (AES-256-GCM / Argon2id), SQLite3
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
