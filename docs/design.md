# Design

[日本語版はこちら / Japanese version](design.ja.md)

What CypherArx is for, how it is put together, and the principles its decisions are
measured against. It describes what exists today.

| Document | Covers |
|---|---|
| this one | purpose, structure, principles |
| [crypto.md](crypto.md) | keys, encryption, what the file shows, what is not protected |
| [data-model.md](data-model.md) | tables, the two-parent model of entries, the schema |
| [../README.md](../README.md) | the library's API, feature by feature, and how to build it |

**CypherArx is pre-alpha and has not been reviewed by anyone else. Do not keep real
passwords in it yet.**

## Purpose

CypherArx is a password manager for data that the usual "site, user name, password" list
cannot hold. It keeps everything in one local file and never sends it anywhere.

Three things, together, are the reason it exists; the rest follows from them.

- **Hierarchy.** A service has accounts; an account has things below it, such as cards,
  tokens and backup codes.
- **Free-form fields.** An entry holds any number of labelled values: several passwords,
  a PIN, a registered phone number, a one-time-password secret, recovery codes.
- **Several identities across services.** A person may act under more than one identity
  and have accounts for each on the same service. Accounts can be seen by service or by
  identity; it is the same account in both views, not a copy.

How one logs in is recorded too: with a password, or through another account ("log in
with …").

## Structure

```
cypherarx-core    library: cryptography, storage, the model, generation, one-time passwords, import
      ▲
cypherarx-gui     application: screens, session and locking, clipboard, OS integration
```

- **The logic is in the core and nowhere else.** The core is a C++23 library with no user
  interface and no knowledge of one. An application on top of it calls its API and adds
  nothing the core should own.
- **There is no command-line tool, on purpose.** A command that prints stored passwords is
  as convenient for other software on the machine as it is for the owner.
- **The core does not open network connections.** Nothing in it can send the vault
  anywhere.
- The core depends on libsodium (all cryptography), SQLite (the file), zxcvbn-c (password
  strength estimates) and miniz (unpacking one import format).

Inside the core:

| Part | Role |
|---|---|
| `Secret`, `crypto`, `kdf`, `vault_key` | guarded memory, encryption, key derivation, the two-level key hierarchy |
| `Vault` | the file: creating, opening, format versions, entries, fields, login methods, categories, tags, settings, the access log, key rotation |
| `passgen`, `totp`, `strength` | password generation, one-time passwords, judging a master password |
| `import`, `erase` | reading exports of other products, overwriting and deleting a file |

Failures the caller must handle are returned as values (`std::expected`), not thrown: a
wrong password or a value that does not decrypt is an outcome, not an exception.

The application, `cypherarx-gui`, is split the same way. Its `model` holds everything that
is not drawing (what is selected, what the two views contain, when to lock, when the
clipboard is cleared) and is tested without a window; its views draw the model; a small
`platform` part holds what differs per operating system. It currently runs on Windows.

## Principles

When a decision is unclear, these decide it.

1. **The implementation must not take the easy way at the cost of safety.**
2. **Use the network as little as possible, and only when the user means it.** Today that
   is never.
3. **Do not take a responsibility that cannot be kept; state the facts.** The software
   says what it checked. It does not declare something safe.
4. **Look for measures that limit what an attacker can do.** "More of it is safer" is a
   trap; a concrete limit is better.
5. **Do not hold what need not be held, and erase for certain what must be erased.**
6. **What is shown must mean exactly what it says.**
7. **Leave to the operating system and to established libraries what they do better.**
   Memory locking and all cryptography come from libsodium, not from here.
8. **Ask whether a new feature weakens something else.** There is no password hint and no
   rule about character classes, because each makes passwords easier to guess.
9. **A convenient feature is convenient for an attacker too.** This is why there is no
   command-line tool.
10. **Do not build a feature its author would not use.**

Nothing is protected by being hidden. The file layout and the code are public; the
protection is the key.

## What is not there

So that nothing is assumed: there is no synchronisation between devices, no export, no
browser integration, no mobile application, no recovery of a forgotten master password,
and no audit by a third party.
