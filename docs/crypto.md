# Cryptographic design

[日本語版はこちら / Japanese version](crypto.ja.md)

How `cypherarx-core` protects a vault: the keys, what is encrypted and how, what stays
readable, how keys are replaced, and what the design does not protect against. It
describes vault format 2 (`kVaultFormatVersion`), as implemented.

**This design and its implementation have not been reviewed by anyone else. The format may
change without notice while the project is pre-alpha.**

## What is protected, and against what

A vault is one SQLite file. The design assumes that the file may fall into other hands: a
stolen or discarded disk, a backup, a cloud folder, a copy taken while the owner is away.

Whoever has the file and not the master password should learn:

- none of the stored text: names, URLs, user names, passwords, one-time-password secrets,
  notes, field labels, category and tag names, settings, and which entry was used when;
- only what is listed under [What the file shows](#what-the-file-shows).

Whoever changes the file should not be able to make the application show a stored value in
another place: a ciphertext moved to another row or column fails to decrypt.

The design does **not** protect against:

- **Software running as the same user while the vault is unlocked.** It can read the
  process's memory, the screen and the keyboard. Guarded memory makes this harder, not
  impossible.
- **A weak master password.** Whoever has the file can try passwords for as long as they
  like; Argon2id only makes each try expensive.
- **A leaked master password together with an old copy of the file.** That copy stays
  readable with that password for ever. Changing the password protects later copies only.
- **Rolling the whole file back to an earlier state.** Each value is authenticated on its
  own; nothing authenticates the file as a whole, so an old copy of the file, or an old
  row put back with its old ciphertext, is accepted.
- **Deleting rows, or changing the columns that are not encrypted** (see below).
- **What is left outside the file**: SQLite's journal and temporary files after they are
  deleted, blocks the file system or an SSD has not reused, swap and hibernation files of
  other programs that held a value (the clipboard, for one).

Nothing is hidden by obscurity. The table layout is public; the protection is the key.

## Primitives

All cryptography comes from [libsodium](https://libsodium.org); none is implemented here.

| Purpose | Primitive | Parameters |
|---|---|---|
| Key derivation | Argon2id (`crypto_pwhash`, `ALG_ARGON2ID13`) | 16-byte salt, 32-byte output; time and memory cost are stored per vault |
| Encryption | XChaCha20-Poly1305, IETF (`crypto_aead_xchacha20poly1305_ietf`) | 32-byte key, 24-byte nonce, 16-byte tag |
| Random numbers | `randombytes_buf` | keys, salts, nonces, row identifiers |

XChaCha20-Poly1305 was chosen over AES-256-GCM because libsodium's AES-256-GCM needs
hardware AES and is not available on every processor the core is meant to run on, and
because a 24-byte nonce can be chosen at random for every value without a realistic chance
of repeating.

## Keys

```
master password
   │  Argon2id (salt and parameters stored in the vault)
   ▼
KEK  key-encryption key, 32 bytes, never stored
   │  XChaCha20-Poly1305
   ▼
DEK  data-encryption key, 32 random bytes, stored only wrapped under the KEK
   │  XChaCha20-Poly1305, one encryption per value
   ▼
stored values
```

- The **KEK** is derived from the master password when a vault is created or opened, used
  once to wrap or unwrap the DEK, and discarded. It is not kept while the vault is open.
- The **DEK** is generated at random. It lives in guarded memory while the vault is
  unlocked and is wiped when the vault object is destroyed.
- A vault has exactly one DEK. There is no table of keys.

A wrong master password is detected by the DEK failing to unwrap (the authentication tag
does not verify). No hash of the password is stored.

The table `crypto_meta` holds what is needed to unlock, in the clear:

| Key | Value |
|---|---|
| `kdf_salt` | the 16-byte Argon2id salt |
| `kdf_params` | text, `argon2id,ops=<passes>,mem=<bytes>` |
| `wrapped_dek` | the DEK encrypted under the KEK, in the blob layout below |

## Encrypted values

Every encrypted value is stored as one blob:

```
version (1 byte, = 1) ‖ nonce (24 bytes) ‖ ciphertext ‖ tag (16 bytes)
```

- The nonce is random and new for every encryption, including every re-encryption of the
  same value.
- A blob whose first byte is not a known version is rejected, so another cipher can be
  introduced later without ambiguity.
- Each value is encrypted separately. Nothing is encrypted per row or per file.

### Associated data

Each encryption authenticates a short text that names where the value belongs. Decrypting
with different associated data fails, so a ciphertext copied to another row or another
column is detected.

For a stored value the associated data is `<scope>|<kind>`:

| Table | Column | Scope | Kind |
|---|---|---|---|
| `entries` | `label_enc`, `url_enc`, `login_url_enc`, `display_name_enc`, `notes_enc` | the row's `uuid` | `label`, `url`, `login_url`, `display_name`, `notes` |
| `fields` | `label_enc`, `value_enc`, `notes_enc` | the row's `uuid` | `label`, `value`, `notes` |
| `login_methods` | `notes_enc` | the row's `uuid` | `notes` |
| `categories`, `tags` | `name_enc` | the row's `uuid` | `name` |
| `access_logs` | `value_enc` | the row's `uuid` | `access` |
| `settings` | `value_enc` | the text `settings` | the row's `key` |

A `uuid` is a random version-4 UUID made when the row is inserted and never changed.

The wrapped DEK uses the fixed associated data `cypherarx/dek-wrap/v1`, so it cannot be
confused with a stored value.

The associated data does not include a counter or a time, which is why putting an old
ciphertext back into its own row is not detected.

## What the file shows

These are stored in the clear and can be read, and changed, by whoever has the file:

- the Argon2id salt and parameters, and the vault format version;
- how many entries, fields, login methods, categories, tags and access records there are,
  and the approximate length of each encrypted value;
- the structure: which entry is under which, which entry belongs to which persona and
  category, which tags an entry has, which field belongs to which entry, and which entry a
  login method points at;
- an entry's type (`service`, `persona`, `account`, `child`), a field's type (`text`,
  `password`, `totp`, …), a login method's type, the favourite flag, the preset flag of a
  category, and sort orders;
- when each row was created, last changed and deleted, and how many times it was changed;
- the names of the settings (not their values).

The types are in the clear because the application has to act on them without decrypting
everything, for example to compute a one-time password. Everything a person typed as text
is encrypted, the labels of fields included: a label such as "bank PIN" would tell an
attacker which values are worth the effort.

## Deleted and replaced values

- **Deleting an entry, a field, a login method, a category or a tag marks the row as
  deleted and keeps it**,
  ciphertext included, for a future synchronisation between devices. The value stays in
  the file, encrypted under the DEK.
- When a value is changed, the row gets a new ciphertext. The pages that held the old one
  are not overwritten at that moment and may remain in the file until it is rewritten.
- Access records older than the retention are deleted for real, without overwriting.
- A key rotation rewrites the whole file (below), which removes such leftovers from it.

## Replacing keys

`Vault::rotate_key` replaces the DEK. `Vault::change_master_password` does the same with a
new password and new Argon2id parameters. Both take the current master password, because
the KEK is not kept, and both do the following:

1. Check the password by unwrapping the current DEK.
2. Make a new salt, a new DEK and a new KEK, and wrap the new DEK.
3. In one database transaction, decrypt every encrypted value with the old DEK and encrypt
   it with the new one (rows marked as deleted too), and store the new salt, parameters
   and wrapped DEK.
4. Replace the DEK in memory.
5. Rewrite the file (`secure_delete` and `VACUUM`) so that the old ciphertexts and the old
   wrapped DEK are no longer in it.

A failure before the commit leaves the vault exactly as it was. If only step 5 fails, the
keys have been replaced and the call reports `ScrubFailed`. The old and the new DEK never
exist in the file at the same time.

The columns in step 3 are listed once, in `kEncryptedColumns` in `src/vault.cpp`. A test
fails for any column whose name ends in `_enc` that a rotation left unchanged.

**The master password cannot be changed while keeping the DEK.** If the DEK stayed,
someone with the old password and an old copy of the file could take the DEK from that
copy and read every later copy with it.

A rotation protects against a leaked DEK. It does nothing against a leaked master
password, since the new DEK is wrapped under the same password.

## Master password

`master_password_strength` judges a candidate; it does not enforce anything, the
application does.

- Fewer than 12 characters: `TooShort`, whatever the estimate.
- The estimate of the number of guesses comes from zxcvbn-c and gives a score from 0 to 4
  (limits at 10³, 10⁶, 10⁸ and 10¹⁰ guesses). Scores 0 and 1 are `Rejected`, 2 is `Warn`,
  3 is `Advise`, 4 is `Ok`.
- No character classes are required. Such rules push people towards predictable patterns.
- The estimator knows English words, names, common passwords, keyboard runs, repeats,
  sequences and dates. It knows nothing about other languages or about the user.

There is no password hint and no recovery. A forgotten master password means the vault
cannot be opened.

## Argon2id parameters

The cost is chosen per machine rather than fixed. `benchmark_kdf` returns three choices
(light, standard, strong) with the time each took on this machine:

- the strong one aims at a budget of 2 seconds, the others at a half and a quarter of it;
- the time cost stays at 3 passes; the memory varies between 64 MiB and 1 GiB;
- a size the machine cannot allocate is halved until it can.

The chosen parameters are stored in the vault, so it opens on any machine; the same
parameters may take longer there. They are in the clear, so whoever has the file knows how
expensive each guess is.

## Memory

- `Secret` holds key material and decrypted secret values in memory from libsodium's
  `sodium_malloc`: locked against swapping, with guard pages before and after, and zeroed
  when freed. It cannot be copied, only moved, and prints as `[REDACTED]`.
- The KEK, the DEK and the value of a field are `Secret`s. A field's value is decrypted
  only when asked for.
- **Other decrypted text is ordinary memory**: names, URLs, notes, field labels, category
  and tag names are returned as `std::string` and are not locked or wiped.
- The password estimator allocates ordinary memory while it works on a password.
- Imported files are parsed in place in the caller's buffer, so the caller can keep an
  export in a `Secret` and wipe it once.

## Vault format version

The file carries a format version in SQLite's `user_version`. A vault with a higher
version than the core knows is refused and left unchanged. A vault with a lower one is
brought up to date after the password has been checked, in one transaction.

| Version | Change |
|---|---|
| 1 | first format |
| 2 | the unused `dek_id` column removed from every table with encrypted values |

The version of the file format is separate from the version byte at the start of each
encrypted blob.
