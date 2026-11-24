# Data model

[日本語版はこちら / Japanese version](data-model.ja.md)

What a vault file holds and how the rows relate, for vault format 2
(`kVaultFormatVersion`), as implemented. How the values are encrypted is in
[crypto.md](crypto.md).

**The format may change without notice while the project is pre-alpha.**

## Tables

A vault is one SQLite file with these tables:

| Table | Holds |
|---|---|
| `crypto_meta` | what is needed to unlock: salt, Argon2id parameters, the wrapped key |
| `entries` | services, personas, accounts and children, in one table |
| `fields` | the free-form values of an entry: user names, passwords, one-time-password secrets, anything |
| `login_methods` | the ways to log in to an account, with a link to another account when it is "log in with …" |
| `categories` | a tree of categories; seven presets and the user's own |
| `tags`, `entry_tags` | tags and which entry has which |
| `settings` | the settings that belong to this vault |
| `access_logs` | that an entry was viewed or a value copied |

Columns whose names end in `_enc` are encrypted. Everything else is stored in the clear;
[crypto.md](crypto.md#what-the-file-shows) lists what that reveals.

## Entries: two parents

The reason for this project is data that a list of "site, user name, password" cannot
hold: several identities on the same service, values that are not passwords, things that
hang below an account. The model is a grid with two independent axes.

An entry has a type, in `entry_type`:

| Type | What it is | `parent_id` | `persona_id` |
|---|---|---|---|
| `service` | a site or an organisation | none | none |
| `persona` | an identity the user acts under | none | none |
| `account` | one login: a service seen through a persona | its service | its persona, or none |
| `child` | something that belongs to an account: a card, a token, backup codes | its account | none |

- A service and a persona are never parent and child of each other. They are two kinds of
  thing, so they are two columns.
- An **account is the only entry with two parents**: one of each kind. It exists once and
  appears in both trees.
- An account may have no persona, for someone who does not separate identities.
- **Values live on accounts and children**, even for a simple service with one login. The
  service is a container, so no rule has to say when a field belongs to the service and
  when to an account.

The two views an application shows are projections of the same rows:

```
service axis (by parent_id)          persona axis (by persona_id)

Example Bank                         Personal
└─ main login                        ├─ main login            (Example Bank)
   └─ debit card                     └─ @example_main         (Example Social)
Example Social                       Work
├─ @example_main                     └─ @example_work         (Example Social)
└─ @example_work
```

An entry's text is in `label_enc` (its name), `url_enc`, `login_url_enc` (the login page,
when it differs from `url_enc`), `display_name_enc` and `notes_enc`. Its plain columns are
the type, the two parents, `category_id` and `is_favorite`.

## Fields

A field is one labelled value of an entry: `label_enc`, `value_enc`, `notes_enc` and a
plain `field_type`. The label is free text, so an entry can hold whatever it needs, in
any number.

The type is a plain text such as `text`, `password`, `totp` or `url`. The core does not
restrict it. It is in the clear so that an application can treat a value by its kind
without decrypting it, for example to hide a password or compute a one-time password.

A field's value is read separately from the rest (`Vault::field_value`), into guarded
memory; listing an entry's fields does not decrypt the values.

## Login methods: links, not parents

How one logs in to an account is a separate layer from the grid above. A login method
belongs to an entry (`entry_id`) and has a plain `method_type` (`email`, `google`,
`github`, …), encrypted `notes_enc`, and optionally `linked_entry_id`: the account one
logs in **through**, for "log in with …".

That link is an edge between two accounts. It is not expressed with `parent_id`: an
account that logs in through another service's account does not belong to it.

## Categories and tags

- `categories` is a tree (`parent_id`) of encrypted names. Seven presets are made when a
  vault is created (`is_preset = 1`); they are encrypted like the user's own so that the
  column has one shape, and they cannot be renamed or deleted. An entry has at most one
  category (`entries.category_id`). Deleting a category leaves its sub-categories and its
  entries without one.
- `tags` are encrypted names; `entry_tags` joins them to entries, many to many. Because a
  ciphertext cannot be compared, the core keeps names unique by decrypting:
  `Vault::add_tag` returns the existing tag when the name is already there.

## Settings

One row per setting: the name in `key`, in the clear, and the value in `value_enc`. Every
write stores every key, so the table does not show which ones were changed.

| Key | Default | Lowest value |
|---|---|---|
| `log_retention_days` | 7 | 0 (nothing is recorded) |
| `session_duration_minutes` | 30 | 1 |
| `session_lock_idle_minutes` | 10 | 0 |
| `session_use_os_keyring` | on | |
| `session_lock_on_screensaver` | on | |
| `session_require_password_for_export` | on | |

The core stores these and does not act on them, apart from the retention of the access
log; the application does. Not every one has an effect in the application yet. A key that
is not stored reads as its default, and a key the core does not know is left alone.

## Access log

One row per event. `value_enc` is one encrypted text of three lines: the entry's `uuid`,
the action (`view` or `copy`) and the time in Unix seconds. The file therefore shows only
how many events there are. Records older than `log_retention_days` are not returned, and
`Vault::purge_access_records` deletes them.

## Columns every row has

The tables an eventual synchronisation between devices would cover carry these:

| Column | Meaning |
|---|---|
| `uuid` | a random version-4 UUID made on insert, never changed; also what each ciphertext is bound to |
| `revision` | starts at 1 and is increased by changes |
| `updated_at` | time of the last change, ISO 8601, UTC, to the second |
| `deleted_at` | when the row was marked as deleted; empty for a live row |
| `device_id` | reserved; not written |

**Deleting marks the row and keeps it.** The core marks only the row it is asked to
delete; rows below a deleted entry are not marked. There is no synchronisation yet: these
columns are there so that adding one does not require a new format.

## Reserved columns

These exist in the tables and are not written or read by this version:
`entries.icon_type`, `entries.icon_data`, `entries.sort_order`,
`entries.browser_extension_allowed`, `fields.linked_entry_id`, `categories.sort_order`,
`login_methods.sort_order` (read for ordering, never written) and every `device_id`.

## Which rules the core keeps

The core stores what it is given. It checks:

- a preset category cannot be renamed, moved or deleted, and a category cannot be its own
  parent;
- tag names are unique;
- `Vault::merge_service` takes two different services; `Vault::set_accounts_persona` takes
  accounts and a persona;
- a setting below its lowest value is refused.

It does **not** check that an entry's parents have the types in the table above, that a
login method belongs to an account, or that a link points at another service's account.
The application built on the core keeps those rules. There are no foreign-key constraints
in the schema.

## Schema

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

A vault that was brought up from format 1 has the same columns; their order within a
table may differ.
