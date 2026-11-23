#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "cypherarx/entry.hpp"
#include "cypherarx/kdf.hpp"
#include "cypherarx/secret.hpp"
#include "cypherarx/settings.hpp"

namespace cypherarx {

/// Failure modes for opening/creating an on-disk vault.
enum class VaultError {
    CannotOpenFile,       ///< SQLite could not open/create the file.
    AlreadyInitialized,   ///< create() called on an existing file.
    NotInitialized,       ///< open() called on a missing/empty file.
    Corrupt,              ///< Required crypto_meta rows are missing/unparseable.
    WrongPassword,        ///< Master password did not unwrap the DEK.
    KdfFailed,            ///< Argon2id failed.
    DatabaseError,        ///< Unexpected SQLite error.
    NotUnlocked,          ///< Operation requires an unlocked vault.
    NotFound,             ///< Requested entry/field does not exist.
    Forbidden,            ///< Operation not allowed on this row (e.g. deleting a preset category).
    Internal,             ///< Unexpected internal error (e.g. encryption failure).
    InvalidValue,
};

/// An encrypted vault backed by a single SQLite file. Owns the in-memory DEK once
/// unlocked. Move-only; the DEK is wiped on destruction. This is the persistence entry
/// point on top of the KEK/DEK key hierarchy; entry/field storage builds on it.
class Vault {
public:
    Vault(Vault&&) noexcept;
    Vault& operator=(Vault&&) noexcept;
    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;
    ~Vault();

    /// Create a new vault file (must not already exist) and leave it unlocked.
    static std::expected<Vault, VaultError>
    create(const std::filesystem::path& path, std::span<const std::uint8_t> password,
           const KdfParams& params);

    /// Open an existing vault file and unlock it with the master password.
    static std::expected<Vault, VaultError>
    open(const std::filesystem::path& path, std::span<const std::uint8_t> password);

    /// Change the master password: KEK is regenerated, the DEK (and all data) is unchanged.
    std::expected<void, VaultError>
    change_master_password(std::span<const std::uint8_t> old_password,
                           std::span<const std::uint8_t> new_password,
                           const KdfParams& new_params);

    [[nodiscard]] bool is_unlocked() const noexcept;

    // --- Entries (text columns are encrypted at rest with the DEK) ---

    /// Insert a new entry. `in.id`/`in.uuid` are ignored; the stored entry (with id + uuid) is returned.
    std::expected<Entry, VaultError> add_entry(const Entry& in);
    /// Fetch a single non-deleted entry by id.
    std::expected<Entry, VaultError> get_entry(std::int64_t id);
    /// List all non-deleted entries (ordered by id).
    std::expected<std::vector<Entry>, VaultError> list_entries();
    /// Re-encrypt and update the mutable text columns of an existing entry (by `e.id`).
    std::expected<void, VaultError> update_entry(const Entry& e);
    /// Soft-delete an entry (tombstone for sync).
    std::expected<void, VaultError> delete_entry(std::int64_t id);

    // --- Fields ---

    /// Add a field to an entry. The secret `value` is encrypted; returns the stored Field (no value).
    std::expected<Field, VaultError>
    add_field(std::int64_t entry_id, const std::string& label, const std::string& field_type,
              std::span<const std::uint8_t> value, const std::string& notes);
    /// List an entry's non-deleted fields (without their secret values).
    std::expected<std::vector<Field>, VaultError> list_fields(std::int64_t entry_id);
    /// Fetch and decrypt a field's secret value into guarded memory (on demand).
    std::expected<Secret, VaultError> field_value(std::int64_t field_id);
    /// Re-encrypt and update a field's label, type, secret value and notes (by `field_id`).
    std::expected<void, VaultError>
    update_field(std::int64_t field_id, const std::string& label, const std::string& field_type,
                 std::span<const std::uint8_t> value, const std::string& notes);
    /// Soft-delete a field (tombstone for sync).
    std::expected<void, VaultError> delete_field(std::int64_t field_id);

    // --- Login methods (reference-link layer, §10.1.1) ---

    /// Record a way to log in to `entry_id`. `linked_entry_id` is the account you log in via
    /// (OAuth / "log in with X"), or nullopt for a direct method (e.g. email+password).
    std::expected<LoginMethod, VaultError>
    add_login_method(std::int64_t entry_id, const std::string& method_type,
                     std::optional<std::int64_t> linked_entry_id, const std::string& notes);
    /// List an entry's non-deleted login methods.
    std::expected<std::vector<LoginMethod>, VaultError> list_login_methods(std::int64_t entry_id);
    /// Re-encrypt and update a login method's type, link and notes (by `id`).
    std::expected<void, VaultError>
    update_login_method(std::int64_t id, const std::string& method_type,
                        std::optional<std::int64_t> linked_entry_id, const std::string& notes);
    /// Soft-delete a login method (tombstone for sync).
    std::expected<void, VaultError> delete_login_method(std::int64_t id);

    // --- Categories (§10.3; presets are seeded on create and on first open) ---

    std::expected<Category, VaultError>
    add_category(const std::string& name, std::optional<std::int64_t> parent_id);
    /// All non-deleted categories, presets first then by id.
    std::expected<std::vector<Category>, VaultError> list_categories();
    /// Rename / re-parent a custom category. Presets -> Forbidden.
    std::expected<void, VaultError>
    update_category(std::int64_t id, const std::string& name, std::optional<std::int64_t> parent_id);
    /// Soft-delete a custom category; its children and entries become uncategorized. Presets -> Forbidden.
    std::expected<void, VaultError> delete_category(std::int64_t id);

    // --- Tags (§10.4) ---

    /// Add a tag, or return the existing tag with the same name.
    std::expected<Tag, VaultError> add_tag(const std::string& name);
    std::expected<std::vector<Tag>, VaultError> list_tags();
    std::expected<void, VaultError> rename_tag(std::int64_t id, const std::string& name);
    /// Soft-delete a tag and remove it from every entry.
    std::expected<void, VaultError> delete_tag(std::int64_t id);
    /// Replace the set of tags attached to an entry.
    std::expected<void, VaultError>
    set_entry_tags(std::int64_t entry_id, const std::vector<std::int64_t>& tag_ids);
    /// Tag ids attached to an entry (ordered by tag id).
    std::expected<std::vector<std::int64_t>, VaultError> entry_tags(std::int64_t entry_id);
    /// Every (entry_id, tag_id) pair for non-deleted entries and tags, for building filters.
    std::expected<std::vector<std::pair<std::int64_t, std::int64_t>>, VaultError> list_entry_tags();

    std::expected<Settings, VaultError> settings();
    std::expected<void, VaultError> set_settings(const Settings& settings);

private:
    Vault();
    bool seed_presets();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace cypherarx
