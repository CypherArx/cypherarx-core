#include "cypherarx/vault.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <sqlite3.h>

#include "cypherarx/secret.hpp"
#include "cypherarx/vault_key.hpp"

namespace cypherarx {

struct Vault::Impl {
    sqlite3* db = nullptr;
    Secret dek;
    bool unlocked = false;

    ~Impl() {
        if (db != nullptr) {
            sqlite3_close(db);
        }
    }
};

namespace {

constexpr const char* kMetaSalt = "kdf_salt";
constexpr const char* kMetaParams = "kdf_params";
constexpr const char* kMetaWrappedDek = "wrapped_dek";

constexpr const char* kSchema =
    "CREATE TABLE IF NOT EXISTS crypto_meta ("
    "  key   TEXT PRIMARY KEY,"
    "  value BLOB NOT NULL"
    ");";

VaultError map_key_error(VaultKeyError e) {
    switch (e) {
        case VaultKeyError::WrongPassword: return VaultError::WrongPassword;
        case VaultKeyError::KdfFailed:     return VaultError::KdfFailed;
        case VaultKeyError::InvalidInput:  return VaultError::Corrupt;
        default:                           return VaultError::DatabaseError;
    }
}

bool exec(sqlite3* db, const char* sql) {
    return sqlite3_exec(db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

bool set_meta(sqlite3* db, const char* key, std::span<const std::uint8_t> value) {
    static const char* sql =
        "INSERT INTO crypto_meta(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, value.data(), static_cast<int>(value.size()), SQLITE_STATIC);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool set_meta_text(sqlite3* db, const char* key, const std::string& value) {
    return set_meta(db, key, {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()});
}

std::optional<std::vector<std::uint8_t>> get_meta(sqlite3* db, const char* key) {
    static const char* sql = "SELECT value FROM crypto_meta WHERE key=?";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC);
    std::optional<std::vector<std::uint8_t>> out;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const auto* p = static_cast<const std::uint8_t*>(sqlite3_column_blob(st, 0));
        const int n = sqlite3_column_bytes(st, 0);
        out = std::vector<std::uint8_t>(p, p + n);
    }
    sqlite3_finalize(st);
    return out;
}

// Load the persisted key material from crypto_meta. Returns nullopt if anything is missing
// or the params string cannot be parsed (corrupt vault).
std::optional<VaultKeyMaterial> load_material(sqlite3* db) {
    const auto salt = get_meta(db, kMetaSalt);
    const auto params_bytes = get_meta(db, kMetaParams);
    const auto wrapped = get_meta(db, kMetaWrappedDek);
    if (!salt || !params_bytes || !wrapped) {
        return std::nullopt;
    }
    const std::string params_str(params_bytes->begin(), params_bytes->end());
    const auto params = KdfParams::from_string(params_str);
    if (!params) {
        return std::nullopt;
    }
    return VaultKeyMaterial{*salt, *params, *wrapped};
}

bool store_material(sqlite3* db, const VaultKeyMaterial& m) {
    return set_meta(db, kMetaSalt, m.salt)
        && set_meta_text(db, kMetaParams, m.params.to_string())
        && set_meta(db, kMetaWrappedDek, m.wrapped_dek);
}

} // namespace

Vault::Vault() : impl_(std::make_unique<Impl>()) {}
Vault::Vault(Vault&&) noexcept = default;
Vault& Vault::operator=(Vault&&) noexcept = default;
Vault::~Vault() = default;

bool Vault::is_unlocked() const noexcept {
    return impl_ && impl_->unlocked;
}

std::expected<Vault, VaultError>
Vault::create(const std::string& path, std::span<const std::uint8_t> password,
              const KdfParams& params) {
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        return std::unexpected(VaultError::AlreadyInitialized);
    }

    Vault vault;
    if (sqlite3_open_v2(path.c_str(), &vault.impl_->db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::CannotOpenFile);
    }
    if (!exec(vault.impl_->db, kSchema)) {
        return std::unexpected(VaultError::DatabaseError);
    }

    auto keys = create_vault_keys(password, params);
    if (!keys) {
        return std::unexpected(map_key_error(keys.error()));
    }
    if (!store_material(vault.impl_->db, keys->second)) {
        return std::unexpected(VaultError::DatabaseError);
    }
    exec(vault.impl_->db, "PRAGMA user_version=1;");

    vault.impl_->dek = std::move(keys->first);
    vault.impl_->unlocked = true;
    return vault;
}

std::expected<Vault, VaultError>
Vault::open(const std::string& path, std::span<const std::uint8_t> password) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return std::unexpected(VaultError::NotInitialized);
    }

    Vault vault;
    if (sqlite3_open_v2(path.c_str(), &vault.impl_->db, SQLITE_OPEN_READWRITE, nullptr)
        != SQLITE_OK) {
        return std::unexpected(VaultError::CannotOpenFile);
    }

    const auto material = load_material(vault.impl_->db);
    if (!material) {
        return std::unexpected(VaultError::Corrupt);
    }
    auto dek = unlock_vault(password, *material);
    if (!dek) {
        return std::unexpected(map_key_error(dek.error()));
    }

    vault.impl_->dek = std::move(dek).value();
    vault.impl_->unlocked = true;
    return vault;
}

std::expected<void, VaultError>
Vault::change_master_password(std::span<const std::uint8_t> old_password,
                              std::span<const std::uint8_t> new_password,
                              const KdfParams& new_params) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }

    const auto current = load_material(impl_->db);
    if (!current) {
        return std::unexpected(VaultError::Corrupt);
    }

    // Verifies the old password and re-wraps the same DEK under the new password.
    auto next = ::cypherarx::change_master_password(old_password, *current, new_password,
                                                    new_params);
    if (!next) {
        return std::unexpected(map_key_error(next.error()));
    }

    if (!exec(impl_->db, "BEGIN")) {
        return std::unexpected(VaultError::DatabaseError);
    }
    if (!store_material(impl_->db, *next)) {
        exec(impl_->db, "ROLLBACK");
        return std::unexpected(VaultError::DatabaseError);
    }
    if (!exec(impl_->db, "COMMIT")) {
        exec(impl_->db, "ROLLBACK");
        return std::unexpected(VaultError::DatabaseError);
    }
    return {};
}

} // namespace cypherarx
