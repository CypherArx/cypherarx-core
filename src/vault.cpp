#include "cypherarx/vault.hpp"

#include <chrono>
#include <filesystem>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <sqlite3.h>

#include "cypherarx/crypto.hpp"
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
    ");"
    "CREATE TABLE IF NOT EXISTS entries ("
    "  id INTEGER PRIMARY KEY,"
    "  parent_id INTEGER,"
    "  entry_type TEXT,"
    "  label_enc BLOB NOT NULL,"
    "  url_enc BLOB,"
    "  login_url_enc BLOB,"
    "  display_name_enc BLOB,"
    "  notes_enc BLOB,"
    "  category_id INTEGER,"
    "  is_favorite INTEGER DEFAULT 0,"
    "  icon_type TEXT,"
    "  icon_data TEXT,"
    "  sort_order INTEGER,"
    "  browser_extension_allowed INTEGER DEFAULT 1,"
    "  dek_id INTEGER,"
    "  created_at TEXT,"
    "  updated_at TEXT,"
    "  uuid TEXT NOT NULL UNIQUE,"
    "  revision INTEGER DEFAULT 1,"
    "  deleted_at TEXT,"
    "  device_id TEXT"
    ");"
    "CREATE TABLE IF NOT EXISTS fields ("
    "  id INTEGER PRIMARY KEY,"
    "  entry_id INTEGER,"
    "  label_enc BLOB NOT NULL,"
    "  value_enc BLOB NOT NULL,"
    "  notes_enc BLOB,"
    "  field_type TEXT NOT NULL,"
    "  linked_entry_id INTEGER,"
    "  dek_id INTEGER,"
    "  uuid TEXT NOT NULL UNIQUE,"
    "  revision INTEGER DEFAULT 1,"
    "  updated_at TEXT NOT NULL,"
    "  deleted_at TEXT,"
    "  device_id TEXT"
    ");";

VaultError map_key_error(VaultKeyError e) {
    switch (e) {
        case VaultKeyError::WrongPassword: return VaultError::WrongPassword;
        case VaultKeyError::KdfFailed:     return VaultError::KdfFailed;
        case VaultKeyError::InvalidInput:  return VaultError::Corrupt;
        default:                           return VaultError::Internal;
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
    // Idempotent: brings older vaults up to the current schema.
    if (!exec(vault.impl_->db, kSchema)) {
        return std::unexpected(VaultError::DatabaseError);
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

// --- Entry / field storage ---

namespace {

std::string now_iso8601() {
    using namespace std::chrono;
    return std::format("{:%FT%TZ}", floor<seconds>(system_clock::now()));
}

// AAD binds each ciphertext to its entry/field uuid and which column it is, so a blob can
// never be silently moved to a different row or column.
std::vector<std::uint8_t> aad_for(std::string_view uuid, std::string_view kind) {
    std::vector<std::uint8_t> a;
    a.reserve(uuid.size() + 1 + kind.size());
    a.insert(a.end(), uuid.begin(), uuid.end());
    a.push_back('|');
    a.insert(a.end(), kind.begin(), kind.end());
    return a;
}

std::optional<std::vector<std::uint8_t>>
enc_bytes(std::span<const std::uint8_t> dek, std::span<const std::uint8_t> plain,
          std::string_view uuid, std::string_view kind) {
    auto r = aead_encrypt(dek, plain, aad_for(uuid, kind));
    if (!r) {
        return std::nullopt;
    }
    return std::move(r).value();
}

std::optional<std::vector<std::uint8_t>>
enc_text(std::span<const std::uint8_t> dek, std::string_view plain, std::string_view uuid,
         std::string_view kind) {
    return enc_bytes(dek, {reinterpret_cast<const std::uint8_t*>(plain.data()), plain.size()},
                     uuid, kind);
}

std::optional<std::string>
dec_text(std::span<const std::uint8_t> dek, std::span<const std::uint8_t> blob,
         std::string_view uuid, std::string_view kind) {
    auto r = aead_decrypt(dek, blob, aad_for(uuid, kind));
    if (!r) {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(r->data()), r->size());
}

void bind_blob(sqlite3_stmt* st, int i, const std::vector<std::uint8_t>& v) {
    sqlite3_bind_blob(st, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
}

std::string text_col(sqlite3_stmt* st, int i) {
    const auto* p = reinterpret_cast<const char*>(sqlite3_column_text(st, i));
    return p ? std::string(p) : std::string();
}

std::span<const std::uint8_t> blob_col(sqlite3_stmt* st, int i) {
    const auto* p = static_cast<const std::uint8_t*>(sqlite3_column_blob(st, i));
    const int n = sqlite3_column_bytes(st, i);
    return {p, static_cast<std::size_t>(n)};
}

// Column order shared by get_entry / list_entries.
constexpr const char* kEntryCols =
    "id,parent_id,entry_type,label_enc,url_enc,login_url_enc,display_name_enc,notes_enc,uuid";

std::optional<Entry> decode_entry(sqlite3_stmt* st, std::span<const std::uint8_t> dek) {
    Entry e;
    e.id = sqlite3_column_int64(st, 0);
    if (sqlite3_column_type(st, 1) != SQLITE_NULL) {
        e.parent_id = sqlite3_column_int64(st, 1);
    }
    e.entry_type = text_col(st, 2);
    e.uuid = text_col(st, 8);

    auto label = dec_text(dek, blob_col(st, 3), e.uuid, "label");
    auto url = dec_text(dek, blob_col(st, 4), e.uuid, "url");
    auto login_url = dec_text(dek, blob_col(st, 5), e.uuid, "login_url");
    auto display_name = dec_text(dek, blob_col(st, 6), e.uuid, "display_name");
    auto notes = dec_text(dek, blob_col(st, 7), e.uuid, "notes");
    if (!label || !url || !login_url || !display_name || !notes) {
        return std::nullopt;
    }
    e.label = std::move(*label);
    e.url = std::move(*url);
    e.login_url = std::move(*login_url);
    e.display_name = std::move(*display_name);
    e.notes = std::move(*notes);
    return e;
}

} // namespace

std::expected<Entry, VaultError> Vault::add_entry(const Entry& in) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    const auto dek = impl_->dek.bytes();

    Entry e = in;
    e.id = 0;
    e.uuid = new_uuid();
    const std::string ts = now_iso8601();

    auto label = enc_text(dek, e.label, e.uuid, "label");
    auto url = enc_text(dek, e.url, e.uuid, "url");
    auto login_url = enc_text(dek, e.login_url, e.uuid, "login_url");
    auto display_name = enc_text(dek, e.display_name, e.uuid, "display_name");
    auto notes = enc_text(dek, e.notes, e.uuid, "notes");
    if (!label || !url || !login_url || !display_name || !notes) {
        return std::unexpected(VaultError::Internal);
    }

    static const char* sql =
        "INSERT INTO entries(parent_id,entry_type,label_enc,url_enc,login_url_enc,"
        "display_name_enc,notes_enc,dek_id,created_at,updated_at,uuid,revision) "
        "VALUES(?,?,?,?,?,?,?,1,?,?,?,1)";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    if (e.parent_id) {
        sqlite3_bind_int64(st, 1, *e.parent_id);
    } else {
        sqlite3_bind_null(st, 1);
    }
    sqlite3_bind_text(st, 2, e.entry_type.c_str(), -1, SQLITE_TRANSIENT);
    bind_blob(st, 3, *label);
    bind_blob(st, 4, *url);
    bind_blob(st, 5, *login_url);
    bind_blob(st, 6, *display_name);
    bind_blob(st, 7, *notes);
    sqlite3_bind_text(st, 8, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, e.uuid.c_str(), -1, SQLITE_TRANSIENT);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) {
        return std::unexpected(VaultError::DatabaseError);
    }

    e.id = sqlite3_last_insert_rowid(impl_->db);
    return e;
}

std::expected<Entry, VaultError> Vault::get_entry(std::int64_t id) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    const std::string sql =
        std::string("SELECT ") + kEntryCols + " FROM entries WHERE id=? AND deleted_at IS NULL";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    sqlite3_bind_int64(st, 1, id);

    std::expected<Entry, VaultError> result = std::unexpected(VaultError::NotFound);
    if (sqlite3_step(st) == SQLITE_ROW) {
        auto e = decode_entry(st, impl_->dek.bytes());
        result = e ? std::expected<Entry, VaultError>(std::move(*e))
                   : std::unexpected(VaultError::Corrupt);
    }
    sqlite3_finalize(st);
    return result;
}

std::expected<std::vector<Entry>, VaultError> Vault::list_entries() {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    const std::string sql = std::string("SELECT ") + kEntryCols +
                            " FROM entries WHERE deleted_at IS NULL ORDER BY id";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }

    std::vector<Entry> out;
    const auto dek = impl_->dek.bytes();
    while (sqlite3_step(st) == SQLITE_ROW) {
        auto e = decode_entry(st, dek);
        if (!e) {
            sqlite3_finalize(st);
            return std::unexpected(VaultError::Corrupt);
        }
        out.push_back(std::move(*e));
    }
    sqlite3_finalize(st);
    return out;
}

std::expected<void, VaultError> Vault::update_entry(const Entry& e) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    if (e.uuid.empty()) {
        return std::unexpected(VaultError::NotFound);
    }
    const auto dek = impl_->dek.bytes();

    auto label = enc_text(dek, e.label, e.uuid, "label");
    auto url = enc_text(dek, e.url, e.uuid, "url");
    auto login_url = enc_text(dek, e.login_url, e.uuid, "login_url");
    auto display_name = enc_text(dek, e.display_name, e.uuid, "display_name");
    auto notes = enc_text(dek, e.notes, e.uuid, "notes");
    if (!label || !url || !login_url || !display_name || !notes) {
        return std::unexpected(VaultError::Internal);
    }

    static const char* sql =
        "UPDATE entries SET entry_type=?,label_enc=?,url_enc=?,login_url_enc=?,"
        "display_name_enc=?,notes_enc=?,updated_at=?,revision=revision+1 "
        "WHERE id=? AND deleted_at IS NULL";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    const std::string ts = now_iso8601();
    sqlite3_bind_text(st, 1, e.entry_type.c_str(), -1, SQLITE_TRANSIENT);
    bind_blob(st, 2, *label);
    bind_blob(st, 3, *url);
    bind_blob(st, 4, *login_url);
    bind_blob(st, 5, *display_name);
    bind_blob(st, 6, *notes);
    sqlite3_bind_text(st, 7, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 8, e.id);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    const int changed = sqlite3_changes(impl_->db);
    sqlite3_finalize(st);
    if (!ok) {
        return std::unexpected(VaultError::DatabaseError);
    }
    if (changed == 0) {
        return std::unexpected(VaultError::NotFound);
    }
    return {};
}

std::expected<void, VaultError> Vault::delete_entry(std::int64_t id) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    static const char* sql =
        "UPDATE entries SET deleted_at=?,revision=revision+1 WHERE id=? AND deleted_at IS NULL";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    const std::string ts = now_iso8601();
    sqlite3_bind_text(st, 1, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, id);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    const int changed = sqlite3_changes(impl_->db);
    sqlite3_finalize(st);
    if (!ok) {
        return std::unexpected(VaultError::DatabaseError);
    }
    if (changed == 0) {
        return std::unexpected(VaultError::NotFound);
    }
    return {};
}

std::expected<Field, VaultError>
Vault::add_field(std::int64_t entry_id, const std::string& label, const std::string& field_type,
                 std::span<const std::uint8_t> value, const std::string& notes) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    const auto dek = impl_->dek.bytes();

    Field f;
    f.id = 0;
    f.entry_id = entry_id;
    f.label = label;
    f.field_type = field_type;
    f.notes = notes;
    f.uuid = new_uuid();

    auto label_enc = enc_text(dek, label, f.uuid, "label");
    auto value_enc = enc_bytes(dek, value, f.uuid, "value");
    auto notes_enc = enc_text(dek, notes, f.uuid, "notes");
    if (!label_enc || !value_enc || !notes_enc) {
        return std::unexpected(VaultError::Internal);
    }

    static const char* sql =
        "INSERT INTO fields(entry_id,label_enc,value_enc,notes_enc,field_type,dek_id,uuid,"
        "revision,updated_at) VALUES(?,?,?,?,?,1,?,1,?)";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    const std::string ts = now_iso8601();
    sqlite3_bind_int64(st, 1, entry_id);
    bind_blob(st, 2, *label_enc);
    bind_blob(st, 3, *value_enc);
    bind_blob(st, 4, *notes_enc);
    sqlite3_bind_text(st, 5, field_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, f.uuid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, ts.c_str(), -1, SQLITE_TRANSIENT);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) {
        return std::unexpected(VaultError::DatabaseError);
    }

    f.id = sqlite3_last_insert_rowid(impl_->db);
    return f;
}

std::expected<std::vector<Field>, VaultError> Vault::list_fields(std::int64_t entry_id) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    static const char* sql =
        "SELECT id,entry_id,label_enc,notes_enc,field_type,uuid FROM fields "
        "WHERE entry_id=? AND deleted_at IS NULL ORDER BY id";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    sqlite3_bind_int64(st, 1, entry_id);

    std::vector<Field> out;
    const auto dek = impl_->dek.bytes();
    while (sqlite3_step(st) == SQLITE_ROW) {
        Field f;
        f.id = sqlite3_column_int64(st, 0);
        f.entry_id = sqlite3_column_int64(st, 1);
        f.uuid = text_col(st, 5);
        auto label = dec_text(dek, blob_col(st, 2), f.uuid, "label");
        auto notes = dec_text(dek, blob_col(st, 3), f.uuid, "notes");
        if (!label || !notes) {
            sqlite3_finalize(st);
            return std::unexpected(VaultError::Corrupt);
        }
        f.label = std::move(*label);
        f.notes = std::move(*notes);
        f.field_type = text_col(st, 4);
        out.push_back(std::move(f));
    }
    sqlite3_finalize(st);
    return out;
}

std::expected<Secret, VaultError> Vault::field_value(std::int64_t field_id) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    static const char* sql =
        "SELECT value_enc,uuid FROM fields WHERE id=? AND deleted_at IS NULL";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    sqlite3_bind_int64(st, 1, field_id);

    std::expected<Secret, VaultError> result = std::unexpected(VaultError::NotFound);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const auto blob = blob_col(st, 0);
        const std::string uuid = text_col(st, 1);
        auto value = aead_decrypt(impl_->dek.bytes(), blob, aad_for(uuid, "value"));
        result = value ? std::expected<Secret, VaultError>(std::move(value).value())
                       : std::unexpected(VaultError::Corrupt);
    }
    sqlite3_finalize(st);
    return result;
}

std::expected<void, VaultError> Vault::delete_field(std::int64_t field_id) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    static const char* sql =
        "UPDATE fields SET deleted_at=?,revision=revision+1 WHERE id=? AND deleted_at IS NULL";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    const std::string ts = now_iso8601();
    sqlite3_bind_text(st, 1, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, field_id);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    const int changed = sqlite3_changes(impl_->db);
    sqlite3_finalize(st);
    if (!ok) {
        return std::unexpected(VaultError::DatabaseError);
    }
    if (changed == 0) {
        return std::unexpected(VaultError::NotFound);
    }
    return {};
}

} // namespace cypherarx
