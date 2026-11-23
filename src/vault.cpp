#include "cypherarx/vault.hpp"

#include <charconv>
#include <chrono>
#include <map>
#include <set>
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
    "  persona_id INTEGER,"
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
    ");"
    "CREATE TABLE IF NOT EXISTS login_methods ("
    "  id INTEGER PRIMARY KEY,"
    "  entry_id INTEGER,"
    "  method_type TEXT NOT NULL,"
    "  linked_entry_id INTEGER,"
    "  notes_enc BLOB,"
    "  sort_order INTEGER,"
    "  dek_id INTEGER,"
    "  uuid TEXT NOT NULL UNIQUE,"
    "  revision INTEGER DEFAULT 1,"
    "  updated_at TEXT NOT NULL,"
    "  deleted_at TEXT,"
    "  device_id TEXT"
    ");"
    "CREATE TABLE IF NOT EXISTS categories ("
    "  id INTEGER PRIMARY KEY,"
    "  parent_id INTEGER,"
    "  name_enc BLOB NOT NULL,"
    "  is_preset INTEGER DEFAULT 0,"
    "  sort_order INTEGER,"
    "  dek_id INTEGER,"
    "  uuid TEXT NOT NULL UNIQUE,"
    "  revision INTEGER DEFAULT 1,"
    "  updated_at TEXT NOT NULL,"
    "  deleted_at TEXT,"
    "  device_id TEXT"
    ");"
    "CREATE TABLE IF NOT EXISTS tags ("
    "  id INTEGER PRIMARY KEY,"
    "  name_enc BLOB NOT NULL,"
    "  dek_id INTEGER,"
    "  uuid TEXT NOT NULL UNIQUE,"
    "  revision INTEGER DEFAULT 1,"
    "  updated_at TEXT NOT NULL,"
    "  deleted_at TEXT,"
    "  device_id TEXT"
    ");"
    "CREATE TABLE IF NOT EXISTS entry_tags ("
    "  entry_id INTEGER NOT NULL,"
    "  tag_id INTEGER NOT NULL,"
    "  PRIMARY KEY (entry_id, tag_id)"
    ");"
    "CREATE TABLE IF NOT EXISTS access_logs ("
    "  id INTEGER PRIMARY KEY,"
    "  value_enc BLOB NOT NULL,"
    "  dek_id INTEGER,"
    "  uuid TEXT NOT NULL UNIQUE"
    ");"
    "CREATE TABLE IF NOT EXISTS settings ("
    "  key TEXT PRIMARY KEY,"
    "  value_enc BLOB NOT NULL,"
    "  dek_id INTEGER"
    ");";

// Seeded once per vault (§10.3). Encrypted like custom names so the column has one shape.
constexpr const char* kPresetCategories[] = {"金融", "SNS", "ショッピング", "メール",
                                             "ゲーム", "仕事", "その他"};

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
Vault::create(const std::filesystem::path& path, std::span<const std::uint8_t> password,
              const KdfParams& params) {
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        return std::unexpected(VaultError::AlreadyInitialized);
    }

    Vault vault;
    const std::u8string utf8 = path.u8string();
    if (sqlite3_open_v2(reinterpret_cast<const char*>(utf8.c_str()), &vault.impl_->db,
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
    if (!vault.seed_presets()) {
        return std::unexpected(VaultError::DatabaseError);
    }
    return vault;
}

std::expected<Vault, VaultError>
Vault::open(const std::filesystem::path& path, std::span<const std::uint8_t> password) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return std::unexpected(VaultError::NotInitialized);
    }

    Vault vault;
    const std::u8string utf8 = path.u8string();
    if (sqlite3_open_v2(reinterpret_cast<const char*>(utf8.c_str()), &vault.impl_->db,
                        SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::CannotOpenFile);
    }
    // Idempotent: brings older vaults up to the current schema.
    if (!exec(vault.impl_->db, kSchema)) {
        return std::unexpected(VaultError::DatabaseError);
    }
    // Migration: add entries.persona_id to vaults created before the two-parent model (§10.1.1).
    // Harmlessly fails (ignored) when the column already exists.
    sqlite3_exec(vault.impl_->db, "ALTER TABLE entries ADD COLUMN persona_id INTEGER", nullptr,
                 nullptr, nullptr);

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
    if (!vault.seed_presets()) {
        return std::unexpected(VaultError::DatabaseError);
    }
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

void bind_opt_int64(sqlite3_stmt* st, int i, std::optional<std::int64_t> v) {
    if (v) {
        sqlite3_bind_int64(st, i, *v);
    } else {
        sqlite3_bind_null(st, i);
    }
}

std::optional<std::int64_t> opt_int64_col(sqlite3_stmt* st, int i) {
    if (sqlite3_column_type(st, i) == SQLITE_NULL) {
        return std::nullopt;
    }
    return sqlite3_column_int64(st, i);
}

// Column order shared by get_entry / list_entries.
constexpr const char* kEntryCols =
    "id,parent_id,persona_id,entry_type,label_enc,url_enc,login_url_enc,display_name_enc,notes_enc,"
    "uuid,category_id,is_favorite";

std::optional<Entry> decode_entry(sqlite3_stmt* st, std::span<const std::uint8_t> dek) {
    Entry e;
    e.id = sqlite3_column_int64(st, 0);
    e.parent_id = opt_int64_col(st, 1);
    e.persona_id = opt_int64_col(st, 2);
    e.entry_type = text_col(st, 3);
    e.uuid = text_col(st, 9);
    e.category_id = opt_int64_col(st, 10);
    e.is_favorite = sqlite3_column_int(st, 11) != 0;

    auto label = dec_text(dek, blob_col(st, 4), e.uuid, "label");
    auto url = dec_text(dek, blob_col(st, 5), e.uuid, "url");
    auto login_url = dec_text(dek, blob_col(st, 6), e.uuid, "login_url");
    auto display_name = dec_text(dek, blob_col(st, 7), e.uuid, "display_name");
    auto notes = dec_text(dek, blob_col(st, 8), e.uuid, "notes");
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
        "INSERT INTO entries(parent_id,persona_id,entry_type,label_enc,url_enc,login_url_enc,"
        "display_name_enc,notes_enc,dek_id,created_at,updated_at,uuid,revision,category_id,"
        "is_favorite) VALUES(?,?,?,?,?,?,?,?,1,?,?,?,1,?,?)";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    bind_opt_int64(st, 1, e.parent_id);
    bind_opt_int64(st, 2, e.persona_id);
    sqlite3_bind_text(st, 3, e.entry_type.c_str(), -1, SQLITE_TRANSIENT);
    bind_blob(st, 4, *label);
    bind_blob(st, 5, *url);
    bind_blob(st, 6, *login_url);
    bind_blob(st, 7, *display_name);
    bind_blob(st, 8, *notes);
    sqlite3_bind_text(st, 9, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, e.uuid.c_str(), -1, SQLITE_TRANSIENT);
    bind_opt_int64(st, 12, e.category_id);
    sqlite3_bind_int(st, 13, e.is_favorite ? 1 : 0);
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
        "UPDATE entries SET parent_id=?,persona_id=?,entry_type=?,label_enc=?,url_enc=?,"
        "login_url_enc=?,display_name_enc=?,notes_enc=?,updated_at=?,revision=revision+1,"
        "category_id=?,is_favorite=? WHERE id=? AND deleted_at IS NULL";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    const std::string ts = now_iso8601();
    bind_opt_int64(st, 1, e.parent_id);
    bind_opt_int64(st, 2, e.persona_id);
    sqlite3_bind_text(st, 3, e.entry_type.c_str(), -1, SQLITE_TRANSIENT);
    bind_blob(st, 4, *label);
    bind_blob(st, 5, *url);
    bind_blob(st, 6, *login_url);
    bind_blob(st, 7, *display_name);
    bind_blob(st, 8, *notes);
    sqlite3_bind_text(st, 9, ts.c_str(), -1, SQLITE_TRANSIENT);
    bind_opt_int64(st, 10, e.category_id);
    sqlite3_bind_int(st, 11, e.is_favorite ? 1 : 0);
    sqlite3_bind_int64(st, 12, e.id);
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

std::expected<void, VaultError>
Vault::update_field(std::int64_t field_id, const std::string& label,
                    const std::string& field_type, std::span<const std::uint8_t> value,
                    const std::string& notes) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    const auto dek = impl_->dek.bytes();

    // The AAD binds each ciphertext to the field's uuid, so fetch it before re-encrypting.
    std::string uuid;
    {
        static const char* q = "SELECT uuid FROM fields WHERE id=? AND deleted_at IS NULL";
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(impl_->db, q, -1, &st, nullptr) != SQLITE_OK) {
            return std::unexpected(VaultError::DatabaseError);
        }
        sqlite3_bind_int64(st, 1, field_id);
        const bool found = sqlite3_step(st) == SQLITE_ROW;
        if (found) {
            uuid = text_col(st, 0);
        }
        sqlite3_finalize(st);
        if (!found) {
            return std::unexpected(VaultError::NotFound);
        }
    }

    auto label_enc = enc_text(dek, label, uuid, "label");
    auto value_enc = enc_bytes(dek, value, uuid, "value");
    auto notes_enc = enc_text(dek, notes, uuid, "notes");
    if (!label_enc || !value_enc || !notes_enc) {
        return std::unexpected(VaultError::Internal);
    }

    static const char* sql =
        "UPDATE fields SET label_enc=?,value_enc=?,notes_enc=?,field_type=?,"
        "updated_at=?,revision=revision+1 WHERE id=? AND deleted_at IS NULL";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    const std::string ts = now_iso8601();
    bind_blob(st, 1, *label_enc);
    bind_blob(st, 2, *value_enc);
    bind_blob(st, 3, *notes_enc);
    sqlite3_bind_text(st, 4, field_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, field_id);
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

std::expected<LoginMethod, VaultError>
Vault::add_login_method(std::int64_t entry_id, const std::string& method_type,
                        std::optional<std::int64_t> linked_entry_id, const std::string& notes) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    const auto dek = impl_->dek.bytes();

    LoginMethod m;
    m.entry_id = entry_id;
    m.method_type = method_type;
    m.linked_entry_id = linked_entry_id;
    m.notes = notes;
    m.uuid = new_uuid();

    auto notes_enc = enc_text(dek, notes, m.uuid, "notes");
    if (!notes_enc) {
        return std::unexpected(VaultError::Internal);
    }

    static const char* sql =
        "INSERT INTO login_methods(entry_id,method_type,linked_entry_id,notes_enc,dek_id,uuid,"
        "revision,updated_at) VALUES(?,?,?,?,1,?,1,?)";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    const std::string ts = now_iso8601();
    sqlite3_bind_int64(st, 1, entry_id);
    sqlite3_bind_text(st, 2, method_type.c_str(), -1, SQLITE_TRANSIENT);
    if (linked_entry_id) {
        sqlite3_bind_int64(st, 3, *linked_entry_id);
    } else {
        sqlite3_bind_null(st, 3);
    }
    bind_blob(st, 4, *notes_enc);
    sqlite3_bind_text(st, 5, m.uuid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, ts.c_str(), -1, SQLITE_TRANSIENT);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) {
        return std::unexpected(VaultError::DatabaseError);
    }

    m.id = sqlite3_last_insert_rowid(impl_->db);
    return m;
}

std::expected<std::vector<LoginMethod>, VaultError>
Vault::list_login_methods(std::int64_t entry_id) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    static const char* sql =
        "SELECT id,entry_id,method_type,linked_entry_id,notes_enc,uuid FROM login_methods "
        "WHERE entry_id=? AND deleted_at IS NULL ORDER BY sort_order, id";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    sqlite3_bind_int64(st, 1, entry_id);

    std::vector<LoginMethod> out;
    const auto dek = impl_->dek.bytes();
    while (sqlite3_step(st) == SQLITE_ROW) {
        LoginMethod m;
        m.id = sqlite3_column_int64(st, 0);
        m.entry_id = sqlite3_column_int64(st, 1);
        m.method_type = text_col(st, 2);
        if (sqlite3_column_type(st, 3) != SQLITE_NULL) {
            m.linked_entry_id = sqlite3_column_int64(st, 3);
        }
        m.uuid = text_col(st, 5);
        auto notes = dec_text(dek, blob_col(st, 4), m.uuid, "notes");
        if (!notes) {
            sqlite3_finalize(st);
            return std::unexpected(VaultError::Corrupt);
        }
        m.notes = std::move(*notes);
        out.push_back(std::move(m));
    }
    sqlite3_finalize(st);
    return out;
}

std::expected<void, VaultError>
Vault::update_login_method(std::int64_t id, const std::string& method_type,
                           std::optional<std::int64_t> linked_entry_id,
                           const std::string& notes) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    const auto dek = impl_->dek.bytes();

    std::string uuid;
    {
        static const char* q = "SELECT uuid FROM login_methods WHERE id=? AND deleted_at IS NULL";
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(impl_->db, q, -1, &st, nullptr) != SQLITE_OK) {
            return std::unexpected(VaultError::DatabaseError);
        }
        sqlite3_bind_int64(st, 1, id);
        const bool found = sqlite3_step(st) == SQLITE_ROW;
        if (found) {
            uuid = text_col(st, 0);
        }
        sqlite3_finalize(st);
        if (!found) {
            return std::unexpected(VaultError::NotFound);
        }
    }

    auto notes_enc = enc_text(dek, notes, uuid, "notes");
    if (!notes_enc) {
        return std::unexpected(VaultError::Internal);
    }

    static const char* sql =
        "UPDATE login_methods SET method_type=?,linked_entry_id=?,notes_enc=?,updated_at=?,"
        "revision=revision+1 WHERE id=? AND deleted_at IS NULL";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    const std::string ts = now_iso8601();
    sqlite3_bind_text(st, 1, method_type.c_str(), -1, SQLITE_TRANSIENT);
    bind_opt_int64(st, 2, linked_entry_id);
    bind_blob(st, 3, *notes_enc);
    sqlite3_bind_text(st, 4, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, id);
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

std::expected<void, VaultError> Vault::delete_login_method(std::int64_t id) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    static const char* sql = "UPDATE login_methods SET deleted_at=?,revision=revision+1 "
                             "WHERE id=? AND deleted_at IS NULL";
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

// --- Categories / tags ---

namespace {

// Encrypted-name row shared by categories and tags: INSERT with a fresh uuid, or UPDATE by id.
// Returns the new row id (insert) or the number of changed rows (update), nullopt on SQL error.
std::optional<std::int64_t> insert_named(sqlite3* db, std::span<const std::uint8_t> dek,
                                         const char* sql, const std::string& name,
                                         const std::string& uuid,
                                         std::optional<std::int64_t> parent_id, int is_preset,
                                         bool with_parent) {
    auto name_enc = enc_text(dek, name, uuid, "name");
    if (!name_enc) {
        return std::nullopt;
    }
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    const std::string ts = now_iso8601();
    int i = 1;
    if (with_parent) {
        bind_opt_int64(st, i++, parent_id);
    }
    bind_blob(st, i++, *name_enc);
    if (with_parent) {
        sqlite3_bind_int(st, i++, is_preset);
    }
    sqlite3_bind_text(st, i++, uuid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, i++, ts.c_str(), -1, SQLITE_TRANSIENT);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) {
        return std::nullopt;
    }
    return sqlite3_last_insert_rowid(db);
}

std::optional<std::string> uuid_of(sqlite3* db, const char* table, std::int64_t id,
                                   int* is_preset_out) {
    const std::string sql = std::string("SELECT uuid,") +
                            (is_preset_out ? "is_preset" : "0") + " FROM " + table +
                            " WHERE id=? AND deleted_at IS NULL";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    sqlite3_bind_int64(st, 1, id);
    std::optional<std::string> out;
    if (sqlite3_step(st) == SQLITE_ROW) {
        out = text_col(st, 0);
        if (is_preset_out) {
            *is_preset_out = sqlite3_column_int(st, 1);
        }
    }
    sqlite3_finalize(st);
    return out;
}

bool exec_int64(sqlite3* db, const char* sql, std::int64_t a, std::optional<std::int64_t> b = {}) {
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_int64(st, 1, a);
    if (b) {
        sqlite3_bind_int64(st, 2, *b);
    }
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool exec_text_int64(sqlite3* db, const char* sql, const std::string& text, std::int64_t id) {
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(st, 1, text.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, id);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

} // namespace

bool Vault::seed_presets() {
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, "SELECT COUNT(*) FROM categories", -1, &st, nullptr)
        != SQLITE_OK) {
        return false;
    }
    std::int64_t count = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        count = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    if (count > 0) {
        return true;
    }
    if (!exec(impl_->db, "BEGIN")) {
        return false;
    }
    static const char* sql =
        "INSERT INTO categories(parent_id,name_enc,is_preset,dek_id,uuid,revision,updated_at) "
        "VALUES(?,?,?,1,?,1,?)";
    for (const char* name : kPresetCategories) {
        if (!insert_named(impl_->db, impl_->dek.bytes(), sql, name, new_uuid(), std::nullopt, 1,
                          true)) {
            exec(impl_->db, "ROLLBACK");
            return false;
        }
    }
    return exec(impl_->db, "COMMIT");
}

std::expected<Category, VaultError>
Vault::add_category(const std::string& name, std::optional<std::int64_t> parent_id) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    Category c;
    c.parent_id = parent_id;
    c.name = name;
    c.uuid = new_uuid();
    static const char* sql =
        "INSERT INTO categories(parent_id,name_enc,is_preset,dek_id,uuid,revision,updated_at) "
        "VALUES(?,?,?,1,?,1,?)";
    auto id = insert_named(impl_->db, impl_->dek.bytes(), sql, name, c.uuid, parent_id, 0, true);
    if (!id) {
        return std::unexpected(VaultError::DatabaseError);
    }
    c.id = *id;
    return c;
}

std::expected<std::vector<Category>, VaultError> Vault::list_categories() {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    static const char* sql = "SELECT id,parent_id,name_enc,is_preset,uuid FROM categories "
                             "WHERE deleted_at IS NULL ORDER BY is_preset DESC, sort_order, id";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    std::vector<Category> out;
    const auto dek = impl_->dek.bytes();
    while (sqlite3_step(st) == SQLITE_ROW) {
        Category c;
        c.id = sqlite3_column_int64(st, 0);
        c.parent_id = opt_int64_col(st, 1);
        c.is_preset = sqlite3_column_int(st, 3) != 0;
        c.uuid = text_col(st, 4);
        auto name = dec_text(dek, blob_col(st, 2), c.uuid, "name");
        if (!name) {
            sqlite3_finalize(st);
            return std::unexpected(VaultError::Corrupt);
        }
        c.name = std::move(*name);
        out.push_back(std::move(c));
    }
    sqlite3_finalize(st);
    return out;
}

std::expected<void, VaultError>
Vault::update_category(std::int64_t id, const std::string& name,
                       std::optional<std::int64_t> parent_id) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    int is_preset = 0;
    const auto uuid = uuid_of(impl_->db, "categories", id, &is_preset);
    if (!uuid) {
        return std::unexpected(VaultError::NotFound);
    }
    if (is_preset) {
        return std::unexpected(VaultError::Forbidden);
    }
    if (parent_id && *parent_id == id) {
        return std::unexpected(VaultError::Forbidden);
    }
    auto name_enc = enc_text(impl_->dek.bytes(), name, *uuid, "name");
    if (!name_enc) {
        return std::unexpected(VaultError::Internal);
    }
    static const char* sql = "UPDATE categories SET parent_id=?,name_enc=?,updated_at=?,"
                             "revision=revision+1 WHERE id=? AND deleted_at IS NULL";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    const std::string ts = now_iso8601();
    bind_opt_int64(st, 1, parent_id);
    bind_blob(st, 2, *name_enc);
    sqlite3_bind_text(st, 3, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, id);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) {
        return std::unexpected(VaultError::DatabaseError);
    }
    return {};
}

std::expected<void, VaultError> Vault::delete_category(std::int64_t id) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    int is_preset = 0;
    if (!uuid_of(impl_->db, "categories", id, &is_preset)) {
        return std::unexpected(VaultError::NotFound);
    }
    if (is_preset) {
        return std::unexpected(VaultError::Forbidden);
    }
    const std::string ts = now_iso8601();
    if (!exec(impl_->db, "BEGIN")) {
        return std::unexpected(VaultError::DatabaseError);
    }
    const bool ok =
        exec_text_int64(impl_->db,
                        "UPDATE categories SET deleted_at=?,revision=revision+1 WHERE id=?", ts,
                        id) &&
        exec_text_int64(impl_->db,
                        "UPDATE categories SET parent_id=NULL,updated_at=?,revision=revision+1 "
                        "WHERE parent_id=? AND deleted_at IS NULL",
                        ts, id) &&
        exec_text_int64(impl_->db,
                        "UPDATE entries SET category_id=NULL,updated_at=?,revision=revision+1 "
                        "WHERE category_id=? AND deleted_at IS NULL",
                        ts, id);
    if (!ok || !exec(impl_->db, "COMMIT")) {
        exec(impl_->db, "ROLLBACK");
        return std::unexpected(VaultError::DatabaseError);
    }
    return {};
}

std::expected<Tag, VaultError> Vault::add_tag(const std::string& name) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    auto existing = list_tags();
    if (!existing) {
        return std::unexpected(existing.error());
    }
    for (auto& t : *existing) {
        if (t.name == name) {
            return std::move(t);
        }
    }
    Tag t;
    t.name = name;
    t.uuid = new_uuid();
    static const char* sql =
        "INSERT INTO tags(name_enc,dek_id,uuid,revision,updated_at) VALUES(?,1,?,1,?)";
    auto id = insert_named(impl_->db, impl_->dek.bytes(), sql, name, t.uuid, std::nullopt, 0, false);
    if (!id) {
        return std::unexpected(VaultError::DatabaseError);
    }
    t.id = *id;
    return t;
}

std::expected<std::vector<Tag>, VaultError> Vault::list_tags() {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    static const char* sql = "SELECT id,name_enc,uuid FROM tags WHERE deleted_at IS NULL ORDER BY id";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    std::vector<Tag> out;
    const auto dek = impl_->dek.bytes();
    while (sqlite3_step(st) == SQLITE_ROW) {
        Tag t;
        t.id = sqlite3_column_int64(st, 0);
        t.uuid = text_col(st, 2);
        auto name = dec_text(dek, blob_col(st, 1), t.uuid, "name");
        if (!name) {
            sqlite3_finalize(st);
            return std::unexpected(VaultError::Corrupt);
        }
        t.name = std::move(*name);
        out.push_back(std::move(t));
    }
    sqlite3_finalize(st);
    return out;
}

std::expected<void, VaultError> Vault::rename_tag(std::int64_t id, const std::string& name) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    const auto uuid = uuid_of(impl_->db, "tags", id, nullptr);
    if (!uuid) {
        return std::unexpected(VaultError::NotFound);
    }
    auto name_enc = enc_text(impl_->dek.bytes(), name, *uuid, "name");
    if (!name_enc) {
        return std::unexpected(VaultError::Internal);
    }
    static const char* sql = "UPDATE tags SET name_enc=?,updated_at=?,revision=revision+1 "
                             "WHERE id=? AND deleted_at IS NULL";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    const std::string ts = now_iso8601();
    bind_blob(st, 1, *name_enc);
    sqlite3_bind_text(st, 2, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, id);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) {
        return std::unexpected(VaultError::DatabaseError);
    }
    return {};
}

std::expected<void, VaultError> Vault::delete_tag(std::int64_t id) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    if (!uuid_of(impl_->db, "tags", id, nullptr)) {
        return std::unexpected(VaultError::NotFound);
    }
    const std::string ts = now_iso8601();
    if (!exec(impl_->db, "BEGIN")) {
        return std::unexpected(VaultError::DatabaseError);
    }
    const bool ok =
        exec_text_int64(impl_->db, "UPDATE tags SET deleted_at=?,revision=revision+1 WHERE id=?",
                        ts, id) &&
        exec_int64(impl_->db, "DELETE FROM entry_tags WHERE tag_id=?", id);
    if (!ok || !exec(impl_->db, "COMMIT")) {
        exec(impl_->db, "ROLLBACK");
        return std::unexpected(VaultError::DatabaseError);
    }
    return {};
}

std::expected<void, VaultError>
Vault::set_entry_tags(std::int64_t entry_id, const std::vector<std::int64_t>& tag_ids) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    if (!uuid_of(impl_->db, "entries", entry_id, nullptr)) {
        return std::unexpected(VaultError::NotFound);
    }
    if (!exec(impl_->db, "BEGIN")) {
        return std::unexpected(VaultError::DatabaseError);
    }
    bool ok = exec_int64(impl_->db, "DELETE FROM entry_tags WHERE entry_id=?", entry_id);
    for (const auto tag_id : tag_ids) {
        ok = ok && exec_int64(impl_->db,
                              "INSERT OR IGNORE INTO entry_tags(entry_id,tag_id) VALUES(?,?)",
                              entry_id, tag_id);
    }
    ok = ok && exec_text_int64(impl_->db,
                               "UPDATE entries SET updated_at=?,revision=revision+1 WHERE id=?",
                               now_iso8601(), entry_id);
    if (!ok || !exec(impl_->db, "COMMIT")) {
        exec(impl_->db, "ROLLBACK");
        return std::unexpected(VaultError::DatabaseError);
    }
    return {};
}

std::expected<std::vector<std::int64_t>, VaultError> Vault::entry_tags(std::int64_t entry_id) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    static const char* sql = "SELECT et.tag_id FROM entry_tags et JOIN tags t ON t.id=et.tag_id "
                             "WHERE et.entry_id=? AND t.deleted_at IS NULL ORDER BY et.tag_id";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    sqlite3_bind_int64(st, 1, entry_id);
    std::vector<std::int64_t> out;
    while (sqlite3_step(st) == SQLITE_ROW) {
        out.push_back(sqlite3_column_int64(st, 0));
    }
    sqlite3_finalize(st);
    return out;
}

std::expected<std::vector<std::pair<std::int64_t, std::int64_t>>, VaultError>
Vault::list_entry_tags() {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    static const char* sql =
        "SELECT et.entry_id,et.tag_id FROM entry_tags et "
        "JOIN tags t ON t.id=et.tag_id JOIN entries e ON e.id=et.entry_id "
        "WHERE t.deleted_at IS NULL AND e.deleted_at IS NULL ORDER BY et.entry_id, et.tag_id";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    std::vector<std::pair<std::int64_t, std::int64_t>> out;
    while (sqlite3_step(st) == SQLITE_ROW) {
        out.emplace_back(sqlite3_column_int64(st, 0), sqlite3_column_int64(st, 1));
    }
    sqlite3_finalize(st);
    return out;
}

namespace {

constexpr std::string_view kSettingsScope = "settings";
constexpr const char* kTrue = "1";
constexpr const char* kFalse = "0";

struct IntSetting {
    const char* key;
    int Settings::* value;
    int minimum;
};

struct BoolSetting {
    const char* key;
    bool Settings::* value;
};

constexpr IntSetting kIntSettings[] = {
    {"log_retention_days", &Settings::log_retention_days, 0},
    {"session_duration_minutes", &Settings::session_duration_minutes, 1},
    {"session_lock_idle_minutes", &Settings::session_lock_idle_minutes, 0},
};

constexpr BoolSetting kBoolSettings[] = {
    {"session_use_os_keyring", &Settings::session_use_os_keyring},
    {"session_lock_on_screensaver", &Settings::session_lock_on_screensaver},
    {"session_require_password_for_export", &Settings::session_require_password_for_export},
};

bool parse_setting(std::string_view text, int minimum, int& out) {
    int v = 0;
    const auto r = std::from_chars(text.data(), text.data() + text.size(), v);
    if (r.ec != std::errc{} || r.ptr != text.data() + text.size() || v < minimum) {
        return false;
    }
    out = v;
    return true;
}

bool parse_setting(std::string_view text, bool& out) {
    if (text != kTrue && text != kFalse) {
        return false;
    }
    out = text == kTrue;
    return true;
}

bool put_setting(sqlite3* db, std::span<const std::uint8_t> dek, const char* key,
                 const std::string& text) {
    const auto enc = enc_text(dek, text, kSettingsScope, key);
    if (!enc) {
        return false;
    }
    static const char* sql = "INSERT INTO settings(key,value_enc,dek_id) VALUES(?,?,1) "
                             "ON CONFLICT(key) DO UPDATE SET value_enc=excluded.value_enc";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
    bind_blob(st, 2, *enc);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

} // namespace

std::expected<Settings, VaultError> Vault::settings() {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, "SELECT key,value_enc FROM settings", -1, &st, nullptr) !=
        SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    Settings out;
    bool corrupt = false;
    while (!corrupt && sqlite3_step(st) == SQLITE_ROW) {
        const std::string key = text_col(st, 0);
        for (const IntSetting& f : kIntSettings) {
            if (key == f.key) {
                const auto text = dec_text(impl_->dek.bytes(), blob_col(st, 1), kSettingsScope, key);
                corrupt = !text || !parse_setting(*text, f.minimum, out.*f.value);
            }
        }
        for (const BoolSetting& f : kBoolSettings) {
            if (key == f.key) {
                const auto text = dec_text(impl_->dek.bytes(), blob_col(st, 1), kSettingsScope, key);
                corrupt = !text || !parse_setting(*text, out.*f.value);
            }
        }
    }
    sqlite3_finalize(st);
    if (corrupt) {
        return std::unexpected(VaultError::Corrupt);
    }
    return out;
}

std::expected<void, VaultError> Vault::set_settings(const Settings& settings) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    for (const IntSetting& f : kIntSettings) {
        if (settings.*f.value < f.minimum) {
            return std::unexpected(VaultError::InvalidValue);
        }
    }
    if (!exec(impl_->db, "BEGIN IMMEDIATE")) {
        return std::unexpected(VaultError::DatabaseError);
    }
    bool ok = true;
    for (const IntSetting& f : kIntSettings) {
        ok = ok && put_setting(impl_->db, impl_->dek.bytes(), f.key, std::to_string(settings.*f.value));
    }
    for (const BoolSetting& f : kBoolSettings) {
        ok = ok && put_setting(impl_->db, impl_->dek.bytes(), f.key, settings.*f.value ? kTrue : kFalse);
    }
    if (!ok || !exec(impl_->db, "COMMIT")) {
        exec(impl_->db, "ROLLBACK");
        return std::unexpected(VaultError::DatabaseError);
    }
    return {};
}

namespace {

constexpr std::string_view kAccessKind = "access";
constexpr char kAccessSeparator = '\n';
constexpr std::int64_t kSecondsPerDay = 24 * 60 * 60;

struct AccessActionName {
    AccessAction action;
    std::string_view name;
};

constexpr AccessActionName kAccessActions[] = {
    {AccessAction::view, "view"},
    {AccessAction::copy, "copy"},
};

std::string_view name_of(AccessAction action) {
    for (const AccessActionName& a : kAccessActions) {
        if (a.action == action) {
            return a.name;
        }
    }
    return {};
}

struct AccessRow {
    std::int64_t id = 0;
    std::string entry_uuid;
    std::optional<AccessAction> action;
    std::int64_t accessed_at = 0;
};

bool parse_access(std::string_view text, AccessRow& row) {
    const auto first = text.find(kAccessSeparator);
    const auto second = first == std::string_view::npos ? first : text.find(kAccessSeparator, first + 1);
    if (second == std::string_view::npos) {
        return false;
    }
    const std::string_view action = text.substr(first + 1, second - first - 1);
    const std::string_view at = text.substr(second + 1);
    const auto r = std::from_chars(at.data(), at.data() + at.size(), row.accessed_at);
    if (first == 0 || r.ec != std::errc{} || r.ptr != at.data() + at.size()) {
        return false;
    }
    row.entry_uuid = std::string(text.substr(0, first));
    row.action.reset();
    for (const AccessActionName& a : kAccessActions) {
        if (a.name == action) {
            row.action = a.action;
        }
    }
    return true;
}

std::expected<std::vector<AccessRow>, VaultError>
read_access_rows(sqlite3* db, std::span<const std::uint8_t> dek) {
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT id,uuid,value_enc FROM access_logs ORDER BY id", -1, &st,
                           nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    std::vector<AccessRow> rows;
    bool corrupt = false;
    while (!corrupt && sqlite3_step(st) == SQLITE_ROW) {
        AccessRow row;
        row.id = sqlite3_column_int64(st, 0);
        const auto text = dec_text(dek, blob_col(st, 2), text_col(st, 1), kAccessKind);
        corrupt = !text || !parse_access(*text, row);
        rows.push_back(std::move(row));
    }
    sqlite3_finalize(st);
    if (corrupt) {
        return std::unexpected(VaultError::Corrupt);
    }
    return rows;
}

std::int64_t oldest_kept(const Settings& settings, std::int64_t now) {
    return now - settings.log_retention_days * kSecondsPerDay;
}

} // namespace

std::expected<void, VaultError>
Vault::record_access(std::int64_t entry_id, AccessAction action, std::int64_t now) {
    const auto current = settings();
    if (!current) {
        return std::unexpected(current.error());
    }
    const auto entry_uuid = uuid_of(impl_->db, "entries", entry_id, nullptr);
    if (!entry_uuid) {
        return std::unexpected(VaultError::NotFound);
    }
    if (current->log_retention_days == 0) {
        return {};
    }
    std::string text = *entry_uuid;
    text += kAccessSeparator;
    text += name_of(action);
    text += kAccessSeparator;
    text += std::to_string(now);
    const std::string uuid = new_uuid();
    const auto enc = enc_text(impl_->dek.bytes(), text, uuid, kAccessKind);
    if (!enc) {
        return std::unexpected(VaultError::Internal);
    }
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, "INSERT INTO access_logs(value_enc,uuid,dek_id) VALUES(?,?,1)", -1, &st,
                           nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    bind_blob(st, 1, *enc);
    sqlite3_bind_text(st, 2, uuid.c_str(), -1, SQLITE_TRANSIENT);
    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok) {
        return std::unexpected(VaultError::DatabaseError);
    }
    return {};
}

std::expected<std::vector<AccessRecord>, VaultError> Vault::access_records(std::int64_t now) {
    const auto current = settings();
    if (!current) {
        return std::unexpected(current.error());
    }
    const auto rows = read_access_rows(impl_->db, impl_->dek.bytes());
    if (!rows) {
        return std::unexpected(rows.error());
    }
    const std::int64_t oldest = oldest_kept(*current, now);
    std::vector<AccessRecord> out;
    for (const AccessRow& row : *rows) {
        if (row.action && row.accessed_at > oldest) {
            out.push_back({row.entry_uuid, *row.action, row.accessed_at});
        }
    }
    return out;
}

std::expected<std::size_t, VaultError> Vault::purge_access_records(std::int64_t now) {
    const auto current = settings();
    if (!current) {
        return std::unexpected(current.error());
    }
    const auto rows = read_access_rows(impl_->db, impl_->dek.bytes());
    if (!rows) {
        return std::unexpected(rows.error());
    }
    const std::int64_t oldest = oldest_kept(*current, now);
    if (!exec(impl_->db, "BEGIN IMMEDIATE")) {
        return std::unexpected(VaultError::DatabaseError);
    }
    std::size_t removed = 0;
    bool ok = true;
    for (const AccessRow& row : *rows) {
        if (ok && row.accessed_at <= oldest) {
            ok = exec_int64(impl_->db, "DELETE FROM access_logs WHERE id=?", row.id);
            ++removed;
        }
    }
    if (!ok || !exec(impl_->db, "COMMIT")) {
        exec(impl_->db, "ROLLBACK");
        return std::unexpected(VaultError::DatabaseError);
    }
    return removed;
}

namespace {

struct EncryptedColumn {
    const char* table;
    const char* scope;
    const char* column;
    const char* kind;
};

constexpr EncryptedColumn kEncryptedColumns[] = {
    {"entries", "uuid", "label_enc", "'label'"},
    {"entries", "uuid", "url_enc", "'url'"},
    {"entries", "uuid", "login_url_enc", "'login_url'"},
    {"entries", "uuid", "display_name_enc", "'display_name'"},
    {"entries", "uuid", "notes_enc", "'notes'"},
    {"fields", "uuid", "label_enc", "'label'"},
    {"fields", "uuid", "value_enc", "'value'"},
    {"fields", "uuid", "notes_enc", "'notes'"},
    {"login_methods", "uuid", "notes_enc", "'notes'"},
    {"categories", "uuid", "name_enc", "'name'"},
    {"tags", "uuid", "name_enc", "'name'"},
    {"settings", "'settings'", "value_enc", "key"},
    {"access_logs", "uuid", "value_enc", "'access'"},
};

struct Reencrypted {
    std::int64_t rowid;
    std::vector<std::uint8_t> blob;
};

std::expected<void, VaultError> reencrypt_column(sqlite3* db, const EncryptedColumn& c,
                                                 std::span<const std::uint8_t> old_dek,
                                                 std::span<const std::uint8_t> new_dek) {
    const std::string select = std::format("SELECT rowid,{},{},{} FROM {} WHERE {} IS NOT NULL", c.scope,
                                           c.kind, c.column, c.table, c.column);
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, select.c_str(), -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    std::vector<Reencrypted> rows;
    std::optional<VaultError> failure;
    while (!failure && sqlite3_step(st) == SQLITE_ROW) {
        const std::vector<std::uint8_t> aad = aad_for(text_col(st, 1), text_col(st, 2));
        const auto plain = aead_decrypt(old_dek, blob_col(st, 3), aad);
        if (!plain) {
            failure = VaultError::Corrupt;
            break;
        }
        auto blob = aead_encrypt(new_dek, plain->bytes(), aad);
        if (!blob) {
            failure = VaultError::Internal;
            break;
        }
        rows.push_back({sqlite3_column_int64(st, 0), std::move(*blob)});
    }
    sqlite3_finalize(st);
    if (failure) {
        return std::unexpected(*failure);
    }
    const std::string update = std::format("UPDATE {} SET {}=? WHERE rowid=?", c.table, c.column);
    if (sqlite3_prepare_v2(db, update.c_str(), -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    bool ok = true;
    for (const Reencrypted& row : rows) {
        bind_blob(st, 1, row.blob);
        sqlite3_bind_int64(st, 2, row.rowid);
        ok = ok && sqlite3_step(st) == SQLITE_DONE;
        sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    if (!ok) {
        return std::unexpected(VaultError::DatabaseError);
    }
    return {};
}

} // namespace

std::expected<void, VaultError> Vault::rotate_key(std::span<const std::uint8_t> password) {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    const auto current = load_material(impl_->db);
    if (!current) {
        return std::unexpected(VaultError::Corrupt);
    }
    const auto verified = unlock_vault(password, *current);
    if (!verified) {
        return std::unexpected(map_key_error(verified.error()));
    }
    auto keys = create_vault_keys(password, current->params);
    if (!keys) {
        return std::unexpected(map_key_error(keys.error()));
    }
    if (!exec(impl_->db, "PRAGMA secure_delete=ON") || !exec(impl_->db, "BEGIN IMMEDIATE")) {
        return std::unexpected(VaultError::DatabaseError);
    }
    for (const EncryptedColumn& c : kEncryptedColumns) {
        const auto done = reencrypt_column(impl_->db, c, impl_->dek.bytes(), keys->first.bytes());
        if (!done) {
            exec(impl_->db, "ROLLBACK");
            return std::unexpected(done.error());
        }
    }
    if (!store_material(impl_->db, keys->second) || !exec(impl_->db, "COMMIT")) {
        exec(impl_->db, "ROLLBACK");
        return std::unexpected(VaultError::DatabaseError);
    }
    impl_->dek = std::move(keys->first);
    if (!exec(impl_->db, "VACUUM")) {
        return std::unexpected(VaultError::ScrubFailed);
    }
    return {};
}

std::expected<std::vector<EntryUrl>, VaultError> Vault::urls() {
    if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    static const char* sql =
        "SELECT f.id,f.entry_id,f.value_enc,f.uuid FROM fields f JOIN entries e ON e.id=f.entry_id "
        "WHERE f.field_type=? AND f.deleted_at IS NULL AND e.deleted_at IS NULL ORDER BY f.id";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &st, nullptr) != SQLITE_OK) {
        return std::unexpected(VaultError::DatabaseError);
    }
    sqlite3_bind_text(st, 1, kUrlFieldType.data(), static_cast<int>(kUrlFieldType.size()),
                      SQLITE_TRANSIENT);
    std::vector<EntryUrl> out;
    bool corrupt = false;
    while (!corrupt && sqlite3_step(st) == SQLITE_ROW) {
        auto value = dec_text(impl_->dek.bytes(), blob_col(st, 2), text_col(st, 3), "value");
        corrupt = !value;
        if (value) {
            out.push_back({sqlite3_column_int64(st, 1), sqlite3_column_int64(st, 0), std::move(*value)});
        }
    }
    sqlite3_finalize(st);
    if (corrupt) {
        return std::unexpected(VaultError::Corrupt);
    }
    return out;
}

namespace {

constexpr const char* kServiceType = "service";
constexpr const char* kAccountType = "account";
constexpr const char* kPersonaType = "persona";

std::string lowered(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

std::string service_key(std::string_view url, std::string_view name) {
    const std::string_view site = import_site(url);
    return lowered(site.empty() ? name : site);
}

std::span<const std::uint8_t> as_bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

} // namespace

std::expected<ImportSummary, VaultError>
Vault::import_logins(std::span<const ImportedLogin> logins, const ImportOptions& options) {
    const auto existing = list_entries();
    if (!existing) {
        return std::unexpected(existing.error());
    }
    const auto known = urls();
    if (!known) {
        return std::unexpected(known.error());
    }
    std::map<std::string, std::int64_t> services;
    std::set<std::int64_t> service_ids;
    std::map<std::int64_t, std::string> login_urls;
    std::set<std::pair<std::int64_t, std::string>> accounts;
    bool persona_found = !options.persona_id.has_value();
    for (const Entry& e : *existing) {
        persona_found = persona_found || (e.id == *options.persona_id && e.entry_type == kPersonaType);
        if (e.entry_type == kServiceType) {
            service_ids.insert(e.id);
            login_urls.emplace(e.id, e.login_url);
            if (const std::string key = service_key(e.url, e.label); !key.empty()) {
                services.emplace(key, e.id);
            }
        } else if (e.entry_type == kAccountType && e.parent_id) {
            accounts.emplace(*e.parent_id, e.label);
        }
    }
    if (!persona_found) {
        return std::unexpected(VaultError::NotFound);
    }
    for (const EntryUrl& url : *known) {
        const std::string key = service_key(url.value, url.value);
        if (service_ids.contains(url.entry_id) && !key.empty()) {
            services.emplace(key, url.entry_id);
        }
    }
    if (!exec(impl_->db, "BEGIN IMMEDIATE")) {
        return std::unexpected(VaultError::DatabaseError);
    }
    ImportSummary summary;
    std::optional<VaultError> failure;
    for (const ImportedLogin& login : logins) {
        const std::string_view secret = totp_secret(login.totp);
        const std::string key = service_key(login.url, login.name);
        if (key.empty() || (login.password.empty() && secret.empty())) {
            ++summary.skipped_empty;
            continue;
        }
        auto service = services.find(key);
        if (service != services.end() && accounts.contains({service->second, std::string(login.username)})) {
            ++summary.skipped_existing;
            continue;
        }
        if (service == services.end()) {
            const std::string_view site = import_site(login.url);
            const std::string origin = import_origin(login.url);
            Entry e;
            e.entry_type = kServiceType;
            if (lowered(login.name) != lowered(site)) {
                e.label = std::string(login.name);
            }
            e.login_url = std::string(login.url);
            const auto added = add_entry(e);
            if (!added) {
                failure = added.error();
                break;
            }
            if (!site.empty()) {
                const auto url = add_field(added->id, options.url_label,
                                               std::string(kUrlFieldType), as_bytes(origin), {});
                if (!url) {
                    failure = url.error();
                    break;
                }
                ++summary.fields;
            }
            service = services.emplace(key, added->id).first;
            login_urls.emplace(added->id, e.login_url);
            ++summary.services;
        }
        Entry account;
        account.entry_type = kAccountType;
        account.parent_id = service->second;
        account.persona_id = options.persona_id;
        account.label = std::string(login.username);
        if (login.url != login_urls[service->second]) {
            account.login_url = std::string(login.url);
        }
        account.notes = std::string(login.notes);
        const auto added = add_entry(account);
        if (!added) {
            failure = added.error();
            break;
        }
        accounts.emplace(service->second, account.label);
        ++summary.accounts;
        if (!login.username.empty()) {
            const std::string& label =
                is_email_shaped(login.username) ? options.email_label : options.id_label;
            const auto field =
                add_field(added->id, label, options.identifier_type, as_bytes(login.username), {});
            if (!field) {
                failure = field.error();
                break;
            }
            ++summary.fields;
        }
        if (!login.password.empty()) {
            const auto field = add_field(added->id, options.password_label, options.password_type,
                                         as_bytes(login.password), {});
            if (!field) {
                failure = field.error();
                break;
            }
            ++summary.fields;
        }
        if (!secret.empty()) {
            const auto field =
                add_field(added->id, options.totp_label, options.totp_type, as_bytes(secret), {});
            if (!field) {
                failure = field.error();
                break;
            }
            ++summary.fields;
        }
    }
    if (failure || !exec(impl_->db, "COMMIT")) {
        exec(impl_->db, "ROLLBACK");
        return std::unexpected(failure.value_or(VaultError::DatabaseError));
    }
    return summary;
}

std::expected<void, VaultError> Vault::merge_service(std::int64_t source_id, std::int64_t target_id) {
    const auto source = get_entry(source_id);
    if (!source) {
        return std::unexpected(source.error());
    }
    const auto target = get_entry(target_id);
    if (!target) {
        return std::unexpected(target.error());
    }
    if (source_id == target_id || source->entry_type != kServiceType ||
        target->entry_type != kServiceType) {
        return std::unexpected(VaultError::Forbidden);
    }
    const auto entries = list_entries();
    if (!entries) {
        return std::unexpected(entries.error());
    }
    const auto known = urls();
    if (!known) {
        return std::unexpected(known.error());
    }
    if (!exec(impl_->db, "BEGIN IMMEDIATE")) {
        return std::unexpected(VaultError::DatabaseError);
    }
    std::optional<VaultError> failure;
    const auto keep = [&](const std::expected<void, VaultError>& done) {
        if (!done && !failure) {
            failure = done.error();
        }
    };

    std::string login_url = target->login_url;
    if (login_url.empty() && !source->login_url.empty()) {
        Entry updated = *target;
        updated.login_url = source->login_url;
        keep(update_entry(updated));
        login_url = source->login_url;
    }
    for (const Entry& e : *entries) {
        if (failure || e.entry_type != kAccountType || e.parent_id != source_id) {
            continue;
        }
        Entry moved = e;
        moved.parent_id = target_id;
        if (moved.login_url.empty() && source->login_url != login_url) {
            moved.login_url = source->login_url;
        }
        keep(update_entry(moved));
    }
    std::set<std::string> present;
    for (const EntryUrl& url : *known) {
        if (url.entry_id == target_id) {
            present.insert(lowered(url.value));
        }
    }
    for (const EntryUrl& url : *known) {
        if (failure || url.entry_id != source_id) {
            continue;
        }
        if (!present.insert(lowered(url.value)).second) {
            keep(delete_field(url.field_id));
        } else if (!exec_int64(impl_->db, "UPDATE fields SET entry_id=?,revision=revision+1 WHERE id=?",
                               target_id, url.field_id)) {
            failure = VaultError::DatabaseError;
        }
    }
    if (!failure) {
        keep(delete_entry(source_id));
    }
    if (failure || !exec(impl_->db, "COMMIT")) {
        exec(impl_->db, "ROLLBACK");
        return std::unexpected(failure.value_or(VaultError::DatabaseError));
    }
    return {};
}

std::expected<void, VaultError> Vault::set_accounts_persona(std::span<const std::int64_t> account_ids,
                                                            std::optional<std::int64_t> persona_id) {
    if (persona_id) {
        const auto persona = get_entry(*persona_id);
        if (!persona) {
            return std::unexpected(persona.error());
        }
        if (persona->entry_type != kPersonaType) {
            return std::unexpected(VaultError::Forbidden);
        }
    } else if (!is_unlocked()) {
        return std::unexpected(VaultError::NotUnlocked);
    }
    std::vector<Entry> accounts;
    for (const std::int64_t id : account_ids) {
        auto account = get_entry(id);
        if (!account) {
            return std::unexpected(account.error());
        }
        if (account->entry_type != kAccountType) {
            return std::unexpected(VaultError::Forbidden);
        }
        accounts.push_back(std::move(*account));
    }
    if (!exec(impl_->db, "BEGIN IMMEDIATE")) {
        return std::unexpected(VaultError::DatabaseError);
    }
    std::optional<VaultError> failure;
    for (Entry& account : accounts) {
        account.persona_id = persona_id;
        if (const auto updated = update_entry(account); !updated) {
            failure = updated.error();
            break;
        }
    }
    if (failure || !exec(impl_->db, "COMMIT")) {
        exec(impl_->db, "ROLLBACK");
        return std::unexpected(failure.value_or(VaultError::DatabaseError));
    }
    return {};
}

} // namespace cypherarx
