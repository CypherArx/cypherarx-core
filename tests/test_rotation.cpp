#include "cypherarx/vault.hpp"

#include "cypherarx/access_log.hpp"
#include "cypherarx/entry.hpp"
#include "cypherarx/kdf.hpp"
#include "cypherarx/secret.hpp"
#include "cypherarx/settings.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>
#include <sqlite3.h>

namespace {

using namespace cypherarx;

constexpr std::int64_t kNow = 1'800'000'000;
constexpr std::string_view kEncryptedSuffix = "_enc";
constexpr std::string_view kMetaTable = "crypto_meta";
constexpr std::string_view kWrappedDek = "wrapped_dek";

using Blob = std::vector<std::uint8_t>;

Blob bytes(std::string_view s) {
    return {s.begin(), s.end()};
}

struct Snapshot {
    std::vector<Entry> entries;
    std::vector<Field> fields;
    Blob field_value;
    std::vector<LoginMethod> login_methods;
    std::vector<Category> categories;
    std::vector<Tag> tags;
    Settings settings;
    std::vector<AccessRecord> access;
};

class RotationTest : public ::testing::Test {
protected:
    std::filesystem::path path_;
    std::optional<Vault> vault_;
    std::int64_t account_ = 0;
    std::int64_t field_ = 0;

    void SetUp() override {
        init_crypto();
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        path_ = std::filesystem::temp_directory_path() /
                ("cypherarx_rotation_" + std::string(info->name()) + ".db");
        cleanup();
        auto v = Vault::create(path_, bytes("master-pass"), KdfParams::interactive());
        ASSERT_TRUE(v.has_value());
        vault_ = std::move(*v);
        fill();
    }
    void TearDown() override {
        vault_.reset();
        cleanup();
    }
    void cleanup() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
        std::filesystem::remove(std::filesystem::path(path_) += "-wal", ec);
        std::filesystem::remove(std::filesystem::path(path_) += "-shm", ec);
        std::filesystem::remove(std::filesystem::path(path_) += "-journal", ec);
    }
    void reopen(std::string_view password = "master-pass") {
        vault_.reset();
        auto v = Vault::open(path_, bytes(password));
        ASSERT_TRUE(v.has_value());
        vault_ = std::move(*v);
    }

    void fill() {
        Entry service;
        service.entry_type = "service";
        service.label = "Example";
        service.url = "https://example.com";
        service.login_url = "https://example.com/login";
        service.display_name = "Example Inc.";
        service.notes = "service notes";
        const Entry stored_service = vault_->add_entry(service).value();

        Entry account;
        account.entry_type = "account";
        account.parent_id = stored_service.id;
        account.label = "user@example.com";
        account.url = "https://example.com/me";
        account.login_url = "https://example.com/login";
        account.display_name = "User";
        account.notes = "account notes";
        account_ = vault_->add_entry(account).value().id;

        field_ = vault_->add_field(account_, "password", "password", bytes("s3cret-value"), "field notes")
                     .value()
                     .id;
        ASSERT_TRUE(vault_->add_login_method(account_, "password", std::nullopt, "login notes").has_value());
        ASSERT_TRUE(vault_->add_category("Custom", std::nullopt).has_value());
        const Tag tag = vault_->add_tag("work").value();
        ASSERT_TRUE(vault_->set_entry_tags(account_, {tag.id}).has_value());
        Settings settings;
        settings.session_duration_minutes = 45;
        ASSERT_TRUE(vault_->set_settings(settings).has_value());
        ASSERT_TRUE(vault_->record_access(account_, AccessAction::copy, kNow).has_value());
    }

    Snapshot snapshot() {
        Snapshot s;
        s.entries = vault_->list_entries().value();
        s.fields = vault_->list_fields(account_).value();
        const Secret value = vault_->field_value(field_).value();
        s.field_value.assign(value.bytes().begin(), value.bytes().end());
        s.login_methods = vault_->list_login_methods(account_).value();
        s.categories = vault_->list_categories().value();
        s.tags = vault_->list_tags().value();
        s.settings = vault_->settings().value();
        s.access = vault_->access_records(kNow).value();
        return s;
    }

    static void expect_same(const Snapshot& a, const Snapshot& b) {
        ASSERT_EQ(a.entries.size(), b.entries.size());
        for (std::size_t i = 0; i < a.entries.size(); ++i) {
            EXPECT_EQ(a.entries[i].uuid, b.entries[i].uuid);
            EXPECT_EQ(a.entries[i].label, b.entries[i].label);
            EXPECT_EQ(a.entries[i].url, b.entries[i].url);
            EXPECT_EQ(a.entries[i].login_url, b.entries[i].login_url);
            EXPECT_EQ(a.entries[i].display_name, b.entries[i].display_name);
            EXPECT_EQ(a.entries[i].notes, b.entries[i].notes);
        }
        ASSERT_EQ(a.fields.size(), b.fields.size());
        for (std::size_t i = 0; i < a.fields.size(); ++i) {
            EXPECT_EQ(a.fields[i].label, b.fields[i].label);
            EXPECT_EQ(a.fields[i].notes, b.fields[i].notes);
        }
        EXPECT_EQ(a.field_value, b.field_value);
        ASSERT_EQ(a.login_methods.size(), b.login_methods.size());
        for (std::size_t i = 0; i < a.login_methods.size(); ++i) {
            EXPECT_EQ(a.login_methods[i].notes, b.login_methods[i].notes);
        }
        ASSERT_EQ(a.categories.size(), b.categories.size());
        for (std::size_t i = 0; i < a.categories.size(); ++i) {
            EXPECT_EQ(a.categories[i].name, b.categories[i].name);
        }
        ASSERT_EQ(a.tags.size(), b.tags.size());
        for (std::size_t i = 0; i < a.tags.size(); ++i) {
            EXPECT_EQ(a.tags[i].name, b.tags[i].name);
        }
        EXPECT_EQ(a.settings, b.settings);
        EXPECT_EQ(a.access, b.access);
    }

    sqlite3* raw() {
        sqlite3* db = nullptr;
        const std::u8string utf8 = path_.u8string();
        EXPECT_EQ(sqlite3_open_v2(reinterpret_cast<const char*>(utf8.c_str()), &db, SQLITE_OPEN_READONLY,
                                  nullptr),
                  SQLITE_OK);
        return db;
    }

    static std::vector<std::string> column(sqlite3* db, const std::string& sql, int index) {
        std::vector<std::string> out;
        sqlite3_stmt* st = nullptr;
        EXPECT_EQ(sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr), SQLITE_OK);
        while (sqlite3_step(st) == SQLITE_ROW) {
            out.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(st, index)));
        }
        sqlite3_finalize(st);
        return out;
    }

    std::map<std::string, std::vector<Blob>> encrypted_blobs() {
        std::map<std::string, std::vector<Blob>> out;
        sqlite3* db = raw();
        for (const std::string& table :
             column(db, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", 0)) {
            for (const std::string& name : column(db, "PRAGMA table_info(" + table + ")", 1)) {
                if (!name.ends_with(kEncryptedSuffix)) {
                    continue;
                }
                std::vector<Blob>& blobs = out[table + "." + name];
                sqlite3_stmt* st = nullptr;
                const std::string sql =
                    "SELECT " + name + " FROM " + table + " WHERE " + name + " IS NOT NULL ORDER BY rowid";
                EXPECT_EQ(sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr), SQLITE_OK);
                while (sqlite3_step(st) == SQLITE_ROW) {
                    const auto* p = static_cast<const std::uint8_t*>(sqlite3_column_blob(st, 0));
                    blobs.emplace_back(p, p + sqlite3_column_bytes(st, 0));
                }
                sqlite3_finalize(st);
            }
        }
        sqlite3_close(db);
        return out;
    }

    Blob wrapped_dek() {
        Blob out;
        sqlite3* db = raw();
        sqlite3_stmt* st = nullptr;
        const std::string sql = "SELECT value FROM " + std::string(kMetaTable) + " WHERE key='" +
                                std::string(kWrappedDek) + "'";
        EXPECT_EQ(sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr), SQLITE_OK);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const auto* p = static_cast<const std::uint8_t*>(sqlite3_column_blob(st, 0));
            out.assign(p, p + sqlite3_column_bytes(st, 0));
        }
        sqlite3_finalize(st);
        sqlite3_close(db);
        return out;
    }

    Blob file_bytes() {
        std::ifstream in(path_, std::ios::binary);
        return Blob(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }

    static bool contains(const Blob& haystack, const Blob& needle) {
        return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
    }
};

TEST_F(RotationTest, EverythingReadsTheSameAfterRotation) {
    const Snapshot before = snapshot();
    ASSERT_TRUE(vault_->rotate_key(bytes("master-pass")).has_value());
    expect_same(before, snapshot());
    reopen();
    expect_same(before, snapshot());
}

TEST_F(RotationTest, EveryEncryptedColumnHasDataAndIsReencrypted) {
    const auto before = encrypted_blobs();
    ASSERT_FALSE(before.empty());
    for (const auto& [name, blobs] : before) {
        EXPECT_FALSE(blobs.empty()) << name << " has no data in this test, so it is not covered";
    }
    ASSERT_TRUE(vault_->rotate_key(bytes("master-pass")).has_value());
    const auto after = encrypted_blobs();
    ASSERT_EQ(before.size(), after.size());
    for (const auto& [name, blobs] : before) {
        const std::vector<Blob>& now = after.at(name);
        ASSERT_EQ(blobs.size(), now.size()) << name;
        for (std::size_t i = 0; i < blobs.size(); ++i) {
            EXPECT_NE(blobs[i], now[i]) << name << " row " << i << " kept its old ciphertext";
        }
    }
}

TEST_F(RotationTest, TheWrappedKeyIsReplaced) {
    const Blob before = wrapped_dek();
    ASSERT_FALSE(before.empty());
    ASSERT_TRUE(vault_->rotate_key(bytes("master-pass")).has_value());
    EXPECT_NE(before, wrapped_dek());
}

TEST_F(RotationTest, OldCiphertextIsGoneFromTheFile) {
    const auto before = encrypted_blobs();
    const Blob old_key = wrapped_dek();
    {
        const Blob file = file_bytes();
        ASSERT_TRUE(contains(file, old_key));
        for (const auto& [name, blobs] : before) {
            for (const Blob& blob : blobs) {
                ASSERT_TRUE(contains(file, blob)) << name << " is not found even before the rotation";
            }
        }
    }
    ASSERT_TRUE(vault_->rotate_key(bytes("master-pass")).has_value());
    vault_.reset();
    const Blob file = file_bytes();
    ASSERT_FALSE(file.empty());
    EXPECT_FALSE(contains(file, old_key));
    for (const auto& [name, blobs] : before) {
        for (const Blob& blob : blobs) {
            EXPECT_FALSE(contains(file, blob)) << name;
        }
    }
}

TEST_F(RotationTest, WrongPasswordChangesNothing) {
    const auto blobs = encrypted_blobs();
    const Blob key = wrapped_dek();
    const Snapshot before = snapshot();
    EXPECT_EQ(vault_->rotate_key(bytes("not-the-password")).error(), VaultError::WrongPassword);
    EXPECT_EQ(blobs, encrypted_blobs());
    EXPECT_EQ(key, wrapped_dek());
    expect_same(before, snapshot());
}

TEST_F(RotationTest, CorruptValueStopsTheRotationAndChangesNothing) {
    vault_.reset();
    {
        sqlite3* db = nullptr;
        const std::u8string utf8 = path_.u8string();
        ASSERT_EQ(sqlite3_open_v2(reinterpret_cast<const char*>(utf8.c_str()), &db, SQLITE_OPEN_READWRITE,
                                  nullptr),
                  SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(db, "UPDATE tags SET name_enc=x'00'", nullptr, nullptr, nullptr), SQLITE_OK);
        sqlite3_close(db);
    }
    reopen();
    const auto blobs = encrypted_blobs();
    const Blob key = wrapped_dek();
    EXPECT_EQ(vault_->rotate_key(bytes("master-pass")).error(), VaultError::Corrupt);
    EXPECT_EQ(blobs, encrypted_blobs());
    EXPECT_EQ(key, wrapped_dek());
    EXPECT_EQ(vault_->list_entries().value().size(), 2u);
}

TEST_F(RotationTest, DeletedRowsAreReencryptedToo) {
    ASSERT_TRUE(vault_->delete_field(field_).has_value());
    const auto before = encrypted_blobs();
    ASSERT_TRUE(vault_->rotate_key(bytes("master-pass")).has_value());
    const auto after = encrypted_blobs();
    const std::vector<Blob>& old_values = before.at("fields.value_enc");
    const std::vector<Blob>& new_values = after.at("fields.value_enc");
    ASSERT_EQ(old_values.size(), 1u);
    ASSERT_EQ(new_values.size(), 1u);
    EXPECT_NE(old_values.front(), new_values.front());
}

TEST_F(RotationTest, ChangingThePasswordReplacesTheKeyAndEveryValue) {
    const Snapshot values = snapshot();
    const auto before = encrypted_blobs();
    const Blob old_key = wrapped_dek();
    ASSERT_TRUE(vault_
                    ->change_master_password(bytes("master-pass"), bytes("new-pass"),
                                             KdfParams::interactive())
                    .has_value());
    const auto after = encrypted_blobs();
    ASSERT_EQ(before.size(), after.size());
    for (const auto& [name, blobs] : before) {
        const std::vector<Blob>& now = after.at(name);
        ASSERT_EQ(blobs.size(), now.size()) << name;
        for (std::size_t i = 0; i < blobs.size(); ++i) {
            EXPECT_NE(blobs[i], now[i]) << name << " row " << i << " kept its old ciphertext";
        }
    }
    expect_same(values, snapshot());
    vault_.reset();
    const Blob file = file_bytes();
    EXPECT_FALSE(contains(file, old_key));
    for (const auto& [name, blobs] : before) {
        for (const Blob& blob : blobs) {
            EXPECT_FALSE(contains(file, blob)) << name;
        }
    }
    EXPECT_EQ(Vault::open(path_, bytes("master-pass")).error(), VaultError::WrongPassword);
    reopen("new-pass");
    expect_same(values, snapshot());
}

TEST_F(RotationTest, AWrongOldPasswordChangesNothing) {
    const auto blobs = encrypted_blobs();
    const Blob key = wrapped_dek();
    EXPECT_EQ(vault_
                  ->change_master_password(bytes("not-the-password"), bytes("new-pass"),
                                           KdfParams::interactive())
                  .error(),
              VaultError::WrongPassword);
    EXPECT_EQ(blobs, encrypted_blobs());
    EXPECT_EQ(key, wrapped_dek());
    reopen();
}

TEST_F(RotationTest, WritingAndChangingThePasswordWorkAfterRotation) {
    ASSERT_TRUE(vault_->rotate_key(bytes("master-pass")).has_value());
    ASSERT_TRUE(vault_->add_tag("after").has_value());
    ASSERT_TRUE(vault_
                    ->change_master_password(bytes("master-pass"), bytes("new-pass"),
                                             KdfParams::interactive())
                    .has_value());
    ASSERT_TRUE(vault_->rotate_key(bytes("new-pass")).has_value());
    reopen("new-pass");
    EXPECT_EQ(vault_->list_tags().value().size(), 2u);
    const Secret value = vault_->field_value(field_).value();
    EXPECT_EQ(Blob(value.bytes().begin(), value.bytes().end()), bytes("s3cret-value"));
}

}
