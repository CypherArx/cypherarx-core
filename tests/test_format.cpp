#include "cypherarx/vault.hpp"

#include "cypherarx/entry.hpp"
#include "cypherarx/kdf.hpp"
#include "cypherarx/secret.hpp"

#include <cstdint>
#include <filesystem>
#include <format>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>
#include <sqlite3.h>

namespace {

using namespace cypherarx;

constexpr std::string_view kPassword = "master-pass";
constexpr std::string_view kWrongPassword = "other-pass";
constexpr std::string_view kKeyIdColumn = "dek_id";
constexpr std::string_view kPersonaColumn = "persona_id";
constexpr int kLegacyVersion = 1;
constexpr const char* kKeyIdTables[] = {"entries", "fields", "login_methods", "categories",
                                        "tags",    "access_logs", "settings"};

std::vector<std::uint8_t> bytes(std::string_view s) {
    return {s.begin(), s.end()};
}

class FormatTest : public ::testing::Test {
protected:
    std::filesystem::path path_;
    std::int64_t entry_ = 0;

    void SetUp() override {
        init_crypto();
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        path_ = std::filesystem::temp_directory_path() /
                ("cypherarx_format_" + std::string(info->name()) + ".db");
        cleanup();
        auto v = Vault::create(path_, bytes(kPassword), KdfParams::interactive());
        ASSERT_TRUE(v.has_value());
        Entry e;
        e.entry_type = "service";
        e.label = "Kept";
        const auto added = v->add_entry(e);
        ASSERT_TRUE(added.has_value());
        entry_ = added->id;
        const auto field = v->add_field(entry_, "password", "password", bytes("secret-value"), "");
        ASSERT_TRUE(field.has_value());
    }
    void TearDown() override { cleanup(); }
    void cleanup() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
        std::filesystem::remove(std::filesystem::path(path_) += "-journal", ec);
    }

    sqlite3* raw() {
        sqlite3* db = nullptr;
        const std::u8string utf8 = path_.u8string();
        EXPECT_EQ(sqlite3_open_v2(reinterpret_cast<const char*>(utf8.c_str()), &db, SQLITE_OPEN_READWRITE,
                                  nullptr),
                  SQLITE_OK);
        return db;
    }
    void run(const std::string& sql) {
        sqlite3* db = raw();
        EXPECT_EQ(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr), SQLITE_OK) << sql;
        sqlite3_close(db);
    }
    int number(const std::string& sql) {
        sqlite3* db = raw();
        sqlite3_stmt* st = nullptr;
        int out = -1;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
            out = sqlite3_column_int(st, 0);
        }
        sqlite3_finalize(st);
        sqlite3_close(db);
        return out;
    }
    int version() { return number("PRAGMA user_version"); }
    int columns(std::string_view table, std::string_view column) {
        return number(std::format("SELECT COUNT(*) FROM pragma_table_info('{}') WHERE name='{}'", table, column));
    }
    int key_id_columns() {
        int n = 0;
        for (const char* table : kKeyIdTables) {
            n += columns(table, kKeyIdColumn);
        }
        return n;
    }
    void make_legacy(int stored_version) {
        for (const char* table : kKeyIdTables) {
            run(std::format("ALTER TABLE {} ADD COLUMN {} INTEGER", table, kKeyIdColumn));
            run(std::format("UPDATE {} SET {}=1", table, kKeyIdColumn));
        }
        run(std::format("PRAGMA user_version={}", stored_version));
    }
    void expect_data(Vault& v) {
        const auto e = v.get_entry(entry_);
        ASSERT_TRUE(e.has_value());
        EXPECT_EQ(e->label, "Kept");
        const auto fields = v.list_fields(entry_);
        ASSERT_TRUE(fields.has_value());
        ASSERT_EQ(fields->size(), 1u);
        const auto value = v.field_value((*fields)[0].id);
        ASSERT_TRUE(value.has_value());
        const std::string_view text{reinterpret_cast<const char*>(value->data()), value->size()};
        EXPECT_EQ(text, "secret-value");
    }
};

TEST_F(FormatTest, NewVaultHasCurrentVersionAndNoKeyIdColumn) {
    EXPECT_EQ(version(), kVaultFormatVersion);
    EXPECT_EQ(key_id_columns(), 0);
}

TEST_F(FormatTest, LegacyVaultIsUpgradedOnOpen) {
    make_legacy(kLegacyVersion);
    ASSERT_EQ(key_id_columns(), static_cast<int>(std::size(kKeyIdTables)));
    {
        auto v = Vault::open(path_, bytes(kPassword));
        ASSERT_TRUE(v.has_value());
        expect_data(*v);
        Entry e;
        e.entry_type = "service";
        e.label = "After";
        EXPECT_TRUE(v->add_entry(e).has_value());
    }
    EXPECT_EQ(version(), kVaultFormatVersion);
    EXPECT_EQ(key_id_columns(), 0);
    auto again = Vault::open(path_, bytes(kPassword));
    ASSERT_TRUE(again.has_value());
    expect_data(*again);
}

TEST_F(FormatTest, VaultWithoutStoredVersionIsUpgraded) {
    make_legacy(0);
    run(std::format("ALTER TABLE entries DROP COLUMN {}", kPersonaColumn));
    {
        auto v = Vault::open(path_, bytes(kPassword));
        ASSERT_TRUE(v.has_value());
        expect_data(*v);
    }
    EXPECT_EQ(version(), kVaultFormatVersion);
    EXPECT_EQ(key_id_columns(), 0);
    EXPECT_EQ(columns("entries", kPersonaColumn), 1);
}

TEST_F(FormatTest, WrongPasswordLeavesLegacyVaultUntouched) {
    make_legacy(kLegacyVersion);
    const auto v = Vault::open(path_, bytes(kWrongPassword));
    ASSERT_FALSE(v.has_value());
    EXPECT_EQ(v.error(), VaultError::WrongPassword);
    EXPECT_EQ(version(), kLegacyVersion);
    EXPECT_EQ(key_id_columns(), static_cast<int>(std::size(kKeyIdTables)));
}

TEST_F(FormatTest, NewerVaultIsRefusedAndUntouched) {
    run(std::format("PRAGMA user_version={}", kVaultFormatVersion + 1));
    const auto v = Vault::open(path_, bytes(kPassword));
    ASSERT_FALSE(v.has_value());
    EXPECT_EQ(v.error(), VaultError::NewerFormat);
    EXPECT_EQ(version(), kVaultFormatVersion + 1);
}

}
