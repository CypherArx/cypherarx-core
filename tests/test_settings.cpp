#include "cypherarx/vault.hpp"

#include "cypherarx/kdf.hpp"
#include "cypherarx/secret.hpp"
#include "cypherarx/settings.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>
#include <sqlite3.h>

namespace {

using namespace cypherarx;

std::vector<std::uint8_t> bytes(std::string_view s) {
    return {s.begin(), s.end()};
}

class SettingsTest : public ::testing::Test {
protected:
    std::filesystem::path path_;
    std::optional<Vault> vault_;

    void SetUp() override {
        init_crypto();
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        path_ = std::filesystem::temp_directory_path() /
                ("cypherarx_settings_" + std::string(info->name()) + ".db");
        cleanup();
        auto v = Vault::create(path_, bytes("master-pass"), KdfParams::interactive());
        ASSERT_TRUE(v.has_value());
        vault_ = std::move(*v);
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
    }
    void reopen() {
        vault_.reset();
        auto v = Vault::open(path_, bytes("master-pass"));
        ASSERT_TRUE(v.has_value());
        vault_ = std::move(*v);
    }
    void run_sql(const std::string& sql) {
        vault_.reset();
        sqlite3* db = nullptr;
        const std::u8string utf8 = path_.u8string();
        ASSERT_EQ(sqlite3_open_v2(reinterpret_cast<const char*>(utf8.c_str()), &db,
                                  SQLITE_OPEN_READWRITE, nullptr),
                  SQLITE_OK);
        EXPECT_EQ(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr), SQLITE_OK);
        sqlite3_close(db);
        reopen();
    }
    std::string raw_dump() {
        std::string out;
        sqlite3* db = nullptr;
        const std::u8string utf8 = path_.u8string();
        EXPECT_EQ(sqlite3_open_v2(reinterpret_cast<const char*>(utf8.c_str()), &db,
                                  SQLITE_OPEN_READONLY, nullptr),
                  SQLITE_OK);
        sqlite3_stmt* st = nullptr;
        EXPECT_EQ(sqlite3_prepare_v2(db, "SELECT key,value_enc FROM settings", -1, &st, nullptr),
                  SQLITE_OK);
        while (sqlite3_step(st) == SQLITE_ROW) {
            out += reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
            out += '=';
            const auto* blob = static_cast<const char*>(sqlite3_column_blob(st, 1));
            out.append(blob, static_cast<std::size_t>(sqlite3_column_bytes(st, 1)));
            out += '\n';
        }
        sqlite3_finalize(st);
        sqlite3_close(db);
        return out;
    }

    static Settings changed() {
        Settings s;
        s.log_retention_days = 0;
        s.session_duration_minutes = 5;
        s.session_use_os_keyring = false;
        s.session_lock_on_screensaver = false;
        s.session_lock_idle_minutes = 3;
        s.session_require_password_for_export = false;
        return s;
    }
};

TEST_F(SettingsTest, NewVaultHasTheDefaults) {
    const auto s = vault_->settings();
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(*s, Settings{});
}

TEST_F(SettingsTest, RoundTripsAcrossReopen) {
    ASSERT_TRUE(vault_->set_settings(changed()).has_value());
    EXPECT_EQ(vault_->settings().value(), changed());
    reopen();
    EXPECT_EQ(vault_->settings().value(), changed());
}

TEST_F(SettingsTest, LaterWriteReplacesTheEarlierOne) {
    ASSERT_TRUE(vault_->set_settings(changed()).has_value());
    ASSERT_TRUE(vault_->set_settings(Settings{}).has_value());
    EXPECT_EQ(vault_->settings().value(), Settings{});
}

TEST_F(SettingsTest, EveryKeyIsWrittenAndNoValueIsReadable) {
    Settings s;
    s.session_duration_minutes = 4242;
    ASSERT_TRUE(vault_->set_settings(s).has_value());
    const std::string dump = raw_dump();
    for (const char* key :
         {"log_retention_days", "session_duration_minutes", "session_use_os_keyring",
          "session_lock_on_screensaver", "session_lock_idle_minutes",
          "session_require_password_for_export"}) {
        EXPECT_NE(dump.find(std::string(key) + "="), std::string::npos) << key;
    }
    EXPECT_EQ(dump.find("4242"), std::string::npos);
}

TEST_F(SettingsTest, RejectsValuesOutOfRange) {
    Settings s;
    s.log_retention_days = -1;
    EXPECT_EQ(vault_->set_settings(s).error(), VaultError::InvalidValue);
    s = Settings{};
    s.session_duration_minutes = 0;
    EXPECT_EQ(vault_->set_settings(s).error(), VaultError::InvalidValue);
    s = Settings{};
    s.session_lock_idle_minutes = -5;
    EXPECT_EQ(vault_->set_settings(s).error(), VaultError::InvalidValue);
    EXPECT_EQ(vault_->settings().value(), Settings{});
}

TEST_F(SettingsTest, ValueMovedToAnotherKeyIsCorrupt) {
    ASSERT_TRUE(vault_->set_settings(changed()).has_value());
    run_sql("UPDATE settings SET value_enc=(SELECT value_enc FROM settings WHERE "
            "key='session_lock_idle_minutes') WHERE key='session_duration_minutes'");
    EXPECT_EQ(vault_->settings().error(), VaultError::Corrupt);
}

TEST_F(SettingsTest, TamperedValueIsCorrupt) {
    ASSERT_TRUE(vault_->set_settings(changed()).has_value());
    run_sql("UPDATE settings SET value_enc=x'00' WHERE key='log_retention_days'");
    EXPECT_EQ(vault_->settings().error(), VaultError::Corrupt);
}

TEST_F(SettingsTest, MissingAndUnknownKeysAreTolerated) {
    ASSERT_TRUE(vault_->set_settings(changed()).has_value());
    run_sql("DELETE FROM settings WHERE key='session_lock_idle_minutes';"
            "INSERT INTO settings(key,value_enc) VALUES('from_a_newer_version',x'00')");
    Settings expected = changed();
    expected.session_lock_idle_minutes = Settings{}.session_lock_idle_minutes;
    EXPECT_EQ(vault_->settings().value(), expected);
}

TEST_F(SettingsTest, OlderVaultWithoutTheTableGetsItOnOpen) {
    run_sql("DROP TABLE settings");
    EXPECT_EQ(vault_->settings().value(), Settings{});
    ASSERT_TRUE(vault_->set_settings(changed()).has_value());
    EXPECT_EQ(vault_->settings().value(), changed());
}

}
