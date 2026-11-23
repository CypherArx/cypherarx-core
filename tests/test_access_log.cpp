#include "cypherarx/vault.hpp"

#include "cypherarx/access_log.hpp"
#include "cypherarx/entry.hpp"
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

constexpr std::int64_t kDay = 24 * 60 * 60;
constexpr std::int64_t kNow = 1'800'000'000;

std::vector<std::uint8_t> bytes(std::string_view s) {
    return {s.begin(), s.end()};
}

class AccessLogTest : public ::testing::Test {
protected:
    std::filesystem::path path_;
    std::optional<Vault> vault_;

    void SetUp() override {
        init_crypto();
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        path_ = std::filesystem::temp_directory_path() /
                ("cypherarx_access_" + std::string(info->name()) + ".db");
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
    sqlite3* raw(int flags) {
        sqlite3* db = nullptr;
        const std::u8string utf8 = path_.u8string();
        EXPECT_EQ(sqlite3_open_v2(reinterpret_cast<const char*>(utf8.c_str()), &db, flags, nullptr),
                  SQLITE_OK);
        return db;
    }
    void run_sql(const std::string& sql) {
        vault_.reset();
        sqlite3* db = raw(SQLITE_OPEN_READWRITE);
        EXPECT_EQ(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr), SQLITE_OK);
        sqlite3_close(db);
        reopen();
    }
    std::string raw_dump() {
        std::string out;
        sqlite3* db = raw(SQLITE_OPEN_READONLY);
        sqlite3_stmt* st = nullptr;
        EXPECT_EQ(sqlite3_prepare_v2(db, "SELECT value_enc FROM access_logs", -1, &st, nullptr),
                  SQLITE_OK);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const auto* blob = static_cast<const char*>(sqlite3_column_blob(st, 0));
            out.append(blob, static_cast<std::size_t>(sqlite3_column_bytes(st, 0)));
            out += '\n';
        }
        sqlite3_finalize(st);
        sqlite3_close(db);
        return out;
    }
    int row_count() {
        sqlite3* db = raw(SQLITE_OPEN_READONLY);
        sqlite3_stmt* st = nullptr;
        EXPECT_EQ(sqlite3_prepare_v2(db, "SELECT count(*) FROM access_logs", -1, &st, nullptr),
                  SQLITE_OK);
        EXPECT_EQ(sqlite3_step(st), SQLITE_ROW);
        const int n = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        sqlite3_close(db);
        return n;
    }

    Entry service(std::string label) {
        Entry e;
        e.entry_type = "service";
        e.label = std::move(label);
        return vault_->add_entry(e).value();
    }
};

TEST_F(AccessLogTest, RecordsAreListedOldestFirst) {
    const Entry a = service("A");
    const Entry b = service("B");
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::view, kNow - 30).has_value());
    ASSERT_TRUE(vault_->record_access(b.id, AccessAction::copy, kNow - 20).has_value());
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::copy, kNow - 10).has_value());

    const std::vector<AccessRecord> expected{
        {a.uuid, AccessAction::view, kNow - 30},
        {b.uuid, AccessAction::copy, kNow - 20},
        {a.uuid, AccessAction::copy, kNow - 10},
    };
    EXPECT_EQ(vault_->access_records(kNow).value(), expected);
    reopen();
    EXPECT_EQ(vault_->access_records(kNow).value(), expected);
}

TEST_F(AccessLogTest, UnknownEntryIsNotFound) {
    EXPECT_EQ(vault_->record_access(12345, AccessAction::view, kNow).error(), VaultError::NotFound);
    EXPECT_EQ(row_count(), 0);
}

TEST_F(AccessLogTest, RecordsOlderThanTheRetentionAreNotListed) {
    const Entry a = service("A");
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::view, kNow - 8 * kDay).has_value());
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::view, kNow - 6 * kDay).has_value());
    const auto records = vault_->access_records(kNow).value();
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(records.front().accessed_at, kNow - 6 * kDay);
    EXPECT_EQ(row_count(), 2);
}

TEST_F(AccessLogTest, PurgeDeletesOnlyTheExpiredRecords) {
    const Entry a = service("A");
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::view, kNow - 9 * kDay).has_value());
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::view, kNow - 8 * kDay).has_value());
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::copy, kNow - kDay).has_value());
    EXPECT_EQ(vault_->purge_access_records(kNow).value(), 2u);
    EXPECT_EQ(row_count(), 1);
    EXPECT_EQ(vault_->purge_access_records(kNow).value(), 0u);
    EXPECT_EQ(vault_->access_records(kNow).value().size(), 1u);
}

TEST_F(AccessLogTest, RetentionOfZeroRecordsNothingAndPurgesEverything) {
    const Entry a = service("A");
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::view, kNow).has_value());
    Settings s;
    s.log_retention_days = 0;
    ASSERT_TRUE(vault_->set_settings(s).has_value());
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::copy, kNow).has_value());
    EXPECT_EQ(row_count(), 1);
    EXPECT_TRUE(vault_->access_records(kNow).value().empty());
    EXPECT_EQ(vault_->purge_access_records(kNow).value(), 1u);
    EXPECT_EQ(row_count(), 0);
}

TEST_F(AccessLogTest, LongerRetentionKeepsOlderRecords) {
    const Entry a = service("A");
    Settings s;
    s.log_retention_days = 30;
    ASSERT_TRUE(vault_->set_settings(s).has_value());
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::view, kNow - 20 * kDay).has_value());
    EXPECT_EQ(vault_->access_records(kNow).value().size(), 1u);
    EXPECT_EQ(vault_->purge_access_records(kNow).value(), 0u);
}

TEST_F(AccessLogTest, NothingAboutARecordIsReadableInTheFile) {
    const Entry a = service("A");
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::copy, kNow).has_value());
    const std::string dump = raw_dump();
    EXPECT_EQ(dump.find(a.uuid), std::string::npos);
    EXPECT_EQ(dump.find("copy"), std::string::npos);
    EXPECT_EQ(dump.find(std::to_string(kNow)), std::string::npos);
}

TEST_F(AccessLogTest, TamperedRecordIsCorrupt) {
    const Entry a = service("A");
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::view, kNow).has_value());
    run_sql("UPDATE access_logs SET value_enc=x'00'");
    EXPECT_EQ(vault_->access_records(kNow).error(), VaultError::Corrupt);
    EXPECT_EQ(vault_->purge_access_records(kNow).error(), VaultError::Corrupt);
    EXPECT_EQ(row_count(), 1);
}

TEST_F(AccessLogTest, RecordCopiedOverAnotherRowIsCorrupt) {
    const Entry a = service("A");
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::view, kNow - 10).has_value());
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::copy, kNow - 5).has_value());
    run_sql("UPDATE access_logs SET value_enc=(SELECT value_enc FROM access_logs ORDER BY id LIMIT 1) "
            "WHERE id=(SELECT max(id) FROM access_logs)");
    EXPECT_EQ(vault_->access_records(kNow).error(), VaultError::Corrupt);
}

TEST_F(AccessLogTest, OlderVaultWithoutTheTableGetsItOnOpen) {
    const Entry a = service("A");
    run_sql("DROP TABLE access_logs");
    EXPECT_TRUE(vault_->access_records(kNow).value().empty());
    ASSERT_TRUE(vault_->record_access(a.id, AccessAction::view, kNow).has_value());
    EXPECT_EQ(vault_->access_records(kNow).value().size(), 1u);
}

}
