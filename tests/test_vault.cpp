#include "cypherarx/vault.hpp"

#include "cypherarx/kdf.hpp"
#include "cypherarx/secret.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace cypherarx;

std::vector<std::uint8_t> pw(std::string_view s) {
    return {s.begin(), s.end()};
}

class VaultFileTest : public ::testing::Test {
protected:
    std::filesystem::path path_;

    void SetUp() override {
        init_crypto();
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        path_ = std::filesystem::temp_directory_path() /
                ("cypherarx_test_" + std::string(info->name()) + ".db");
        cleanup();
    }
    void TearDown() override { cleanup(); }

    void cleanup() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
        std::filesystem::remove(std::filesystem::path(path_) += "-wal", ec);
        std::filesystem::remove(std::filesystem::path(path_) += "-shm", ec);
    }

    const std::filesystem::path& path() const { return path_; }
};

TEST_F(VaultFileTest, CreateLeavesVaultUnlocked) {
    auto v = Vault::create(path(), pw("master-pass"), KdfParams::interactive());
    ASSERT_TRUE(v.has_value());
    EXPECT_TRUE(v->is_unlocked());
    EXPECT_TRUE(std::filesystem::exists(path_));
}

TEST_F(VaultFileTest, NonAsciiPathRoundTrip) {
    path_ = std::filesystem::temp_directory_path() / std::filesystem::path(u8"cypherarx_金庫_テスト.db");
    cleanup();
    { ASSERT_TRUE(Vault::create(path(), pw("master-pass"), KdfParams::interactive())); }
    EXPECT_TRUE(std::filesystem::exists(path_));

    auto v = Vault::open(path(), pw("master-pass"));
    ASSERT_TRUE(v.has_value());
    EXPECT_TRUE(v->is_unlocked());
}

TEST_F(VaultFileTest, CreateThenReopenWithPassword) {
    { ASSERT_TRUE(Vault::create(path(), pw("master-pass"), KdfParams::interactive())); }

    auto v = Vault::open(path(), pw("master-pass"));
    ASSERT_TRUE(v.has_value());
    EXPECT_TRUE(v->is_unlocked());
}

TEST_F(VaultFileTest, OpenWithWrongPasswordFails) {
    { ASSERT_TRUE(Vault::create(path(), pw("correct"), KdfParams::interactive())); }

    auto v = Vault::open(path(), pw("wrong"));
    ASSERT_FALSE(v.has_value());
    EXPECT_EQ(v.error(), VaultError::WrongPassword);
}

TEST_F(VaultFileTest, CreateRejectsExistingFile) {
    ASSERT_TRUE(Vault::create(path(), pw("master"), KdfParams::interactive()));
    auto again = Vault::create(path(), pw("master"), KdfParams::interactive());
    ASSERT_FALSE(again.has_value());
    EXPECT_EQ(again.error(), VaultError::AlreadyInitialized);
}

TEST_F(VaultFileTest, OpenMissingFileFails) {
    auto v = Vault::open(path(), pw("master"));
    ASSERT_FALSE(v.has_value());
    EXPECT_EQ(v.error(), VaultError::NotInitialized);
}

TEST_F(VaultFileTest, ChangePasswordThenReopenWithNew) {
    {
        auto v = Vault::create(path(), pw("old-pass"), KdfParams::interactive());
        ASSERT_TRUE(v.has_value());
        const auto changed = v->change_master_password(pw("old-pass"), pw("new-pass"),
                                                       KdfParams::interactive());
        ASSERT_TRUE(changed.has_value());
    }

    EXPECT_FALSE(Vault::open(path(), pw("old-pass")).has_value());
    EXPECT_TRUE(Vault::open(path(), pw("new-pass")).has_value());
}

TEST_F(VaultFileTest, ChangePasswordWithWrongOldFails) {
    auto v = Vault::create(path(), pw("old-pass"), KdfParams::interactive());
    ASSERT_TRUE(v.has_value());
    const auto changed = v->change_master_password(pw("nope"), pw("new-pass"),
                                                   KdfParams::interactive());
    ASSERT_FALSE(changed.has_value());
    EXPECT_EQ(changed.error(), VaultError::WrongPassword);
}

} // namespace
