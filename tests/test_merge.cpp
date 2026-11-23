#include "cypherarx/vault.hpp"

#include "cypherarx/entry.hpp"
#include "cypherarx/kdf.hpp"
#include "cypherarx/secret.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace cypherarx;

std::vector<std::uint8_t> bytes(std::string_view s) {
    return {s.begin(), s.end()};
}

class MergeTest : public ::testing::Test {
protected:
    std::filesystem::path path_;
    std::optional<Vault> vault_;

    void SetUp() override {
        init_crypto();
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        path_ = std::filesystem::temp_directory_path() /
                ("cypherarx_merge_" + std::string(info->name()) + ".db");
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
        std::filesystem::remove(std::filesystem::path(path_) += "-journal", ec);
    }

    Entry service(std::string label, std::string login_url = {}) {
        Entry e;
        e.entry_type = "service";
        e.label = std::move(label);
        e.login_url = std::move(login_url);
        return vault_->add_entry(e).value();
    }
    Entry account(std::int64_t parent, std::string label, std::string login_url = {}) {
        Entry e;
        e.entry_type = "account";
        e.parent_id = parent;
        e.label = std::move(label);
        e.login_url = std::move(login_url);
        return vault_->add_entry(e).value();
    }
    void url(std::int64_t entry, std::string_view value) {
        ASSERT_TRUE(vault_->add_field(entry, "URL", std::string(kUrlFieldType), bytes(value), "").has_value());
    }
    std::vector<std::string> urls_of(std::int64_t entry) {
        std::vector<std::string> out;
        for (const EntryUrl& u : vault_->urls().value()) {
            if (u.entry_id == entry) {
                out.push_back(u.value);
            }
        }
        return out;
    }
};

TEST_F(MergeTest, MovesTheAccountsAndRemovesTheSource) {
    const Entry x = service("X");
    const Entry dotcom = service("");
    const Entry a = account(x.id, "first");
    const Entry b = account(dotcom.id, "second");
    const Entry c = account(dotcom.id, "third");

    ASSERT_TRUE(vault_->merge_service(dotcom.id, x.id).has_value());

    EXPECT_EQ(vault_->get_entry(dotcom.id).error(), VaultError::NotFound);
    EXPECT_EQ(vault_->get_entry(x.id).value().label, "X");
    for (const std::int64_t id : {a.id, b.id, c.id}) {
        EXPECT_EQ(vault_->get_entry(id).value().parent_id, x.id);
    }
    EXPECT_EQ(vault_->get_entry(b.id).value().label, "second");
}

TEST_F(MergeTest, TheTargetGetsTheSourcesUrlsOnce) {
    const Entry x = service("X");
    const Entry dotcom = service("");
    url(x.id, "https://x.com");
    url(dotcom.id, "https://X.com");
    url(dotcom.id, "https://twitter.com");

    ASSERT_TRUE(vault_->merge_service(dotcom.id, x.id).has_value());

    EXPECT_EQ(urls_of(x.id), (std::vector<std::string>{"https://x.com", "https://twitter.com"}));
    EXPECT_TRUE(urls_of(dotcom.id).empty());
    EXPECT_EQ(vault_->list_fields(x.id).value().size(), 2u);
}

TEST_F(MergeTest, TheTargetTakesTheLoginUrlWhenItHasNone) {
    const Entry x = service("X");
    const Entry dotcom = service("", "https://x.com/login");
    const Entry a = account(dotcom.id, "me");

    ASSERT_TRUE(vault_->merge_service(dotcom.id, x.id).has_value());

    EXPECT_EQ(vault_->get_entry(x.id).value().login_url, "https://x.com/login");
    EXPECT_TRUE(vault_->get_entry(a.id).value().login_url.empty());
}

TEST_F(MergeTest, AccountsKeepTheLoginUrlTheyHadThroughTheirService) {
    const Entry x = service("X", "https://x.com/login");
    const Entry other = service("Other", "https://x.com/i/flow/login");
    const Entry inherits = account(other.id, "inherits");
    const Entry own = account(other.id, "own", "https://x.com/admin/login");
    const Entry already = account(x.id, "already");

    ASSERT_TRUE(vault_->merge_service(other.id, x.id).has_value());

    EXPECT_EQ(vault_->get_entry(x.id).value().login_url, "https://x.com/login");
    EXPECT_EQ(vault_->get_entry(inherits.id).value().login_url, "https://x.com/i/flow/login");
    EXPECT_EQ(vault_->get_entry(own.id).value().login_url, "https://x.com/admin/login");
    EXPECT_TRUE(vault_->get_entry(already.id).value().login_url.empty());
}

TEST_F(MergeTest, RefusesAnythingButTwoDifferentServices) {
    const Entry x = service("X");
    const Entry a = account(x.id, "me");
    EXPECT_EQ(vault_->merge_service(x.id, x.id).error(), VaultError::Forbidden);
    EXPECT_EQ(vault_->merge_service(a.id, x.id).error(), VaultError::Forbidden);
    EXPECT_EQ(vault_->merge_service(x.id, a.id).error(), VaultError::Forbidden);
    EXPECT_EQ(vault_->merge_service(x.id, 987654).error(), VaultError::NotFound);
    EXPECT_EQ(vault_->merge_service(987654, x.id).error(), VaultError::NotFound);
    EXPECT_EQ(vault_->list_entries().value().size(), 2u);
    EXPECT_EQ(vault_->get_entry(a.id).value().parent_id, x.id);
}

TEST_F(MergeTest, TheMergedDataSurvivesReopening) {
    const Entry x = service("X");
    const Entry dotcom = service("");
    url(dotcom.id, "https://x.com");
    const Entry a = account(dotcom.id, "me");
    ASSERT_TRUE(vault_->merge_service(dotcom.id, x.id).has_value());
    vault_.reset();
    auto v = Vault::open(path_, bytes("master-pass"));
    ASSERT_TRUE(v.has_value());
    vault_ = std::move(*v);
    EXPECT_EQ(vault_->get_entry(a.id).value().parent_id, x.id);
    EXPECT_EQ(urls_of(x.id), (std::vector<std::string>{"https://x.com"}));
    EXPECT_EQ(vault_->list_entries().value().size(), 2u);
}

}
