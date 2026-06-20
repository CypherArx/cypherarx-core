#include "cypherarx/vault.hpp"

#include "cypherarx/entry.hpp"
#include "cypherarx/kdf.hpp"
#include "cypherarx/secret.hpp"

#include <cstdint>
#include <cstring>
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

Entry make_entry(std::string label, std::string type = "service") {
    Entry e;
    e.entry_type = std::move(type);
    e.label = std::move(label);
    e.url = "https://example.com";
    e.login_url = "https://example.com/login";
    e.notes = "a note";
    return e;
}

class EntriesTest : public ::testing::Test {
protected:
    std::filesystem::path path_;
    std::optional<Vault> vault_;

    void SetUp() override {
        init_crypto();
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        path_ = std::filesystem::temp_directory_path() /
                ("cypherarx_entries_" + std::string(info->name()) + ".db");
        cleanup();
        auto v = Vault::create(path_.string(), bytes("master-pass"), KdfParams::interactive());
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
        std::filesystem::remove(path_.string() + "-wal", ec);
        std::filesystem::remove(path_.string() + "-shm", ec);
    }
};

TEST_F(EntriesTest, AddAndGetEntry) {
    auto added = vault_->add_entry(make_entry("My Bank"));
    ASSERT_TRUE(added.has_value());
    EXPECT_GT(added->id, 0);
    EXPECT_FALSE(added->uuid.empty());

    auto got = vault_->get_entry(added->id);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->label, "My Bank");
    EXPECT_EQ(got->entry_type, "service");
    EXPECT_EQ(got->url, "https://example.com");
    EXPECT_EQ(got->login_url, "https://example.com/login");
    EXPECT_EQ(got->notes, "a note");
    EXPECT_EQ(got->uuid, added->uuid);
}

TEST_F(EntriesTest, GetMissingEntryReturnsNotFound) {
    auto got = vault_->get_entry(9999);
    ASSERT_FALSE(got.has_value());
    EXPECT_EQ(got.error(), VaultError::NotFound);
}

TEST_F(EntriesTest, ListEntries) {
    ASSERT_TRUE(vault_->add_entry(make_entry("A")));
    ASSERT_TRUE(vault_->add_entry(make_entry("B")));
    auto list = vault_->list_entries();
    ASSERT_TRUE(list.has_value());
    ASSERT_EQ(list->size(), 2u);
    EXPECT_EQ((*list)[0].label, "A");
    EXPECT_EQ((*list)[1].label, "B");
}

TEST_F(EntriesTest, UpdateEntry) {
    auto e = vault_->add_entry(make_entry("Old")).value();
    e.label = "New";
    e.notes = "changed";
    ASSERT_TRUE(vault_->update_entry(e).has_value());

    auto got = vault_->get_entry(e.id).value();
    EXPECT_EQ(got.label, "New");
    EXPECT_EQ(got.notes, "changed");
}

TEST_F(EntriesTest, DeleteEntryHidesIt) {
    auto e = vault_->add_entry(make_entry("Doomed")).value();
    ASSERT_TRUE(vault_->delete_entry(e.id).has_value());

    EXPECT_EQ(vault_->get_entry(e.id).error(), VaultError::NotFound);
    EXPECT_TRUE(vault_->list_entries()->empty());
}

TEST_F(EntriesTest, AddFieldAndReadValueOnDemand) {
    auto e = vault_->add_entry(make_entry("Site")).value();

    auto f = vault_->add_field(e.id, "login ID", "text", bytes("secret-value-123"), "memo");
    ASSERT_TRUE(f.has_value());
    EXPECT_GT(f->id, 0);

    auto fields = vault_->list_fields(e.id);
    ASSERT_TRUE(fields.has_value());
    ASSERT_EQ(fields->size(), 1u);
    EXPECT_EQ((*fields)[0].label, "login ID");
    EXPECT_EQ((*fields)[0].field_type, "text");
    EXPECT_EQ((*fields)[0].notes, "memo");

    auto value = vault_->field_value(f->id);
    ASSERT_TRUE(value.has_value());
    ASSERT_EQ(value->size(), std::string_view("secret-value-123").size());
    EXPECT_EQ(std::memcmp(value->data(), "secret-value-123", value->size()), 0);
}

TEST_F(EntriesTest, UpdateField) {
    auto e = vault_->add_entry(make_entry("Site")).value();
    auto f = vault_->add_field(e.id, "login ID", "text", bytes("old-value"), "old memo").value();

    ASSERT_TRUE(
        vault_->update_field(f.id, "password", "password", bytes("new-secret"), "new memo")
            .has_value());

    auto fields = vault_->list_fields(e.id);
    ASSERT_TRUE(fields.has_value());
    ASSERT_EQ(fields->size(), 1u);
    EXPECT_EQ((*fields)[0].label, "password");
    EXPECT_EQ((*fields)[0].field_type, "password");
    EXPECT_EQ((*fields)[0].notes, "new memo");

    auto value = vault_->field_value(f.id);
    ASSERT_TRUE(value.has_value());
    ASSERT_EQ(value->size(), std::string_view("new-secret").size());
    EXPECT_EQ(std::memcmp(value->data(), "new-secret", value->size()), 0);
}

TEST_F(EntriesTest, UpdateMissingFieldReturnsNotFound) {
    auto r = vault_->update_field(9999, "x", "text", bytes("v"), "");
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), VaultError::NotFound);
}

TEST_F(EntriesTest, DeleteFieldHidesIt) {
    auto e = vault_->add_entry(make_entry("Site")).value();
    auto f = vault_->add_field(e.id, "pw", "password", bytes("p"), "").value();

    ASSERT_TRUE(vault_->delete_field(f.id).has_value());
    EXPECT_TRUE(vault_->list_fields(e.id)->empty());
    EXPECT_EQ(vault_->field_value(f.id).error(), VaultError::NotFound);
}

TEST_F(EntriesTest, DataSurvivesReopen) {
    auto e = vault_->add_entry(make_entry("Persistent")).value();
    ASSERT_TRUE(vault_->add_field(e.id, "k", "text", bytes("v"), ""));
    vault_.reset(); // close the file

    auto reopened = Vault::open(path_.string(), bytes("master-pass"));
    ASSERT_TRUE(reopened.has_value());

    auto list = reopened->list_entries();
    ASSERT_TRUE(list.has_value());
    ASSERT_EQ(list->size(), 1u);
    EXPECT_EQ((*list)[0].label, "Persistent");

    auto fields = reopened->list_fields((*list)[0].id);
    ASSERT_TRUE(fields.has_value());
    ASSERT_EQ(fields->size(), 1u);
    auto value = reopened->field_value((*fields)[0].id);
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(std::memcmp(value->data(), "v", 1), 0);
}

} // namespace
