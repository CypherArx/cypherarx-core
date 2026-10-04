#include "cypherarx/vault.hpp"

#include "cypherarx/entry.hpp"
#include "cypherarx/kdf.hpp"
#include "cypherarx/secret.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace cypherarx;

std::vector<std::uint8_t> bytes(std::string_view s) {
    return {s.begin(), s.end()};
}

class OrganizeTest : public ::testing::Test {
protected:
    std::filesystem::path path_;
    std::optional<Vault> vault_;

    void SetUp() override {
        init_crypto();
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        path_ = std::filesystem::temp_directory_path() /
                ("cypherarx_organize_" + std::string(info->name()) + ".db");
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

    Entry service(std::string label) {
        Entry e;
        e.entry_type = "service";
        e.label = std::move(label);
        return vault_->add_entry(e).value();
    }
};

TEST_F(OrganizeTest, PresetCategoriesAreSeeded) {
    auto cats = vault_->list_categories();
    ASSERT_TRUE(cats.has_value());
    ASSERT_EQ(cats->size(), 7u);
    EXPECT_TRUE(std::ranges::all_of(*cats, [](const Category& c) { return c.is_preset; }));
    EXPECT_EQ((*cats)[0].name, "金融");
    EXPECT_EQ((*cats)[6].name, "その他");
}

TEST_F(OrganizeTest, SeedingIsIdempotentAcrossReopen) {
    vault_.reset();
    auto v = Vault::open(path_, bytes("master-pass"));
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->list_categories()->size(), 7u);
}

TEST_F(OrganizeTest, CustomCategoryTreeAndRename) {
    auto finance = (*vault_->list_categories())[0];
    auto bank = vault_->add_category("銀行", finance.id);
    ASSERT_TRUE(bank.has_value());
    EXPECT_FALSE(bank->is_preset);
    EXPECT_EQ(bank->parent_id, finance.id);

    ASSERT_TRUE(vault_->update_category(bank->id, "Bank", std::nullopt).has_value());
    auto cats = vault_->list_categories().value();
    auto it = std::ranges::find(cats, bank->id, &Category::id);
    ASSERT_NE(it, cats.end());
    EXPECT_EQ(it->name, "Bank");
    EXPECT_FALSE(it->parent_id.has_value());
}

TEST_F(OrganizeTest, PresetCategoryIsReadOnly) {
    auto finance = (*vault_->list_categories())[0];
    EXPECT_EQ(vault_->update_category(finance.id, "x", std::nullopt).error(), VaultError::Forbidden);
    EXPECT_EQ(vault_->delete_category(finance.id).error(), VaultError::Forbidden);
    EXPECT_EQ(vault_->list_categories()->size(), 7u);
}

TEST_F(OrganizeTest, CategoryCannotBeItsOwnParent) {
    auto c = vault_->add_category("loop", std::nullopt).value();
    EXPECT_EQ(vault_->update_category(c.id, "loop", c.id).error(), VaultError::Forbidden);
}

TEST_F(OrganizeTest, DeleteCategoryDetachesChildrenAndEntries) {
    auto parent = vault_->add_category("parent", std::nullopt).value();
    auto child = vault_->add_category("child", parent.id).value();
    Entry e = service("Shop");
    e.category_id = parent.id;
    ASSERT_TRUE(vault_->update_entry(e).has_value());

    ASSERT_TRUE(vault_->delete_category(parent.id).has_value());

    auto cats = vault_->list_categories().value();
    EXPECT_EQ(std::ranges::find(cats, parent.id, &Category::id), cats.end());
    auto it = std::ranges::find(cats, child.id, &Category::id);
    ASSERT_NE(it, cats.end());
    EXPECT_FALSE(it->parent_id.has_value());
    EXPECT_FALSE(vault_->get_entry(e.id)->category_id.has_value());
}

TEST_F(OrganizeTest, EntryCategoryAndFavoriteRoundTrip) {
    auto sns = (*vault_->list_categories())[1];
    Entry e;
    e.entry_type = "service";
    e.label = "X";
    e.category_id = sns.id;
    e.is_favorite = true;
    auto added = vault_->add_entry(e).value();
    auto got = vault_->get_entry(added.id).value();
    EXPECT_EQ(got.category_id, sns.id);
    EXPECT_TRUE(got.is_favorite);

    got.is_favorite = false;
    got.category_id.reset();
    ASSERT_TRUE(vault_->update_entry(got).has_value());
    auto again = vault_->get_entry(added.id).value();
    EXPECT_FALSE(again.is_favorite);
    EXPECT_FALSE(again.category_id.has_value());
}

TEST_F(OrganizeTest, AddTagDeduplicatesByName) {
    auto a = vault_->add_tag("#main").value();
    auto b = vault_->add_tag("#main").value();
    EXPECT_EQ(a.id, b.id);
    auto c = vault_->add_tag("#salary").value();
    EXPECT_NE(a.id, c.id);
    EXPECT_EQ(vault_->list_tags()->size(), 2u);
}

TEST_F(OrganizeTest, EntryTagsSetReplaceAndDelete) {
    Entry e = service("Bank");
    auto t1 = vault_->add_tag("one").value();
    auto t2 = vault_->add_tag("two").value();
    auto t3 = vault_->add_tag("three").value();

    ASSERT_TRUE(vault_->set_entry_tags(e.id, {t1.id, t2.id}).has_value());
    EXPECT_EQ(vault_->entry_tags(e.id).value(), (std::vector<std::int64_t>{t1.id, t2.id}));

    ASSERT_TRUE(vault_->set_entry_tags(e.id, {t2.id, t3.id}).has_value());
    EXPECT_EQ(vault_->entry_tags(e.id).value(), (std::vector<std::int64_t>{t2.id, t3.id}));

    ASSERT_TRUE(vault_->rename_tag(t2.id, "TWO").has_value());
    auto tags = vault_->list_tags().value();
    EXPECT_EQ(std::ranges::find(tags, t2.id, &Tag::id)->name, "TWO");

    ASSERT_TRUE(vault_->delete_tag(t2.id).has_value());
    EXPECT_EQ(vault_->entry_tags(e.id).value(), (std::vector<std::int64_t>{t3.id}));
    EXPECT_EQ(vault_->list_tags()->size(), 2u);
}

TEST_F(OrganizeTest, ListEntryTagsSkipsDeletedEntriesAndTags) {
    Entry a = service("A");
    Entry b = service("B");
    auto t1 = vault_->add_tag("t1").value();
    auto t2 = vault_->add_tag("t2").value();
    ASSERT_TRUE(vault_->set_entry_tags(a.id, {t1.id, t2.id}).has_value());
    ASSERT_TRUE(vault_->set_entry_tags(b.id, {t2.id}).has_value());

    using Pair = std::pair<std::int64_t, std::int64_t>;
    EXPECT_EQ(vault_->list_entry_tags().value(),
              (std::vector<Pair>{{a.id, t1.id}, {a.id, t2.id}, {b.id, t2.id}}));

    ASSERT_TRUE(vault_->delete_entry(b.id).has_value());
    ASSERT_TRUE(vault_->delete_tag(t1.id).has_value());
    EXPECT_EQ(vault_->list_entry_tags().value(), (std::vector<Pair>{{a.id, t2.id}}));
}

TEST_F(OrganizeTest, SetTagsOnMissingEntryFails) {
    EXPECT_EQ(vault_->set_entry_tags(9999, {}).error(), VaultError::NotFound);
}

TEST_F(OrganizeTest, UpdateLoginMethod) {
    Entry github = service("GitHub");
    Entry google = service("Google");
    Entry qiita = service("Qiita");
    auto m = vault_->add_login_method(qiita.id, "github", github.id, "old").value();

    ASSERT_TRUE(vault_->update_login_method(m.id, "google", google.id, "new").has_value());
    auto list = vault_->list_login_methods(qiita.id).value();
    ASSERT_EQ(list.size(), 1u);
    EXPECT_EQ(list[0].method_type, "google");
    EXPECT_EQ(list[0].linked_entry_id, google.id);
    EXPECT_EQ(list[0].notes, "new");

    EXPECT_EQ(vault_->update_login_method(9999, "email", std::nullopt, "").error(),
              VaultError::NotFound);
}

TEST_F(OrganizeTest, OrganizationSurvivesReopen) {
    Entry e = service("Persistent");
    auto cat = vault_->add_category("custom", std::nullopt).value();
    auto tag = vault_->add_tag("sticky").value();
    e.category_id = cat.id;
    ASSERT_TRUE(vault_->update_entry(e).has_value());
    ASSERT_TRUE(vault_->set_entry_tags(e.id, {tag.id}).has_value());
    vault_.reset();

    auto v = Vault::open(path_, bytes("master-pass"));
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->get_entry(e.id)->category_id, cat.id);
    EXPECT_EQ(v->entry_tags(e.id).value(), (std::vector<std::int64_t>{tag.id}));
    auto cats = v->list_categories().value();
    EXPECT_EQ(std::ranges::find(cats, cat.id, &Category::id)->name, "custom");
    EXPECT_EQ(v->list_tags()->at(0).name, "sticky");
}

} // namespace
