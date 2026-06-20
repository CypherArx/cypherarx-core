#include "cypherarx/vault_key.hpp"

#include "cypherarx/crypto.hpp"
#include "cypherarx/kdf.hpp"
#include "cypherarx/secret.hpp"

#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace cypherarx;

std::vector<std::uint8_t> pw(std::string_view s) {
    return {s.begin(), s.end()};
}

bool same(const Secret& a, const Secret& b) {
    return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0;
}

class VaultKeyTest : public ::testing::Test {
protected:
    void SetUp() override { init_crypto(); }
};

TEST_F(VaultKeyTest, CreateThenUnlockRecoversSameDek) {
    auto created = create_vault_keys(pw("master-pass"), KdfParams::interactive());
    ASSERT_TRUE(created.has_value());
    const auto& dek = created->first;
    const auto& mat = created->second;
    EXPECT_EQ(dek.size(), 32u);
    EXPECT_GT(mat.wrapped_dek.size(), dek.size()); // includes AEAD overhead

    const auto unlocked = unlock_vault(pw("master-pass"), mat);
    ASSERT_TRUE(unlocked.has_value());
    EXPECT_TRUE(same(dek, *unlocked));
}

TEST_F(VaultKeyTest, UnlockWithWrongPasswordFails) {
    auto created = create_vault_keys(pw("correct"), KdfParams::interactive()).value();
    const auto r = unlock_vault(pw("wrong"), created.second);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), VaultKeyError::WrongPassword);
}

TEST_F(VaultKeyTest, ChangePasswordKeepsDekAndInvalidatesOld) {
    auto created = create_vault_keys(pw("old-pass"), KdfParams::interactive()).value();
    const Secret& dek = created.first;

    const auto next = change_master_password(pw("old-pass"), created.second,
                                             pw("new-pass"), KdfParams::interactive());
    ASSERT_TRUE(next.has_value());

    // Old password no longer unlocks the new material.
    EXPECT_FALSE(unlock_vault(pw("old-pass"), *next).has_value());

    // New password recovers the SAME DEK (field data never re-encrypted).
    const auto bynew = unlock_vault(pw("new-pass"), *next);
    ASSERT_TRUE(bynew.has_value());
    EXPECT_TRUE(same(dek, *bynew));
}

TEST_F(VaultKeyTest, ChangePasswordWithWrongOldFails) {
    auto created = create_vault_keys(pw("old-pass"), KdfParams::interactive()).value();
    const auto r = change_master_password(pw("nope"), created.second,
                                          pw("new-pass"), KdfParams::interactive());
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), VaultKeyError::WrongPassword);
}

TEST_F(VaultKeyTest, CorruptWrappedDekFailsToUnlock) {
    auto created = create_vault_keys(pw("master"), KdfParams::interactive()).value();
    auto mat = created.second;
    mat.wrapped_dek.back() ^= 0x01;
    const auto r = unlock_vault(pw("master"), mat);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), VaultKeyError::WrongPassword);
}

TEST_F(VaultKeyTest, UnlockWithBadSaltSizeRejected) {
    auto created = create_vault_keys(pw("master"), KdfParams::interactive()).value();
    auto mat = created.second;
    mat.salt.resize(8);
    const auto r = unlock_vault(pw("master"), mat);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), VaultKeyError::InvalidInput);
}

TEST_F(VaultKeyTest, WrapUnwrapRoundTrip) {
    const Secret kek = generate_key();
    const Secret dek = generate_key();

    const auto wrapped = wrap_dek(kek.bytes(), dek.bytes());
    ASSERT_TRUE(wrapped.has_value());

    const auto out = unwrap_dek(kek.bytes(), *wrapped);
    ASSERT_TRUE(out.has_value());
    EXPECT_TRUE(same(dek, *out));

    const Secret other = generate_key();
    EXPECT_FALSE(unwrap_dek(other.bytes(), *wrapped).has_value());
}

} // namespace
