#include "cypherarx/kdf.hpp"
#include "cypherarx/secret.hpp"

#include <array>
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

std::array<std::uint8_t, kdf::salt_bytes> fixed_salt(std::uint8_t v) {
    std::array<std::uint8_t, kdf::salt_bytes> s{};
    s.fill(v);
    return s;
}

class KdfTest : public ::testing::Test {
protected:
    void SetUp() override { init_crypto(); }
};

TEST_F(KdfTest, DeriveIsDeterministic) {
    const auto salt = fixed_salt(0x11);
    const auto a = derive_kek(pw("correct horse battery staple"), salt, KdfParams::interactive());
    const auto b = derive_kek(pw("correct horse battery staple"), salt, KdfParams::interactive());
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    ASSERT_EQ(a->size(), kdf::kek_bytes);
    EXPECT_EQ(std::memcmp(a->data(), b->data(), a->size()), 0);
}

TEST_F(KdfTest, DifferentSaltGivesDifferentKek) {
    const auto p = pw("master");
    const auto a = derive_kek(p, fixed_salt(0x01), KdfParams::interactive()).value();
    const auto b = derive_kek(p, fixed_salt(0x02), KdfParams::interactive()).value();
    EXPECT_NE(std::memcmp(a.data(), b.data(), kdf::kek_bytes), 0);
}

TEST_F(KdfTest, DifferentPasswordGivesDifferentKek) {
    const auto salt = fixed_salt(0x07);
    const auto a = derive_kek(pw("password-a"), salt, KdfParams::interactive()).value();
    const auto b = derive_kek(pw("password-b"), salt, KdfParams::interactive()).value();
    EXPECT_NE(std::memcmp(a.data(), b.data(), kdf::kek_bytes), 0);
}

TEST_F(KdfTest, RejectsWrongSaltSize) {
    const std::array<std::uint8_t, 8> bad{};
    const auto r = derive_kek(pw("x"), bad, KdfParams::interactive());
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), KdfError::InvalidSaltSize);
}

TEST_F(KdfTest, GenerateSaltFillsAndChecksSize) {
    std::array<std::uint8_t, kdf::salt_bytes> a{};
    std::array<std::uint8_t, kdf::salt_bytes> b{};
    ASSERT_TRUE(generate_salt(a).has_value());
    ASSERT_TRUE(generate_salt(b).has_value());
    EXPECT_NE(a, b);

    std::array<std::uint8_t, 4> bad{};
    const auto r = generate_salt(bad);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), KdfError::InvalidSaltSize);
}

TEST_F(KdfTest, ParamsRoundTrip) {
    const KdfParams p = KdfParams::moderate();
    const auto parsed = KdfParams::from_string(p.to_string());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, p);
}

TEST_F(KdfTest, ParamsParseRejectsGarbage) {
    EXPECT_FALSE(KdfParams::from_string("scrypt,ops=1,mem=2").has_value());
    EXPECT_FALSE(KdfParams::from_string("argon2id,ops=,mem=2").has_value());
    EXPECT_FALSE(KdfParams::from_string("argon2id").has_value());
}

TEST_F(KdfTest, PresetsAreOrdered) {
    EXPECT_LT(KdfParams::interactive().ops_limit, KdfParams::moderate().ops_limit);
    EXPECT_LT(KdfParams::moderate().ops_limit, KdfParams::sensitive().ops_limit);
    EXPECT_LT(KdfParams::interactive().mem_limit, KdfParams::moderate().mem_limit);
    EXPECT_LT(KdfParams::moderate().mem_limit, KdfParams::sensitive().mem_limit);
}

} // namespace
