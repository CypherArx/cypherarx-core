#include "cypherarx/passgen.hpp"

#include "cypherarx/secret.hpp"

#include <cstring>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

namespace {

using namespace cypherarx;

std::string to_string(const Secret& s) {
    return std::string(reinterpret_cast<const char*>(s.data()), s.size());
}

std::size_t count_of(std::string_view pw, std::string_view set) {
    std::size_t n = 0;
    for (char c : pw) {
        if (set.find(c) != std::string_view::npos) {
            ++n;
        }
    }
    return n;
}

class PassgenTest : public ::testing::Test {
protected:
    void SetUp() override { init_crypto(); }
};

TEST_F(PassgenTest, GeneratesExactLength) {
    PasswordPolicy p;
    p.min_length = 24;
    p.max_length = 24;
    auto pw = generate_password(p);
    ASSERT_TRUE(pw.has_value());
    EXPECT_EQ(pw->size(), 24u);
}

TEST_F(PassgenTest, LengthWithinRange) {
    PasswordPolicy p;
    p.min_length = 10;
    p.max_length = 20;
    for (int i = 0; i < 20; ++i) {
        auto pw = generate_password(p);
        ASSERT_TRUE(pw.has_value());
        EXPECT_GE(pw->size(), 10u);
        EXPECT_LE(pw->size(), 20u);
    }
}

TEST_F(PassgenTest, RespectsSingleClass) {
    PasswordPolicy p;
    p.min_length = 32;
    p.max_length = 32;
    p.use_upper = false;
    p.use_lower = false;
    p.use_symbols = false;
    p.use_digits = true;
    auto pw = generate_password(p);
    ASSERT_TRUE(pw.has_value());
    const auto s = to_string(*pw);
    EXPECT_EQ(count_of(s, "0123456789"), s.size());
}

TEST_F(PassgenTest, HonorsMinimumCounts) {
    PasswordPolicy p;
    p.min_length = 20;
    p.max_length = 20;
    p.min_digits = 4;
    p.min_symbols = 2;
    p.allowed_symbols = "!@#";
    auto pw = generate_password(p);
    ASSERT_TRUE(pw.has_value());
    const auto s = to_string(*pw);
    EXPECT_GE(count_of(s, "0123456789"), 4u);
    EXPECT_GE(count_of(s, "!@#"), 2u);
}

TEST_F(PassgenTest, RejectsNoClassEnabled) {
    PasswordPolicy p;
    p.use_upper = p.use_lower = p.use_digits = p.use_symbols = false;
    auto pw = generate_password(p);
    ASSERT_FALSE(pw.has_value());
    EXPECT_EQ(pw.error(), PasswordError::InvalidPolicy);
}

TEST_F(PassgenTest, RejectsMinCountsExceedingLength) {
    PasswordPolicy p;
    p.min_length = 4;
    p.max_length = 4;
    p.min_digits = 3;
    p.min_upper = 3;
    auto pw = generate_password(p);
    ASSERT_FALSE(pw.has_value());
    EXPECT_EQ(pw.error(), PasswordError::InvalidPolicy);
}

TEST_F(PassgenTest, RejectsBadLengthRange) {
    PasswordPolicy p;
    p.min_length = 20;
    p.max_length = 10;
    EXPECT_FALSE(generate_password(p).has_value());
}

TEST_F(PassgenTest, ProducesDifferentPasswords) {
    PasswordPolicy p;
    p.min_length = 32;
    p.max_length = 32;
    const auto a = generate_password(p);
    const auto b = generate_password(p);
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    EXPECT_NE(to_string(*a), to_string(*b));
}

} // namespace
