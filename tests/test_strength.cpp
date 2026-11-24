#include "cypherarx/strength.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace cypherarx;

PasswordStrength measure(std::string_view s) {
    const std::vector<std::uint8_t> bytes(s.begin(), s.end());
    return master_password_strength(bytes);
}

TEST(StrengthTest, AnEmptyPasswordIsTooShort) {
    const PasswordStrength s = measure("");
    EXPECT_EQ(s.length, 0u);
    EXPECT_EQ(s.score, 0);
    EXPECT_EQ(s.verdict, PasswordVerdict::TooShort);
}

TEST(StrengthTest, UnderTwelveCharactersIsTooShortHoweverRandom) {
    EXPECT_EQ(measure("q7#Lw9$Zx2!").verdict, PasswordVerdict::TooShort);
}

TEST(StrengthTest, LengthCountsCharactersNotBytes) {
    const PasswordStrength s = measure("\xE3\x81\x82\xE3\x81\x84\xE3\x81\x86");
    EXPECT_EQ(s.length, 3u);
}

TEST(StrengthTest, ALongButGuessablePasswordIsRejected) {
    const PasswordStrength s = measure("password1234");
    EXPECT_GE(s.length, kMasterPasswordMinLength);
    EXPECT_LE(s.score, 1);
    EXPECT_EQ(s.verdict, PasswordVerdict::Rejected);
}

TEST(StrengthTest, ARepeatedCharacterIsRejected) {
    EXPECT_EQ(measure("aaaaaaaaaaaaaaaa").verdict, PasswordVerdict::Rejected);
}

TEST(StrengthTest, ALongRandomPasswordIsOk) {
    const PasswordStrength s = measure("vQ8#rT2m!Zx6pL9wKd4s");
    EXPECT_EQ(s.score, 4);
    EXPECT_EQ(s.verdict, PasswordVerdict::Ok);
}

TEST(StrengthTest, APassphraseOfUnrelatedWordsIsOk) {
    EXPECT_EQ(measure("correct horse battery staple").verdict, PasswordVerdict::Ok);
}

TEST(StrengthTest, AddingRandomCharactersDoesNotLowerTheEstimate) {
    EXPECT_LT(measure("vQ8#rT2m!Zx6").guesses_log10, measure("vQ8#rT2m!Zx6pL9wKd4s").guesses_log10);
}

}
