#include "cypherarx/totp.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace cypherarx;

std::vector<std::uint8_t> ascii(std::string_view s) {
    return {s.begin(), s.end()};
}

// RFC 6238 Appendix B seeds.
const std::vector<std::uint8_t> kSeedSha1 = ascii("12345678901234567890");
const std::vector<std::uint8_t> kSeedSha256 = ascii("12345678901234567890123456789012");
const std::vector<std::uint8_t> kSeedSha512 =
    ascii("1234567890123456789012345678901234567890123456789012345678901234");

std::string code(const std::vector<std::uint8_t>& key, std::uint64_t t, TotpAlgorithm alg) {
    auto r = totp_at(key, t, {alg, 8, 30});
    return r.value_or("<error>");
}

TEST(TotpTest, Rfc6238Sha1Vectors) {
    EXPECT_EQ(code(kSeedSha1, 59, TotpAlgorithm::Sha1), "94287082");
    EXPECT_EQ(code(kSeedSha1, 1111111109, TotpAlgorithm::Sha1), "07081804");
    EXPECT_EQ(code(kSeedSha1, 1111111111, TotpAlgorithm::Sha1), "14050471");
    EXPECT_EQ(code(kSeedSha1, 1234567890, TotpAlgorithm::Sha1), "89005924");
    EXPECT_EQ(code(kSeedSha1, 2000000000, TotpAlgorithm::Sha1), "69279037");
    EXPECT_EQ(code(kSeedSha1, 20000000000ULL, TotpAlgorithm::Sha1), "65353130");
}

TEST(TotpTest, Rfc6238Sha256Vectors) {
    EXPECT_EQ(code(kSeedSha256, 59, TotpAlgorithm::Sha256), "46119246");
    EXPECT_EQ(code(kSeedSha256, 1111111109, TotpAlgorithm::Sha256), "68084774");
    EXPECT_EQ(code(kSeedSha256, 1111111111, TotpAlgorithm::Sha256), "67062674");
}

TEST(TotpTest, Rfc6238Sha512Vectors) {
    EXPECT_EQ(code(kSeedSha512, 59, TotpAlgorithm::Sha512), "90693936");
    EXPECT_EQ(code(kSeedSha512, 1234567890, TotpAlgorithm::Sha512), "93441116");
}

TEST(TotpTest, DefaultIsSixDigits) {
    auto r = totp_at(kSeedSha1, 59);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->size(), 6u);
    EXPECT_EQ(*r, "287082"); // last 6 of the 8-digit SHA1 vector
}

TEST(TotpTest, Base32DecodesRfc4648Vector) {
    auto r = base32_decode("MZXW6YTBOI======");
    ASSERT_TRUE(r.has_value());
    const std::string s(r->begin(), r->end());
    EXPECT_EQ(s, "foobar");
}

TEST(TotpTest, Base32IgnoresSpacesAndCase) {
    auto r = base32_decode("mzxw 6ytb oi");
    ASSERT_TRUE(r.has_value());
    const std::string s(r->begin(), r->end());
    EXPECT_EQ(s, "foobar");
}

TEST(TotpTest, Base32RejectsInvalidChar) {
    EXPECT_FALSE(base32_decode("MZXW6YTB0I").has_value()); // '0' is not in base32 alphabet
}

TEST(TotpTest, SecondsRemaining) {
    EXPECT_EQ(totp_seconds_remaining(45, 30), 15u);
    EXPECT_EQ(totp_seconds_remaining(60, 30), 30u);
}

TEST(TotpTest, RejectsEmptyKeyAndBadParams) {
    EXPECT_EQ(totp_at({}, 59).error(), TotpError::InvalidSecret);
    EXPECT_EQ(totp_at(kSeedSha1, 59, {TotpAlgorithm::Sha1, 0, 30}).error(),
              TotpError::InvalidParams);
}

} // namespace
