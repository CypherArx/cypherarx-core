#include "cypherarx/secret.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <sstream>
#include <utility>

#include <gtest/gtest.h>

using cypherarx::Secret;

namespace {

// Initialize libsodium once for the whole test binary.
class CryptoEnvironment : public ::testing::Environment {
public:
    void SetUp() override { cypherarx::init_crypto(); }
};

[[maybe_unused]] const auto* const kCryptoEnv =
    ::testing::AddGlobalTestEnvironment(new CryptoEnvironment);

} // namespace

TEST(SecretTest, InitCryptoIsIdempotent) {
    EXPECT_NO_THROW(cypherarx::init_crypto());
    EXPECT_NO_THROW(cypherarx::init_crypto());
}

TEST(SecretTest, DefaultConstructedIsEmpty) {
    Secret s;
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.size(), 0u);
    EXPECT_EQ(s.data(), nullptr);
}

TEST(SecretTest, AllocatesRequestedSize) {
    Secret s(32);
    EXPECT_FALSE(s.empty());
    EXPECT_EQ(s.size(), 32u);
    ASSERT_NE(s.data(), nullptr);
}

TEST(SecretTest, StoresAndReadsBytes) {
    const std::array<std::uint8_t, 4> in{0xDE, 0xAD, 0xBE, 0xEF};
    Secret s{std::span<const std::uint8_t>{in}};
    ASSERT_EQ(s.size(), in.size());
    EXPECT_EQ(std::memcmp(s.data(), in.data(), in.size()), 0);
}

TEST(SecretTest, MoveConstructTransfersOwnership) {
    Secret a(16);
    auto* const raw = a.data();

    Secret b(std::move(a));
    EXPECT_EQ(b.size(), 16u);
    EXPECT_EQ(b.data(), raw);
    EXPECT_TRUE(a.empty());        // NOLINT(bugprone-use-after-move): asserting moved-from state
    EXPECT_EQ(a.data(), nullptr);  // NOLINT(bugprone-use-after-move)
}

TEST(SecretTest, MoveAssignReplacesPrevious) {
    Secret a(8);
    Secret b(24);

    b = std::move(a);
    EXPECT_EQ(b.size(), 8u);
    EXPECT_TRUE(a.empty());        // NOLINT(bugprone-use-after-move)
}

TEST(SecretTest, StreamingIsRedacted) {
    Secret s(8);
    std::ostringstream os;
    os << s;
    EXPECT_EQ(os.str(), "[REDACTED]");
}
