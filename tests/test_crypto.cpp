#include "cypherarx/crypto.hpp"
#include "cypherarx/secret.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

namespace {

using namespace cypherarx;

std::vector<std::uint8_t> bytes_of(std::string_view s) {
    return {s.begin(), s.end()};
}

class CryptoTest : public ::testing::Test {
protected:
    void SetUp() override { init_crypto(); }
};

TEST_F(CryptoTest, RoundTrip) {
    const Secret key = generate_key();
    const auto plaintext = bytes_of("super secret value");

    const auto blob = aead_encrypt(key.bytes(), plaintext);
    ASSERT_TRUE(blob.has_value());
    EXPECT_EQ(blob->size(), aead::overhead + plaintext.size());
    EXPECT_EQ((*blob)[0], aead::format_version);

    const auto recovered = aead_decrypt(key.bytes(), *blob);
    ASSERT_TRUE(recovered.has_value());
    ASSERT_EQ(recovered->size(), plaintext.size());
    EXPECT_EQ(std::memcmp(recovered->data(), plaintext.data(), plaintext.size()), 0);
}

TEST_F(CryptoTest, RoundTripEmptyPlaintext) {
    const Secret key = generate_key();
    const auto blob = aead_encrypt(key.bytes(), {});
    ASSERT_TRUE(blob.has_value());
    EXPECT_EQ(blob->size(), aead::overhead);

    const auto recovered = aead_decrypt(key.bytes(), *blob);
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(recovered->size(), 0u);
}

TEST_F(CryptoTest, RoundTripWithAad) {
    const Secret key = generate_key();
    const auto plaintext = bytes_of("value");
    const auto aad = bytes_of("entry-uuid|field|label");

    const auto blob = aead_encrypt(key.bytes(), plaintext, aad);
    ASSERT_TRUE(blob.has_value());

    const auto recovered = aead_decrypt(key.bytes(), *blob, aad);
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(std::memcmp(recovered->data(), plaintext.data(), plaintext.size()), 0);
}

TEST_F(CryptoTest, WrongKeyFails) {
    const Secret key = generate_key();
    const Secret other = generate_key();
    const auto blob = aead_encrypt(key.bytes(), bytes_of("data"));
    ASSERT_TRUE(blob.has_value());

    const auto recovered = aead_decrypt(other.bytes(), *blob);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(recovered.error(), CryptoError::DecryptionFailed);
}

TEST_F(CryptoTest, WrongAadFails) {
    const Secret key = generate_key();
    const auto blob = aead_encrypt(key.bytes(), bytes_of("data"), bytes_of("aad-a"));
    ASSERT_TRUE(blob.has_value());

    const auto recovered = aead_decrypt(key.bytes(), *blob, bytes_of("aad-b"));
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(recovered.error(), CryptoError::DecryptionFailed);
}

TEST_F(CryptoTest, TamperedCiphertextFails) {
    const Secret key = generate_key();
    auto blob = aead_encrypt(key.bytes(), bytes_of("data")).value();
    blob.back() ^= 0x01; // corrupt the authentication tag

    const auto recovered = aead_decrypt(key.bytes(), blob);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(recovered.error(), CryptoError::DecryptionFailed);
}

TEST_F(CryptoTest, BadVersionByteIsRejected) {
    const Secret key = generate_key();
    auto blob = aead_encrypt(key.bytes(), bytes_of("data")).value();
    blob[0] = 0xFF; // unknown format version

    const auto recovered = aead_decrypt(key.bytes(), blob);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(recovered.error(), CryptoError::InvalidCiphertext);
}

TEST_F(CryptoTest, TooShortBlobIsRejected) {
    const Secret key = generate_key();
    const std::vector<std::uint8_t> blob(8, 0);
    const auto recovered = aead_decrypt(key.bytes(), blob);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(recovered.error(), CryptoError::InvalidCiphertext);
}

TEST_F(CryptoTest, WrongKeySizeIsRejected) {
    const std::array<std::uint8_t, 16> short_key{};
    const auto blob = aead_encrypt(short_key, bytes_of("data"));
    ASSERT_FALSE(blob.has_value());
    EXPECT_EQ(blob.error(), CryptoError::InvalidKeySize);
}

TEST_F(CryptoTest, NonceIsRandomizedPerEncryption) {
    const Secret key = generate_key();
    const auto plaintext = bytes_of("same plaintext");
    const auto a = aead_encrypt(key.bytes(), plaintext).value();
    const auto b = aead_encrypt(key.bytes(), plaintext).value();
    ASSERT_EQ(a.size(), b.size());
    EXPECT_NE(a, b); // different nonce -> different blob
}

TEST_F(CryptoTest, RandomBytesFillsDistinctValues) {
    std::array<std::uint8_t, 32> a{};
    std::array<std::uint8_t, 32> b{};
    random_bytes(a);
    random_bytes(b);
    EXPECT_NE(a, b);
}

} // namespace
