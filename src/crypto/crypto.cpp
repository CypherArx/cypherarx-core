#include "cypherarx/crypto.hpp"

#include <array>
#include <string>

#include <sodium.h>

namespace cypherarx {

static_assert(aead::key_bytes == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
static_assert(aead::nonce_bytes == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
static_assert(aead::tag_bytes == crypto_aead_xchacha20poly1305_ietf_ABYTES);

void random_bytes(std::span<std::uint8_t> buf) {
    if (!buf.empty()) {
        randombytes_buf(buf.data(), buf.size());
    }
}

Secret generate_key() {
    Secret key(aead::key_bytes);
    randombytes_buf(key.data(), key.size());
    return key;
}

std::string new_uuid() {
    std::array<std::uint8_t, 16> b{};
    randombytes_buf(b.data(), b.size());
    b[6] = static_cast<std::uint8_t>((b[6] & 0x0F) | 0x40); // version 4
    b[8] = static_cast<std::uint8_t>((b[8] & 0x3F) | 0x80); // variant 1

    static constexpr char hex[] = "0123456789abcdef";
    std::string s;
    s.reserve(36);
    for (std::size_t i = 0; i < b.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            s.push_back('-');
        }
        s.push_back(hex[b[i] >> 4]);
        s.push_back(hex[b[i] & 0x0F]);
    }
    return s;
}

std::expected<std::vector<std::uint8_t>, CryptoError>
aead_encrypt(std::span<const std::uint8_t> key,
             std::span<const std::uint8_t> plaintext,
             std::span<const std::uint8_t> aad) {
    if (key.size() != aead::key_bytes) {
        return std::unexpected(CryptoError::InvalidKeySize);
    }

    std::vector<std::uint8_t> out(aead::overhead + plaintext.size());
    out[0] = aead::format_version;
    std::uint8_t* const nonce = out.data() + 1;
    randombytes_buf(nonce, aead::nonce_bytes);

    unsigned long long cipher_len = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        out.data() + 1 + aead::nonce_bytes, &cipher_len,
        plaintext.data(), plaintext.size(),
        aad.data(), aad.size(),
        nullptr, nonce, key.data());
    if (rc != 0) {
        return std::unexpected(CryptoError::InternalError);
    }

    out.resize(1 + aead::nonce_bytes + static_cast<std::size_t>(cipher_len));
    return out;
}

std::expected<Secret, CryptoError>
aead_decrypt(std::span<const std::uint8_t> key,
             std::span<const std::uint8_t> blob,
             std::span<const std::uint8_t> aad) {
    if (key.size() != aead::key_bytes) {
        return std::unexpected(CryptoError::InvalidKeySize);
    }
    if (blob.size() < aead::overhead || blob[0] != aead::format_version) {
        return std::unexpected(CryptoError::InvalidCiphertext);
    }

    const std::uint8_t* const nonce = blob.data() + 1;
    const std::uint8_t* const cipher = blob.data() + 1 + aead::nonce_bytes;
    const std::size_t cipher_len = blob.size() - 1 - aead::nonce_bytes;

    Secret plaintext(cipher_len - aead::tag_bytes);
    unsigned long long message_len = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(), &message_len, nullptr,
        cipher, cipher_len,
        aad.data(), aad.size(),
        nonce, key.data());
    if (rc != 0) {
        return std::unexpected(CryptoError::DecryptionFailed);
    }

    return plaintext;
}

} // namespace cypherarx
