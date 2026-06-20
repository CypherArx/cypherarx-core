#include "cypherarx/crypto.hpp"

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
