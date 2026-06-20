#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

#include "cypherarx/secret.hpp"

namespace cypherarx {

/// Failure modes for the authenticated-encryption layer.
enum class CryptoError {
    InvalidKeySize,     ///< Key is not `aead::key_bytes` long.
    InvalidCiphertext,  ///< Blob too short, or unknown format version.
    DecryptionFailed,   ///< Authentication tag mismatch (wrong key/AAD or tampering).
    InternalError,      ///< libsodium returned an unexpected error.
};

namespace aead {

// CypherArx uses XChaCha20-Poly1305 (IETF) as its authenticated cipher:
// it is constant-time in pure software on every platform (unlike libsodium's
// AES-256-GCM, which needs x86 AES-NI and is unavailable on Apple Silicon / ARM),
// and its 24-byte nonce makes random nonces collision-safe.
inline constexpr std::size_t key_bytes = 32;    // crypto_aead_xchacha20poly1305_ietf_KEYBYTES
inline constexpr std::size_t nonce_bytes = 24;  // ..._NPUBBYTES
inline constexpr std::size_t tag_bytes = 16;    // ..._ABYTES

/// First byte of every stored blob, so the on-disk format can evolve
/// (e.g. introduce a different cipher) without ambiguity.
inline constexpr std::uint8_t format_version = 1;

/// Layout of an encrypted blob: version(1) || nonce(24) || ciphertext || tag(16).
inline constexpr std::size_t overhead = 1 + nonce_bytes + tag_bytes;

} // namespace aead

/// Fill `buf` with cryptographically secure random bytes.
void random_bytes(std::span<std::uint8_t> buf);

/// Generate a fresh random `aead::key_bytes` key in guarded memory.
Secret generate_key();

/// Generate a random RFC-4122 version-4 UUID string (e.g. for cross-device ids).
std::string new_uuid();

/// Encrypt `plaintext` with `key`, authenticating `aad`. Returns a self-describing
/// blob (version || nonce || ciphertext || tag) with a fresh random nonce.
std::expected<std::vector<std::uint8_t>, CryptoError>
aead_encrypt(std::span<const std::uint8_t> key,
             std::span<const std::uint8_t> plaintext,
             std::span<const std::uint8_t> aad = {});

/// Decrypt and verify a blob produced by `aead_encrypt`. The recovered plaintext
/// is returned in guarded memory. `aad` must match what was used to encrypt.
std::expected<Secret, CryptoError>
aead_decrypt(std::span<const std::uint8_t> key,
             std::span<const std::uint8_t> blob,
             std::span<const std::uint8_t> aad = {});

} // namespace cypherarx
