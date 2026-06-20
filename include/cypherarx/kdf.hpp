#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

#include "cypherarx/secret.hpp"

namespace cypherarx {

/// Failure modes for the key-derivation layer.
enum class KdfError {
    InvalidSaltSize,    ///< Salt is not `kdf::salt_bytes` long.
    InvalidParams,      ///< Could not parse a serialized KdfParams string.
    DerivationFailed,   ///< Argon2id failed (typically could not allocate memlimit).
};

namespace kdf {
inline constexpr std::size_t salt_bytes = 16;  // crypto_pwhash_SALTBYTES
inline constexpr std::size_t kek_bytes = 32;   // == aead::key_bytes
} // namespace kdf

/// Argon2id parameters. Tunable so the dynamic benchmark (design §8/§13) can choose
/// the heaviest setting that still finishes within the time budget on a given machine.
/// Persisted in `crypto_meta.kdf_params` so the vault decrypts on any machine.
struct KdfParams {
    std::uint64_t ops_limit;  ///< Argon2id opslimit (time cost).
    std::size_t mem_limit;    ///< Argon2id memlimit in bytes (memory cost).

    bool operator==(const KdfParams&) const = default;

    // libsodium reference presets (the benchmark interpolates around these).
    static KdfParams interactive();
    static KdfParams moderate();
    static KdfParams sensitive();

    /// Serialize as "argon2id,ops=<n>,mem=<n>" for storage in crypto_meta.
    [[nodiscard]] std::string to_string() const;
    static std::expected<KdfParams, KdfError> from_string(std::string_view text);
};

/// Fill `salt` (must be `kdf::salt_bytes`) with cryptographically secure random bytes.
std::expected<void, KdfError> generate_salt(std::span<std::uint8_t> salt);

/// Derive a `kdf::kek_bytes` KEK from the master password with Argon2id.
/// The result lives in guarded memory.
std::expected<Secret, KdfError>
derive_kek(std::span<const std::uint8_t> password,
           std::span<const std::uint8_t> salt,
           const KdfParams& params);

} // namespace cypherarx
